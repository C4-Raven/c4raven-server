"""Per data type retention (raven/retention.py, raven/blueprints/raven_api/retention_api.py) and
chat held for offline devices (raven/offline_chat.py).

Minimal sqlite Flask app, as in tests/test_group_policies.py: no RabbitMQ, Postgres or
scheduler. sqlite doesn't enforce foreign keys, so the cascade-protection in the CoT purge is
checked by asserting which rows the purge chose, not by the database refusing.
"""

import datetime
import os
import time

import pytest
from bs4 import BeautifulSoup
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven import offline_chat, retention  # noqa: E402
from raven.audit import init_audit  # noqa: E402
from raven.blueprints.raven_api.retention_api import retention_api_blueprint  # noqa: E402
from raven.models.Alert import Alert  # noqa: E402
from raven.models.AuditEvent import AuditEvent  # noqa: E402
from raven.models.CoT import CoT  # noqa: E402
from raven.models.DataPackage import DataPackage  # noqa: E402
from raven.models.EUD import EUD  # noqa: E402
from raven.models.EUDStats import EUDStats  # noqa: E402
from raven.models.GeoChat import GeoChat  # noqa: E402
from raven.models.Group import Group  # noqa: E402
from raven.models.GroupUser import GroupUser  # noqa: E402
from raven.models.Marker import Marker  # noqa: E402
from raven.models.OfflineChatMessage import OfflineChatMessage  # noqa: E402
from raven.models.Point import Point  # noqa: E402
from raven.models.RetentionSetting import RetentionSetting  # noqa: E402
from raven.models.SupportingDocument import SupportingDocument  # noqa: E402,F401
from raven.models.Team import Team  # noqa: E402
from raven.models.VideoRecording import VideoRecording  # noqa: E402

UTC = datetime.timezone.utc
HOUR = 3600
DAY = 86400


@pytest.fixture
def app(tmp_path):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        UPLOAD_FOLDER=str(tmp_path / "uploads"),
        RAVEN_ENABLE_LDAP=False,
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        WTF_CSRF_ENABLED=False,
        SECURITY_PASSWORD_HASH="plaintext",
        SECURITY_USER_IDENTITY_ATTRIBUTES=[
            {"username": {"mapper": lambda x: x, "case_insensitive": True}}
        ],
    )
    os.makedirs(tmp_path / "uploads", exist_ok=True)
    os.makedirs(tmp_path / "logs", exist_ok=True)
    db.init_app(app)
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    init_audit(app)
    app.register_blueprint(retention_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("x"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("x"), roles=["user"])
        ds.create_user(username="bob", password=hash_password("x"), roles=["user"])
        ds.create_user(username="carol", password=hash_password("x"), roles=["user"])
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def login(app, username):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username=username).fs_uniquifier
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()
    return client


@pytest.fixture
def admin(app):
    return login(app, "admin")


def now_utc():
    return datetime.datetime.now(UTC)


def ago(seconds):
    return now_utc() - datetime.timedelta(seconds=seconds)


def naive(dt):
    return dt.astimezone(UTC).replace(tzinfo=None)


def user_id(username):
    from raven.models.user import User

    return db.session.query(User).filter_by(username=username).one().id


def add_eud(uid, callsign, status="Disconnected", username=None, team=None, platform="ATAK-CIV"):
    eud = EUD(uid=uid, callsign=callsign, last_status=status, platform=platform)
    if username:
        eud.user_id = user_id(username)
    if team:
        eud.team_id = team.id
    db.session.add(eud)
    db.session.commit()
    return eud


def set_keep(key, seconds):
    retention.update_settings({key: seconds}, "test")


def types_by_key(response):
    return {t["key"]: t for t in response.json["types"]}


# --- settings API ---


def test_settings_require_admin(app):
    anonymous = app.test_client()
    assert anonymous.get("/api/retention").status_code in (401, 403, 302)
    assert anonymous.put("/api/retention", json={"settings": {"geochat": None}}).status_code in (401, 403, 302)

    alice = login(app, "alice")
    assert alice.get("/api/retention").status_code == 403
    assert alice.put("/api/retention", json={"settings": {"geochat": DAY}}).status_code == 403
    with app.app_context():
        assert db.session.get(RetentionSetting, "geochat") is None


def test_defaults_match_previous_behaviour(admin):
    r = admin.get("/api/retention")
    assert r.status_code == 200, r.json
    types = types_by_key(r)
    assert set(types) == {t.key for t in retention.DATA_TYPES}
    assert {
        "cot", "geochat", "alerts", "casevac", "markers", "data_packages", "video_recordings",
        "eud_stats", "audit_events", "error_logs", "mission_changes", "offline_chat",
    } <= set(types)
    # Everything is kept forever, as before, except the offline chat queue: 48 hours
    for key, t in types.items():
        expected = 48 * HOUR if key == "offline_chat" else None
        assert t["keep_seconds"] == expected, key
        assert t["customized"] is False
        assert t["last_purge_at"] is None
    assert types["geochat"]["count"] == 0
    assert r.json["job"]["id"] == "apply_data_retention"


def test_put_saves_validates_and_audits(admin, app):
    r = admin.put("/api/retention", json={"settings": {"geochat": 7 * DAY, "offline_chat": {"keep_seconds": 12 * HOUR}}})
    assert r.status_code == 200, r.json
    types = types_by_key(r)
    assert types["geochat"]["keep_seconds"] == 7 * DAY
    assert types["geochat"]["customized"] is True
    assert types["geochat"]["updated_by"] == "admin"
    assert types["offline_chat"]["keep_seconds"] == 12 * HOUR

    # Back to forever
    r = admin.put("/api/retention", json={"settings": {"geochat": None}})
    assert types_by_key(r)["geochat"]["keep_seconds"] is None

    # Saving the same value again records nothing new
    admin.put("/api/retention", json={"settings": {"offline_chat": 12 * HOUR}})

    for bad in ({"nope": DAY}, {"geochat": 60}, {"geochat": "7"}, {"geochat": True}, {"geochat": 11 * 365 * DAY}):
        r = admin.put("/api/retention", json={"settings": bad})
        assert r.status_code == 400, bad
    assert admin.put("/api/retention", json={}).status_code == 400

    with app.app_context():
        assert retention.keep_seconds("geochat") is None
        assert retention.keep_seconds("offline_chat") == 12 * HOUR
        events = db.session.query(AuditEvent).filter_by(category="retention").order_by(AuditEvent.id).all()
        assert [(e.action, e.actor, e.details) for e in events] == [
            ("retention_changed", "admin", "Chat messages: forever -> 7 days"),
            ("retention_changed", "admin", "Offline chat queue: 2 days -> 12 hours"),
            ("retention_changed", "admin", "Chat messages: 7 days -> forever"),
        ]


# --- purge ---


def test_purge_per_type(app, tmp_path):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha")
        old, new = ago(10 * DAY), ago(HOUR)

        # Chat: old and new
        for uid, ts in (("chat-old", old), ("chat-new", new)):
            db.session.add(GeoChat(uid=uid, chatroom_id="All Chat Rooms", sender_uid="ANDROID-a", remarks="hi", timestamp=ts, point_id=0, cot_id=0))
        # Alerts
        for uid, ts in (("alert-old", old), ("alert-new", new)):
            db.session.add(Alert(uid=uid, sender_uid="ANDROID-a", start_time=ts, alert_type="911"))
        # Device stats
        for ts in (old, new):
            db.session.add(EUDStats(eud_uid="ANDROID-a", timestamp=ts))
        # Audit events are naive UTC
        for ts in (old, new):
            db.session.add(AuditEvent(timestamp=naive(ts), category="auth", action="web_login", success=True))
        db.session.commit()

        set_keep("geochat", DAY)
        set_keep("alerts", DAY)
        set_keep("eud_stats", DAY)
        set_keep("audit_events", DAY)

        results = retention.apply_retention()
        assert results["geochat"] == 1
        assert results["alerts"] == 1
        assert results["eud_stats"] == 1
        assert results["audit_events"] == 1
        # Types left at forever aren't touched
        assert "cot" not in results and "markers" not in results

        assert [g.uid for g in db.session.query(GeoChat)] == ["chat-new"]
        assert [a.uid for a in db.session.query(Alert)] == ["alert-new"]
        assert db.session.query(EUDStats).count() == 1
        # The new audit event survives, and the purge of the audit trail is itself recorded
        remaining = db.session.query(AuditEvent).order_by(AuditEvent.id).all()
        assert [e.action for e in remaining] == ["web_login", "audit_events_purged"]

        row = db.session.get(RetentionSetting, "geochat")
        assert row.last_purge_count == 1 and row.last_purge_at is not None and row.last_purge_error is None
        # A type at forever gets no purge row
        assert db.session.get(RetentionSetting, "cot") is None


def test_purge_in_batches(app, monkeypatch):
    monkeypatch.setattr(retention, "BATCH_SIZE", 3)
    with app.app_context():
        add_eud("ANDROID-a", "Alpha")
        for i in range(8):
            db.session.add(EUDStats(eud_uid="ANDROID-a", timestamp=ago(10 * DAY)))
        db.session.commit()
        set_keep("eud_stats", DAY)
        assert retention.apply_retention()["eud_stats"] == 8
        assert db.session.query(EUDStats).count() == 0


def test_cot_purge_keeps_what_others_are_built_on(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha")
        old = ago(10 * DAY)

        def cot(uid, mission=None):
            c = CoT(uid=uid, type="a-f-G", sender_uid="ANDROID-a", timestamp=old, start=old, stale=old, xml="<event/>", mission_name=mission)
            db.session.add(c)
            db.session.flush()
            return c

        def point(c):
            p = Point(uid=c.uid, device_uid="ANDROID-a", timestamp=old, cot_id=c.id)
            db.session.add(p)
            db.session.flush()
            return p

        plain = cot("plain")
        plain_point = point(plain)
        marker_cot = cot("marker")
        marker_point = point(marker_cot)
        db.session.add(Marker(uid="m1", point_id=marker_point.id, cot_id=marker_cot.id))
        chat_cot = cot("chat")
        chat_point = point(chat_cot)
        db.session.add(GeoChat(uid="chat-1", chatroom_id="r", sender_uid="ANDROID-a", remarks="x", timestamp=now_utc(), point_id=chat_point.id, cot_id=chat_cot.id))
        mission_cot = cot("mission", mission="ops")
        new = CoT(uid="new", type="a-f-G", sender_uid="ANDROID-a", timestamp=now_utc(), start=now_utc(), stale=now_utc(), xml="<event/>")
        db.session.add(new)
        db.session.commit()
        ids = {"plain": plain.id, "marker": marker_cot.id, "chat": chat_cot.id, "mission": mission_cot.id, "new": new.id}
        plain_point_id = plain_point.id

        set_keep("cot", DAY)
        retention.apply_retention()

        remaining = {c.id for c in db.session.query(CoT)}
        assert ids["plain"] not in remaining
        assert {ids["marker"], ids["chat"], ids["mission"], ids["new"]} <= remaining
        points = {p.id for p in db.session.query(Point)}
        assert plain_point_id not in points
        assert {marker_point.id, chat_point.id} <= points


def test_marker_purge_by_last_update(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha")
        for uid, ts in (("old", ago(10 * DAY)), ("new", ago(HOUR))):
            c = CoT(uid=uid, type="a-h-G", sender_uid="ANDROID-a", timestamp=ts, start=ts, stale=ts, xml="<event/>")
            db.session.add(c)
            db.session.flush()
            db.session.add(Marker(uid=f"marker-{uid}", cot_id=c.id, point_id=0))
        db.session.commit()
        set_keep("markers", DAY)
        retention.apply_retention()
        assert [m.uid for m in db.session.query(Marker)] == ["marker-new"]


def test_data_package_and_video_files_deleted(app, tmp_path):
    with app.app_context():
        uploads = tmp_path / "uploads"
        for h in ("oldhash", "newhash", "enrollhash"):
            (uploads / f"{h}.zip").write_bytes(b"zip")
        db.session.add(DataPackage(filename="old.zip", hash="oldhash", submission_time=ago(10 * DAY), mime_type="application/zip", size=3))
        db.session.add(DataPackage(filename="new.zip", hash="newhash", submission_time=ago(HOUR), mime_type="application/zip", size=3))
        db.session.add(DataPackage(filename="enroll.zip", hash="enrollhash", submission_time=ago(10 * DAY), mime_type="application/zip", size=3, install_on_enrollment=True))

        rec_dir = tmp_path / "recordings"
        rec_dir.mkdir()
        old_seg, new_seg, live_seg = rec_dir / "old.mp4", rec_dir / "new.mp4", rec_dir / "live.mp4"
        for f in (old_seg, new_seg, live_seg):
            f.write_bytes(b"video")
        (rec_dir / "old.mp4.png").write_bytes(b"png")
        db.session.add(VideoRecording(path="cam", segment_path=str(old_seg), in_progress=False, start_time=ago(10 * DAY), stop_time=ago(10 * DAY)))
        db.session.add(VideoRecording(path="cam", segment_path=str(new_seg), in_progress=False, start_time=ago(HOUR), stop_time=ago(HOUR)))
        db.session.add(VideoRecording(path="cam", segment_path=str(live_seg), in_progress=True, start_time=ago(10 * DAY)))
        db.session.commit()

        set_keep("data_packages", DAY)
        set_keep("video_recordings", DAY)
        results = retention.apply_retention()
        assert results["data_packages"] == 1
        assert results["video_recordings"] == 1

        assert sorted(d.hash for d in db.session.query(DataPackage)) == ["enrollhash", "newhash"]
        assert not (uploads / "oldhash.zip").exists()
        assert (uploads / "newhash.zip").exists() and (uploads / "enrollhash.zip").exists()

        assert sorted(v.segment_path for v in db.session.query(VideoRecording)) == sorted([str(new_seg), str(live_seg)])
        assert not old_seg.exists() and not (rec_dir / "old.mp4.png").exists()
        assert new_seg.exists() and live_seg.exists()


def test_rotated_logs_deleted_current_kept(app, tmp_path):
    logs = tmp_path / "logs"
    current = logs / "raven.log"
    rotated_old = logs / "raven.log.2026-01-01"
    rotated_new = logs / "raven.log.2026-11-01"
    for f in (current, rotated_old, rotated_new):
        f.write_text("x")
    old_mtime = time.time() - 30 * DAY
    os.utime(current, (old_mtime, old_mtime))
    os.utime(rotated_old, (old_mtime, old_mtime))
    with app.app_context():
        set_keep("error_logs", 7 * DAY)
        assert retention.apply_retention()["error_logs"] == 1
    assert current.exists() and rotated_new.exists() and not rotated_old.exists()


def test_one_type_failing_does_not_stop_the_others(app, monkeypatch):
    def boom(*args):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(retention.DATA_TYPES_BY_KEY["alerts"], "purge", boom)
    with app.app_context():
        add_eud("ANDROID-a", "Alpha")
        db.session.add(EUDStats(eud_uid="ANDROID-a", timestamp=ago(10 * DAY)))
        db.session.commit()
        set_keep("alerts", DAY)
        set_keep("eud_stats", DAY)
        results = retention.apply_retention()
        assert results["eud_stats"] == 1
        assert "disk on fire" in db.session.get(RetentionSetting, "alerts").last_purge_error


# --- offline chat ---


def geochat_xml(sender_uid="ANDROID-a", sender_callsign="Alpha", chatroom="Bravo", chat_id="ANDROID-b",
                dests=("Bravo",), message_id="11111111-2222-3333-4444-555555555555", parent="RootContactGroup",
                uid1=None, sent=None):
    sent = sent or now_utc()
    t = sent.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    stale = (sent + datetime.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    marti = "".join(f'<dest callsign="{d}"/>' for d in dests)
    marti = f"<marti>{marti}</marti>" if dests else ""
    return (
        f'<event version="2.0" uid="GeoChat.{sender_uid}.{chat_id}.{message_id}" type="b-t-f" how="h-g-i-g-o" '
        f'time="{t}" start="{t}" stale="{stale}">'
        f'<point lat="0" lon="0" hae="0" ce="9999999" le="9999999"/>'
        f'<detail><__chat parent="{parent}" groupOwner="false" messageId="{message_id}" chatroom="{chatroom}" '
        f'id="{chat_id}" senderCallsign="{sender_callsign}">'
        f'<chatgrp uid0="{sender_uid}" uid1="{uid1 or chat_id}" id="{chat_id}"/></__chat>'
        f'<link uid="{sender_uid}" type="a-f-G-U-C" relation="p-p"/>'
        f'<remarks source="BAO.F.ATAK.{sender_uid}" to="{chat_id}" time="{t}">hello</remarks>'
        f"{marti}</detail></event>"
    )


def event_of(xml):
    return BeautifulSoup(xml, "xml").find("event")


def queued(uid=None):
    q = db.session.query(OfflineChatMessage)
    if uid:
        q = q.filter_by(recipient_uid=uid)
    return q.order_by(OfflineChatMessage.id).all()


def test_dm_to_offline_device_is_queued_and_delivered_on_reconnect(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Connected")
        add_eud("ANDROID-b", "Bravo", status="Disconnected")

        first = geochat_xml(message_id="m-1", sent=ago(120))
        second = geochat_xml(message_id="m-2", sent=ago(60))
        assert offline_chat.queue_offline_chat(db.session, event_of(first), "ANDROID-a") == 1
        assert offline_chat.queue_offline_chat(db.session, event_of(second), "ANDROID-a") == 1
        # The same message again (e.g. redelivered to another cot_parser) is not queued twice
        assert offline_chat.queue_offline_chat(db.session, event_of(first), "ANDROID-a") == 0
        rows = queued("ANDROID-b")
        assert [r.message_uid for r in rows] == ["GeoChat.ANDROID-a.ANDROID-b.m-1", "GeoChat.ANDROID-a.ANDROID-b.m-2"]
        assert rows[0].chatroom_id == "ANDROID-b" and rows[0].sender_uid == "ANDROID-a"

        # Reconnect: delivered in order, with a fresh stale time, then marked delivered
        sent = []
        assert offline_chat.deliver_pending(db.session, "ANDROID-b", sent.append) == 2
        assert len(sent) == 2
        delivered = [event_of(s.decode()) for s in sent]
        assert [e.attrs["uid"] for e in delivered] == [r.message_uid for r in rows]
        for e in delivered:
            assert e.find("remarks").text == "hello"
            stale = datetime.datetime.strptime(e.attrs["stale"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
            assert stale > now_utc() + datetime.timedelta(minutes=30)
        # The original send time is kept
        assert delivered[0].attrs["time"] == event_of(first).attrs["time"]
        assert all(r.delivered_at is not None for r in queued("ANDROID-b"))

        # Next reconnect: nothing again
        again = []
        assert offline_chat.deliver_pending(db.session, "ANDROID-b", again.append) == 0
        assert again == []


def test_dm_by_uid_dest_itak(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Connected")
        add_eud("IOS-b", "Bravo", status="Disconnected")
        xml = geochat_xml(chat_id="IOS-b", dests=()).replace("</detail>", '<marti><dest uid="IOS-b"/></marti></detail>')
        assert offline_chat.queue_offline_chat(db.session, event_of(xml), "ANDROID-a") == 1
        assert queued()[0].recipient_uid == "IOS-b"


def test_no_queue_for_online_recipient(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Connected")
        add_eud("ANDROID-b", "Bravo", status="Connected")
        assert offline_chat.queue_offline_chat(db.session, event_of(geochat_xml()), "ANDROID-a") == 0
        assert queued() == []
        sent = []
        assert offline_chat.deliver_pending(db.session, "ANDROID-b", sent.append) == 0
        assert sent == []


def test_not_queued_for_sender_unknown_or_non_tak_devices(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Disconnected")
        add_eud("mesh-1", "Mesh", status="Disconnected", platform="Meshtastic")
        # To yourself, to an unknown callsign, to a Meshtastic node
        for dests in (("Alpha",), ("Nobody",), ("Mesh",)):
            assert offline_chat.queue_offline_chat(db.session, event_of(geochat_xml(dests=dests)), "ANDROID-a") == 0
        # Delivery receipts and other non-chat CoTs
        receipt = event_of('<event uid="r" type="b-t-f-d"><detail><__chatreceipt/></detail></event>')
        assert offline_chat.queue_offline_chat(db.session, receipt, "ANDROID-a") == 0
        assert queued() == []


def test_group_chat_queues_each_offline_member(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Connected")
        add_eud("ANDROID-b", "Bravo", status="Disconnected")
        add_eud("ANDROID-c", "Charlie", status="Connected")
        add_eud("ANDROID-d", "Delta", status="Disconnected")
        xml = geochat_xml(chatroom="Patrol", chat_id="group-uuid", dests=("Bravo", "Charlie", "Delta"), parent="UserGroups")
        assert offline_chat.queue_offline_chat(db.session, event_of(xml), "ANDROID-a") == 2
        assert sorted(r.recipient_uid for r in queued()) == ["ANDROID-b", "ANDROID-d"]


def test_all_chat_rooms_not_queued(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Connected")
        add_eud("ANDROID-b", "Bravo", status="Disconnected")
        xml = geochat_xml(chatroom="All Chat Rooms", chat_id="All Chat Rooms", dests=())
        assert offline_chat.queue_offline_chat(db.session, event_of(xml), "ANDROID-a") == 0
        assert queued() == []


def test_team_chat_follows_group_routing(app):
    with app.app_context():
        cyan = Team(name="Cyan")
        red = Team(name="Red")
        db.session.add_all([cyan, red])
        ops, other = Group(), Group()
        for i, (g, name) in enumerate(((ops, "ops"), (other, "other"))):
            g.name, g.type, g.bitpos = name, "SYSTEM", i + 2
        db.session.add_all([ops, other])
        db.session.commit()
        alice, bob, carol = user_id("alice"), user_id("bob"), user_id("carol")
        db.session.add_all([
            GroupUser(user_id=alice, group_id=ops.id, direction=Group.IN, enabled=True),
            GroupUser(user_id=bob, group_id=ops.id, direction=Group.OUT, enabled=True),
            GroupUser(user_id=carol, group_id=other.id, direction=Group.OUT, enabled=True),
        ])
        db.session.commit()
        add_eud("ANDROID-a", "Alpha", status="Connected", username="alice", team=cyan)
        add_eud("ANDROID-b", "Bravo", status="Disconnected", username="bob", team=cyan)
        # Same team, but can't read the sender's group
        add_eud("ANDROID-c", "Charlie", status="Disconnected", username="carol", team=cyan)
        # Reads the group, wrong team
        add_eud("ANDROID-d", "Delta", status="Disconnected", username="bob", team=red)

        xml = geochat_xml(chatroom="Cyan", chat_id="Cyan", dests=(), parent="TeamGroups")
        assert offline_chat.queue_offline_chat(db.session, event_of(xml), "ANDROID-a", alice) == 1
        assert [r.recipient_uid for r in queued()] == ["ANDROID-b"]


def test_queued_chat_expires_after_48_hours(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Connected")
        add_eud("ANDROID-b", "Bravo", status="Disconnected")
        now = naive(now_utc())
        offline_chat.queue_offline_chat(db.session, event_of(geochat_xml(message_id="old")), "ANDROID-a", now=now - datetime.timedelta(hours=49))
        offline_chat.queue_offline_chat(db.session, event_of(geochat_xml(message_id="recent")), "ANDROID-a", now=now - datetime.timedelta(hours=47))
        assert len(queued()) == 2

        # The 49 hour old one is no longer delivered...
        pending = offline_chat.pending_messages(db.session, "ANDROID-b")
        assert [p.message_uid for p in pending] == ["GeoChat.ANDROID-a.ANDROID-b.recent"]

        # ...and the retention job removes it
        assert retention.apply_retention(only=["offline_chat"])["offline_chat"] == 1
        assert [r.message_uid for r in queued()] == ["GeoChat.ANDROID-a.ANDROID-b.recent"]

        # An admin can change the 48 hours
        set_keep("offline_chat", 24 * HOUR)
        assert offline_chat.pending_messages(db.session, "ANDROID-b") == []
        set_keep("offline_chat", None)
        assert len(offline_chat.pending_messages(db.session, "ANDROID-b")) == 1


def test_failed_write_keeps_the_rest_queued(app):
    with app.app_context():
        add_eud("ANDROID-a", "Alpha", status="Connected")
        add_eud("ANDROID-b", "Bravo", status="Disconnected")
        for i in range(3):
            offline_chat.queue_offline_chat(db.session, event_of(geochat_xml(message_id=f"m{i}", sent=ago(100 - i))), "ANDROID-a")

        sent = []

        def flaky(data):
            if len(sent) == 1:
                raise OSError("broken pipe")
            sent.append(data)

        with pytest.raises(OSError):
            offline_chat.deliver_pending(db.session, "ANDROID-b", flaky)
        db.session.rollback()
        assert [r.delivered_at is not None for r in queued("ANDROID-b")] == [True, False, False]
        rest = []
        assert offline_chat.deliver_pending(db.session, "ANDROID-b", rest.append) == 2
