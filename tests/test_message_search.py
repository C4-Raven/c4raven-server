"""
Tests for message search and CSV/KML export (raven/blueprints/raven_api/message_search_api.py).

Same minimal sqlite Flask app approach as tests/test_security_audit.py: only the blueprint under
test, no RabbitMQ / Postgres / scheduler.
"""

import csv
import datetime
import importlib
import io
import os
import pkgutil
import time
import xml.etree.ElementTree as ET

import pytest
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

import raven.models  # noqa: E402

# The CoT/EUD relationships reach most of the other models; load them all
for _module in pkgutil.iter_modules(raven.models.__path__):
    importlib.import_module(f"raven.models.{_module.name}")

from raven.blueprints.raven_api import message_search_api  # noqa: E402
from raven.blueprints.raven_api.message_search_api import (  # noqa: E402
    message_search_api_blueprint,
)
from raven.models.AuditEvent import AuditEvent  # noqa: E402
from raven.models.Chatrooms import Chatroom  # noqa: E402
from raven.models.CoT import CoT  # noqa: E402
from raven.models.EUD import EUD  # noqa: E402
from raven.models.GeoChat import GeoChat  # noqa: E402
from raven.models.Group import Group  # noqa: E402
from raven.models.GroupUser import GroupUser  # noqa: E402
from raven.models.Marker import Marker  # noqa: E402
from raven.models.Point import Point  # noqa: E402

KML = "{http://www.opengis.net/kml/2.2}"
GX = "{http://www.google.com/kml/ext/2.2}"
T0 = datetime.datetime(2026, 10, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _t(minutes):
    return T0 + datetime.timedelta(minutes=minutes)


@pytest.fixture(autouse=True)
def _wide_default_window(request, monkeypatch):
    """The seed data is at a fixed date (T0), older than the 24 hour default search window, so
    the filter tests search everything unless they're about the default window itself."""
    if "real_default_window" not in request.keywords:
        monkeypatch.setattr(message_search_api, "DEFAULT_WINDOW", datetime.timedelta(days=36500))


@pytest.fixture
def app(tmp_path):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        # Set RAVEN_TEST_DATABASE_URI to run these against a scratch PostgreSQL/MySQL database
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "RAVEN_TEST_DATABASE_URI", f"sqlite:///{tmp_path / 'test.db'}"
        ),
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_ENABLE_LDAP=False,
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        WTF_CSRF_ENABLED=False,
        SECURITY_PASSWORD_HASH="plaintext",
        SECURITY_USER_IDENTITY_ATTRIBUTES=[
            {"username": {"mapper": lambda x: x, "case_insensitive": True}}
        ],
    )
    db.init_app(app)
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(message_search_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        users = {
            "admin": ds.create_user(
                username="admin", password=hash_password("x"), roles=["administrator"]
            )
        }
        for name in ("alice", "bob", "carol", "dave"):
            users[name] = ds.create_user(username=name, password=hash_password("x"), roles=["user"])
        db.session.commit()
        _seed(users)

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _group(name, members):
    group = Group()
    group.name = name
    group.type = Group.SYSTEM
    db.session.add(group)
    db.session.flush()
    for user, directions in members:
        for direction in directions:
            db.session.add(
                GroupUser(user_id=user.id, group_id=group.id, direction=direction, enabled=True)
            )
    return group


def _eud(uid, callsign, user=None):
    db.session.add(EUD(uid=uid, callsign=callsign, user_id=user.id if user else None))


def _cot(uid, sender, cot_type, minutes, lat=None, lon=None, dest=None, how="m-g"):
    xml = f'<event uid="{uid}" type="{cot_type}" how="{how}"><detail>'
    if dest:
        xml += dest
    xml += "</detail></event>"
    cot = CoT(
        uid=uid,
        type=cot_type,
        how=how,
        sender_uid=sender,
        timestamp=_t(minutes),
        start=_t(minutes),
        stale=_t(minutes + 5),
        xml=xml,
    )
    db.session.add(cot)
    db.session.flush()
    point = None
    if lat is not None:
        point = Point(
            uid=uid,
            device_uid=sender,
            latitude=lat,
            longitude=lon,
            hae=9999999.0,
            ce=10.0,
            timestamp=_t(minutes),
            cot_id=cot.id,
        )
        db.session.add(point)
        db.session.flush()
    return cot, point


def _chat(uid, sender, minutes, chatroom_id, chatroom_name, text, dest=None):
    cot, point = _cot(uid, sender, "b-t-f", minutes, 10.0, 20.0, dest=dest, how="h-g-i-g-o")
    if not db.session.get(Chatroom, chatroom_id):
        db.session.add(Chatroom(id=chatroom_id, name=chatroom_name))
    db.session.add(
        GeoChat(
            uid=uid,
            chatroom_id=chatroom_id,
            sender_uid=sender,
            remarks=text,
            timestamp=_t(minutes),
            point_id=point.id,
            cot_id=cot.id,
        )
    )


def _seed(users):
    # alice sends to Blue, bob only receives Blue, carol is alone in Red, dave has no groups
    # (so he receives __ANON__)
    _group("Blue", [(users["alice"], ("IN", "OUT")), (users["bob"], ("OUT",))])
    _group("Red", [(users["carol"], ("IN", "OUT"))])
    _group("__ANON__", [])
    _eud("alice-eud", "ALPHA", users["alice"])
    _eud("bob-eud", "BRAVO", users["bob"])
    _eud("carol-eud", "CHARLIE", users["carol"])
    _eud("tcp-eud", "TCPGUY")
    db.session.flush()

    # alice's PLI track: three points moving north near (10, 20)
    for i in range(3):
        _cot("alice-eud", "alice-eud", "a-f-G-U-C", i, 10.0 + i * 0.01, 20.0)
    _cot("carol-eud", "carol-eud", "a-f-G-U-C", 10, 50.0, 8.0)
    _cot("tcp-eud", "tcp-eud", "a-n-G", 20, -33.9, 151.2)
    _cot("fiji", "tcp-eud", "a-u-G", 21, -17.0, 179.5)
    _chat("chat-1", "alice-eud", 30, "All Chat Rooms", "All Chat Rooms", "hello world")
    _chat(
        "chat-2",
        "alice-eud",
        31,
        "bob-eud",
        "BRAVO",
        "secret for bravo",
        dest='<dest callsign="BRAVO"/>',
    )
    _chat(
        "chat-3",
        "alice-eud",
        32,
        "carol-eud",
        "CHARLIE",
        '=HYPERLINK("x")',
        dest='<dest callsign="CHARLIE"/>',
    )
    cot, point = _cot("marker-1", "alice-eud", "a-h-G", 40, 10.5, 20.5, how="h-g-i-g-o")
    db.session.add(
        Marker(
            uid="marker-1",
            callsign="Enemy tank",
            remarks="Near the bridge",
            point_id=point.id,
            cot_id=cot.id,
            parent_uid="alice-eud",
        )
    )
    # A directed non-chat CoT (e.g. a marker sent to one contact)
    _cot("sent-1", "alice-eud", "a-h-G", 41, 10.6, 20.6, dest='<dest callsign="CHARLIE"/>')
    db.session.commit()


def _login(app, client, username):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username=username).fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()


@pytest.fixture
def client(app):
    return app.test_client()


def _search(app, client, username="admin", **params):
    _login(app, client, username)
    response = client.get("/api/message_search", query_string=params)
    assert response.status_code == 200, response.get_json()
    return response.get_json()


def _uids(body):
    return [r["uid"] for r in body["results"]]


# --- auth and validation ---


def test_requires_login(client):
    assert client.get("/api/message_search").status_code in (401, 302)
    assert client.get("/api/message_search/export").status_code in (401, 302)


@pytest.mark.parametrize(
    "params",
    [
        {"start": "yesterday"},
        {"start": "2026-10-02T00:00:00Z", "end": "2026-10-01T00:00:00Z"},
        {"min_lat": "1", "max_lat": "2"},
        {"min_lat": "5", "max_lat": "1", "min_lon": "0", "max_lon": "1"},
        {"min_lat": "91", "max_lat": "92", "min_lon": "0", "max_lon": "1"},
        {"lat": "1", "lon": "2"},
        {"lat": "1", "lon": "2", "radius": "999999999"},
        {"lat": "nan", "lon": "2", "radius": "10"},
    ],
)
def test_invalid_filters(app, client, params):
    _login(app, client, "admin")
    response = client.get("/api/message_search", query_string=params)
    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_invalid_export_format(app, client):
    _login(app, client, "admin")
    assert client.get("/api/message_search/export?format=xlsx").status_code == 400


# --- filters ---


def test_admin_sees_everything_newest_first(app, client):
    body = _search(app, client)
    assert body["total"] == 11
    times = [r["timestamp"] for r in body["results"]]
    assert times == sorted(times, reverse=True)
    assert body["results"][0]["uid"] == "sent-1"


def test_time_filter(app, client):
    body = _search(app, client, start="2026-10-01T12:01:00Z", end="2026-10-01T12:10:00+00:00")
    assert sorted(_uids(body)) == ["alice-eud", "alice-eud", "carol-eud"]
    # No offset means UTC; an offset is converted
    body = _search(app, client, start="2026-10-01T14:20:00+02:00", end="2026-10-01T12:20:00")
    assert _uids(body) == ["tcp-eud"]


def test_bbox_filter(app, client):
    body = _search(app, client, min_lat=9.9, max_lat=10.03, min_lon=19.9, max_lon=20.1)
    assert _uids(body).count("alice-eud") == 3
    assert "marker-1" not in _uids(body)
    assert all(9.9 <= r["latitude"] <= 10.03 for r in body["results"])


def test_bbox_across_antimeridian(app, client):
    body = _search(app, client, min_lat=-40, max_lat=0, min_lon=170, max_lon=-170)
    assert _uids(body) == ["fiji"]


def test_radius_filter(app, client):
    # Sydney, 10 km
    body = _search(app, client, lat=-33.95, lon=151.2, radius=10000)
    assert _uids(body) == ["tcp-eud"]
    # ~5.5 km is between the 1st (10.0) and the marker (10.5, 20.5): 0.01 deg lat = 1.1 km
    body = _search(app, client, lat=10.0, lon=20.0, radius=2500)
    assert set(_uids(body)) == {"alice-eud", "chat-1", "chat-2", "chat-3"}
    body = _search(app, client, lat=10.0, lon=20.0, radius=100)
    assert set(_uids(body)) == {"alice-eud", "chat-1", "chat-2", "chat-3"}
    assert body["total"] == 4


def test_type_prefix_filter(app, client):
    assert set(_uids(_search(app, client, type="a-h"))) == {"marker-1", "sent-1"}
    assert set(_uids(_search(app, client, type="b-t-f"))) == {"chat-1", "chat-2", "chat-3"}
    # LIKE wildcards are literal
    assert _search(app, client, type="a%")["total"] == 0


def test_callsign_uid_and_text_filters(app, client):
    assert _uids(_search(app, client, callsign="tank")) == ["marker-1"]
    assert _search(app, client, callsign="charlie")["total"] == 1
    assert _uids(_search(app, client, uid="fiji")) == ["fiji"]
    # uid also matches the sender
    assert _search(app, client, uid="tcp-eud")["total"] == 2
    assert _uids(_search(app, client, text="HELLO")) == ["chat-1"]
    assert _uids(_search(app, client, text="bridge")) == ["marker-1"]
    result = _search(app, client, text="hello")["results"][0]
    assert result["chatroom"] == "All Chat Rooms"
    assert result["message"] == "hello world"
    assert result["callsign"] == "ALPHA"
    # ATAK's 9999999 "unknown" isn't passed through
    assert result["hae"] is None and result["ce"] == 10.0


def test_pagination(app, client):
    first = _search(app, client, per_page=4, page=1)
    second = _search(app, client, per_page=4, page=2)
    third = _search(app, client, per_page=4, page=3)
    assert first["total_pages"] == 3
    assert len(first["results"]) == 4 and len(third["results"]) == 3
    ids = [r["id"] for page in (first, second, third) for r in page["results"]]
    assert len(set(ids)) == 11
    # per_page is capped
    assert _search(app, client, per_page=100000)["per_page"] == 500


# --- group visibility ---


def test_group_visibility(app, client):
    alice = set(_uids(_search(app, client, "alice")))
    bob = set(_uids(_search(app, client, "bob")))
    carol = set(_uids(_search(app, client, "carol")))
    dave = set(_uids(_search(app, client, "dave")))

    # alice sees everything she sent, nothing from Red or __ANON__
    assert alice == {"alice-eud", "chat-1", "chat-2", "chat-3", "marker-1", "sent-1"}
    # bob receives Blue broadcasts and his own DM, not alice's DM or CoT to CHARLIE
    assert bob == {"alice-eud", "chat-1", "chat-2", "marker-1"}
    # carol: her own PLI plus what was addressed to her
    assert carol == {"carol-eud", "chat-3", "sent-1"}
    # dave has no OUT groups, so he gets __ANON__ (the unauthenticated TCP EUD)
    assert dave == {"tcp-eud", "fiji"}


def test_group_visibility_ignores_disabled_and_expired_memberships(app, client):
    with app.app_context():
        bob = app.security.datastore.find_user(username="bob")
        membership = db.session.query(GroupUser).filter_by(user_id=bob.id).one()
        membership.expires_at = datetime.datetime(2000, 1, 1)
        db.session.commit()
    # No active OUT groups any more -> bob falls back to __ANON__
    assert set(_uids(_search(app, client, "bob"))) == {"tcp-eud", "fiji", "chat-2"}


def test_get_message_respects_visibility(app, client):
    with app.app_context():
        cot_id = db.session.query(CoT.id).filter_by(uid="chat-3").scalar()
    _login(app, client, "carol")
    response = client.get(f"/api/message_search/{cot_id}")
    assert response.status_code == 200
    assert '<dest callsign="CHARLIE"/>' in response.get_json()["message"]["xml"]
    _login(app, client, "bob")
    assert client.get(f"/api/message_search/{cot_id}").status_code == 404


# --- exports ---


def _export(app, client, username="admin", **params):
    _login(app, client, username)
    response = client.get("/api/message_search/export", query_string=params)
    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    # Read the streamed body, then close it so stream_with_context pops its request context now
    response.get_data()
    response.close()
    return response


def test_csv_export(app, client):
    response = _export(app, client, format="csv", type="b-t-f")
    assert response.mimetype == "text/csv"
    rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
    assert [r["uid"] for r in rows] == ["chat-3", "chat-2", "chat-1"]
    assert rows[2]["message"] == "hello world"
    assert rows[2]["latitude"] == "10.0"
    # Formula injection is neutralised
    assert rows[0]["message"] == '\'=HYPERLINK("x")'


def test_csv_export_is_group_filtered(app, client):
    response = _export(app, client, "bob", format="csv")
    uids = {r["uid"] for r in csv.DictReader(io.StringIO(response.get_data(as_text=True)))}
    assert uids == {"alice-eud", "chat-1", "chat-2", "marker-1"}


def test_export_row_cap(app, client):
    app.config["RAVEN_MESSAGE_EXPORT_MAX_ROWS"] = 2
    response = _export(app, client, format="csv")
    assert response.headers["X-Export-Max-Rows"] == "2"
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert len(rows) == 3  # header + 2


def test_kml_export(app, client):
    response = _export(app, client, format="kml", tracks="1")
    assert response.mimetype == "application/vnd.google-earth.kml+xml"
    root = ET.fromstring(response.get_data())
    assert root.tag == f"{KML}kml"
    folders = root.find(f"{KML}Document").findall(f"{KML}Folder")
    assert [f.find(f"{KML}name").text for f in folders] == ["Messages", "Tracks"]

    placemarks = folders[0].findall(f"{KML}Placemark")
    assert len(placemarks) == 11
    first = placemarks[0]
    assert first.find(f"{KML}TimeStamp/{KML}when").text == "2026-10-01T12:41:00Z"
    assert first.find(f"{KML}Point/{KML}coordinates").text == "20.6,10.6"
    marker = [p for p in placemarks if p.find(f"{KML}name").text == "Enemy tank"][0]
    assert "Near the bridge" in marker.find(f"{KML}description").text

    # One track: alice's PLI uid (3 points, oldest first); single-point uids get none
    tracks = folders[1].findall(f"{KML}Placemark")
    assert len(tracks) == 1
    track = tracks[0].find(f"{GX}Track")
    whens = [w.text for w in track.findall(f"{KML}when")]
    coords = [c.text for c in track.findall(f"{GX}coord")]
    assert whens == ["2026-10-01T12:00:00Z", "2026-10-01T12:01:00Z", "2026-10-01T12:02:00Z"]
    assert coords == ["20.0 10.0 0", "20.0 10.01 0", "20.0 10.02 0"]


def test_kml_escapes_text(app, client):
    with app.app_context():
        marker = db.session.query(Marker).filter_by(uid="marker-1").one()
        marker.callsign = "<b>&\x01"
        db.session.commit()
    response = _export(app, client, format="kml", uid="marker-1")
    root = ET.fromstring(response.get_data())
    names = [p.text for p in root.iter(f"{KML}name")]
    assert "<b>&" in names


def test_export_is_audited(app, client):
    _export(app, client, "bob", format="kml", tracks="1", type="a-f", callsign="alpha")
    _export(app, client, "admin", format="csv")
    with app.app_context():
        events = [e.to_json() for e in db.session.query(AuditEvent).order_by(AuditEvent.id)]
    assert [(e["category"], e["action"], e["username"]) for e in events] == [
        ("data_export", "message_export_kml", "bob"),
        ("data_export", "message_export_csv", "admin"),
    ]
    assert "type=a-f" in events[0]["details"] and "callsign=alpha" in events[0]["details"]
    assert "with tracks" in events[0]["details"]


def test_search_is_not_audited(app, client):
    _search(app, client)
    with app.app_context():
        assert db.session.query(AuditEvent).count() == 0


# --- default window, paging and count caps ---


@pytest.mark.real_default_window
def test_no_dates_searches_last_24_hours(app, client):
    with app.app_context():
        _cot("recent-1", "alice-eud", "a-f-G-U-C", 0, 10.0, 20.0)
        recent = db.session.query(CoT).filter_by(uid="recent-1").one()
        recent.timestamp = datetime.datetime.now(datetime.timezone.utc).replace(
            tzinfo=None
        ) - datetime.timedelta(hours=1)
        db.session.commit()
    body = _search(app, client)
    assert _uids(body) == ["recent-1"]
    assert body["default_start"]
    # An explicit range still reaches the old seed data, and isn't flagged as the default
    body = _search(app, client, start="2026-01-01T00:00:00Z")
    assert body["total"] == 12
    assert body["default_start"] is None


@pytest.mark.real_default_window
def test_export_uses_same_default_window(app, client):
    _login(app, client, "admin")
    response = client.get("/api/message_search/export?format=csv")
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert rows[1:] == []


def test_paging_and_count_are_capped(app, client, monkeypatch):
    monkeypatch.setattr(message_search_api, "MAX_RESULT_WINDOW", 4)
    body = _search(app, client, per_page=2)
    assert body["total"] == 4
    assert body["total_capped"] is True
    assert body["total_pages"] == 2
    # A page past the window is clamped to the last one inside it
    body = _search(app, client, per_page=2, page=50)
    assert body["current_page"] == 2
    assert len(body["results"]) == 2

    monkeypatch.setattr(message_search_api, "MAX_RESULT_WINDOW", 10000)
    body = _search(app, client, per_page=2)
    assert body["total"] == 11
    assert body["total_capped"] is False
