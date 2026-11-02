"""Regression tests for the authz review of data packages, fileshare/video CoTs, group deletion
and video thumbnails (raven/blueprints/marti_api/data_package_marti_api.py, raven/cot_sharing.py,
raven/blueprints/raven_api/group_api.py, video_api.py, video_marti_api.py).

Mission-side regressions (detail/archive access, mission tokens without a role, archive entry
collisions, content hash checks) are in tests/test_mission_features.py.

Minimal sqlite Flask app, as in tests/test_group_isolation.py: no RabbitMQ, Postgres or
MediaMTX. Marti requests are authenticated by monkeypatching verify_client_cert.
"""

import datetime
import hashlib
import importlib
import io
import logging
import os
import time
import zipfile

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

from raven import cot_sharing, group_policy  # noqa: E402
from raven.audit import init_audit  # noqa: E402

dp_marti = importlib.import_module("raven.blueprints.marti_api.data_package_marti_api")
video_marti = importlib.import_module("raven.blueprints.marti_api.video_marti_api")
from raven.blueprints.raven_api.data_package_api import data_package_api  # noqa: E402
from raven.blueprints.raven_api.group_api import group_api  # noqa: E402
from raven.blueprints.raven_api.video_api import video_api_blueprint  # noqa: E402
from raven.models.DataPackage import DataPackage  # noqa: E402
from raven.models.DataPackageRecipient import DataPackageRecipient  # noqa: E402
from raven.models.EUD import EUD  # noqa: E402
from raven.models.Group import Group  # noqa: E402
from raven.models.GroupUser import GroupUser  # noqa: E402
from raven.models.VideoStream import VideoStream  # noqa: E402

LOG = logging.getLogger("test_authz_regressions")


class _FakeCert:
    def __init__(self, cn):
        self._cn = cn

    def get_subject(self):
        cn = self._cn
        return type(
            "Subject",
            (),
            {"commonName": cn, "get_components": lambda self: [(b"CN", cn.encode())]},
        )()


@pytest.fixture
def app(tmp_path, monkeypatch):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        UPLOAD_FOLDER=str(uploads),
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
    init_audit(app)
    app.register_blueprint(data_package_api)
    app.register_blueprint(dp_marti.data_package_marti_api)
    app.register_blueprint(video_api_blueprint)
    app.register_blueprint(video_marti.video_marti_api)
    app.register_blueprint(group_api)
    # No RabbitMQ: group deletion unbinds connected EUDs
    monkeypatch.setattr(group_policy, "unbind_euds", lambda *a, **k: True)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        for name, role in (("admin", "administrator"), ("alice", "user"), ("ann", "user"),
                           ("bob", "user")):
            ds.create_user(username=name, password=hash_password("x"), roles=[role])
        db.session.commit()

        for group_name in ("red", "blue"):
            group = Group()
            group.name = group_name
            group.type = Group.SYSTEM
            db.session.add(group)
        db.session.commit()
        memberships = {"alice": "red", "ann": "red", "bob": "blue"}
        for username, group_name in memberships.items():
            user = ds.find_user(username=username)
            group = db.session.query(Group).filter_by(name=group_name).one()
            for direction in (Group.IN, Group.OUT):
                db.session.add(
                    GroupUser(user_id=user.id, group_id=group.id, direction=direction, enabled=True)
                )
            eud = EUD()
            eud.uid = f"ANDROID-{username}"
            eud.callsign = username.upper()
            eud.user_id = user.id
            db.session.add(eud)
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def web_client(app, username):
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
def as_cert(monkeypatch):
    def use(cn):
        fake = (lambda: _FakeCert(cn)) if cn else (lambda: False)
        monkeypatch.setattr(dp_marti, "verify_client_cert", fake)
        monkeypatch.setattr(video_marti, "verify_client_cert", fake)

    return use


def zip_bytes(content=b"hello"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("MANIFEST/manifest.xml", content)
    return buf.getvalue()


def upload(app, data, name="p.zip", mimetype="application/x-zip-compressed", **query):
    return app.test_client().post(
        "/Marti/sync/missionupload",
        query_string=query,
        data={"assetfile": (io.BytesIO(data), name, mimetype)},
        content_type="multipart/form-data",
    )


def hash_from(response):
    return response.data.decode().split("/metadata/")[1].split("/")[0]


def download(app, file_hash):
    return app.test_client().get("/Marti/sync/content", query_string={"hash": file_hash})


def user_id(app, username):
    with app.app_context():
        return app.security.datastore.find_user(username=username).id


# --- 1: ?hash= is checked, never used as a file name ------------------------------------------


def test_hash_param_must_match_the_bytes(app, as_cert):
    as_cert("alice")
    secret = zip_bytes(b"alice-secret")
    victim = hash_from(upload(app, secret))
    assert victim == hashlib.sha256(secret).hexdigest()

    # bob can't overwrite alice's package by naming its hash
    as_cert("bob")
    r = upload(app, zip_bytes(b"bob-evil"), hash=victim)
    assert r.status_code == 400
    as_cert("alice")
    assert download(app, victim).data == secret

    # A matching hash is accepted
    as_cert("bob")
    mine = zip_bytes(b"bob")
    r = upload(app, mine, hash=hashlib.sha256(mine).hexdigest().upper())
    assert r.status_code == 200, r.data
    assert hash_from(r) == hashlib.sha256(mine).hexdigest()


def test_hash_param_path_traversal(app, as_cert, tmp_path):
    as_cert(None)
    r = upload(app, zip_bytes(b"x"), hash="../escaped")
    assert r.status_code == 400
    assert not (tmp_path / "escaped.zip").exists()
    assert not any(name.startswith(".upload-") for name in os.listdir(tmp_path / "uploads"))


def test_duplicate_upload(app, as_cert):
    as_cert("alice")
    data = zip_bytes(b"shared")
    file_hash = hash_from(upload(app, data))

    # Same group resending the same bytes: idempotent, nothing about the package changes
    as_cert("ann")
    r = upload(app, data)
    assert r.status_code == 200 and hash_from(r) == file_hash
    # Another group: 409, and the package stays alice's/red's
    as_cert("bob")
    assert upload(app, data).status_code == 409
    assert download(app, file_hash).status_code == 403
    with app.app_context():
        dp = db.session.query(DataPackage).filter_by(hash=file_hash).one()
        assert dp.group_names == ["red"]
        assert dp.user.username == "alice"

    # The web upload shares the same code
    r = web_client(app, "bob").post(
        "/api/data_packages",
        data={"file": (io.BytesIO(data), "again.zip", "application/zip")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 409


# --- 2: non-zip uploads are wrapped in a fresh zip ----------------------------------------------


def test_nonzip_named_as_hash_does_not_touch_other_package(app, as_cert):
    as_cert("alice")
    secret = zip_bytes(b"alice-secret")
    victim = hash_from(upload(app, secret))

    as_cert("bob")
    r = upload(app, b"<kml/>", name=f"{victim}.kml", mimetype="application/vnd.google-earth.kml+xml")
    assert r.status_code == 200, r.data
    new_hash = hash_from(r)
    assert new_hash != victim

    as_cert("alice")
    assert download(app, victim).data == secret
    as_cert("bob")
    archive = zipfile.ZipFile(io.BytesIO(download(app, new_hash).data))
    names = archive.namelist()
    assert sorted(n.split("/")[-1] for n in names) == [f"{victim}.kml", "manifest.xml"]
    assert archive.read(next(n for n in names if n.endswith(".kml"))) == b"<kml/>"
    assert b"alice-secret" not in b"".join(archive.read(n) for n in names)


# --- 3: fileshare CoTs only from someone who may share the package ------------------------------


def fileshare(file_hash, sender_uid="ANDROID-alice", dests=("BOB",)):
    dest_xml = "".join(f'<dest callsign="{d}"/>' for d in dests)
    return BeautifulSoup(
        f'<event version="2.0" uid="fs-1" type="b-f-t-r" how="h-e" time="2026-11-01T00:00:00Z" '
        f'start="2026-11-01T00:00:00Z" stale="2026-11-02T00:00:00Z"><point lat="0" lon="0" '
        f'hae="0" ce="0" le="0"/><detail><fileshare filename="x.zip" name="x" '
        f'senderCallsign="X" senderUid="{sender_uid}" senderUrl="u" sha256="{file_hash}" '
        f'sizeInBytes="1"/><marti>{dest_xml}</marti></detail></event>',
        "xml",
    ).find("event")


def recipients(app, file_hash):
    with app.app_context():
        return sorted(
            r.callsign
            for r in db.session.query(DataPackageRecipient).filter_by(data_package_hash=file_hash)
        )


def test_forged_fileshare_grants_nothing(app, as_cert):
    as_cert("alice")
    file_hash = hash_from(upload(app, zip_bytes(b"private")))
    with app.app_context():
        dp = db.session.query(DataPackage).filter_by(hash=file_hash).one()
        dp.tool = "private"
        dp.creator_uid = None
        db.session.commit()

    # bob's connection sends a fileshare for alice's package addressed to himself, naming
    # alice's EUD as the sender
    with app.app_context():
        cot_sharing.record_fileshare_recipients(
            db.session, fileshare(file_hash), "ANDROID-bob", user_id(app, "bob"), LOG
        )
    assert recipients(app, file_hash) == []
    with app.app_context():
        assert db.session.query(DataPackage).filter_by(hash=file_hash).one().creator_uid is None
    as_cert("bob")
    assert download(app, file_hash).status_code == 403

    # ann can see red's packages, but this one is private: only the sender shares it on
    with app.app_context():
        cot_sharing.record_fileshare_recipients(
            db.session, fileshare(file_hash), "ANDROID-ann", user_id(app, "ann"), LOG
        )
        # Anonymous connections never record anything
        cot_sharing.record_fileshare_recipients(
            db.session, fileshare(file_hash), "ANDROID-x", None, LOG
        )
    assert recipients(app, file_hash) == []

    # alice, the uploader, can; her own connection's EUD becomes the sender
    with app.app_context():
        cot_sharing.record_fileshare_recipients(
            db.session, fileshare(file_hash, sender_uid="ANDROID-bob"), "ANDROID-alice",
            user_id(app, "alice"), LOG,
        )
        assert (
            db.session.query(DataPackage).filter_by(hash=file_hash).one().creator_uid
            == "ANDROID-alice"
        )
    assert recipients(app, file_hash) == ["BOB"]
    as_cert("bob")
    assert download(app, file_hash).status_code == 200


def test_public_package_shared_by_group_member(app, as_cert):
    as_cert("alice")
    file_hash = hash_from(upload(app, zip_bytes(b"public")))
    with app.app_context():
        # bob can't see red's package, so can't share it
        cot_sharing.record_fileshare_recipients(
            db.session, fileshare(file_hash), "ANDROID-bob", user_id(app, "bob"), LOG
        )
        assert recipients(app, file_hash) == []
        # ann can
        cot_sharing.record_fileshare_recipients(
            db.session, fileshare(file_hash), "ANDROID-ann", user_id(app, "ann"), LOG
        )
    assert recipients(app, file_hash) == ["BOB"]


# --- 4: video CoTs ------------------------------------------------------------------------------


def video_cot(uid, path, alias="cam", address="10.0.0.1"):
    return BeautifulSoup(
        f'<event version="2.0" uid="v-1" type="b-i-v" how="h-e" time="2026-11-01T00:00:00Z" '
        f'start="2026-11-01T00:00:00Z" stale="2026-11-02T00:00:00Z"><point lat="0" lon="0" '
        f'hae="0" ce="0" le="0"/><detail><__video><ConnectionEntry networkTimeout="12000" '
        f'uid="{uid}" path="/{path}" protocol="rtsp" bufferTime="-1" address="{address}" '
        f'port="8554" roverPort="-1" rtspReliable="0" ignoreEmbeddedKLV="false" alias="{alias}"/>'
        f"</__video></detail></event>",
        "xml",
    ).find("event")


def stream(app, uid):
    with app.app_context():
        v = db.session.query(VideoStream).filter_by(uid=uid).one()
        return v.path, v.alias, v.group_names, v.username


def test_cot_video_gets_senders_groups_and_is_not_rewritten_by_others(app):
    with app.app_context():
        cot_sharing.upsert_cot_video(
            db.session, video_cot("cam-1", "redcam", alias="Red"), None, user_id(app, "alice"), LOG
        )
    assert stream(app, "cam-1") == ("redcam", "Red", ["red"], "alice")

    with app.app_context():
        # bob (blue) can't rewrite red's feed by uid...
        cot_sharing.upsert_cot_video(
            db.session, video_cot("cam-1", "redcam", alias="Pwned"), None, user_id(app, "bob"), LOG
        )
        # ...nor take its path with another uid
        cot_sharing.upsert_cot_video(
            db.session, video_cot("cam-2", "redcam", alias="Pwned"), None, user_id(app, "bob"), LOG
        )
        # nor an anonymous connection
        cot_sharing.upsert_cot_video(
            db.session, video_cot("cam-1", "redcam", alias="Pwned"), None, None, LOG
        )
        assert db.session.query(VideoStream).count() == 1
    assert stream(app, "cam-1") == ("redcam", "Red", ["red"], "alice")

    # ann (red) may update it
    with app.app_context():
        cot_sharing.upsert_cot_video(
            db.session, video_cot("cam-1", "redcam", alias="Red 2"), None, user_id(app, "ann"), LOG
        )
    assert stream(app, "cam-1")[1] == "Red 2"


# --- 5: deleting a group must not make its items public -----------------------------------------


def test_group_delete_refused_while_it_is_the_only_group_of_items(app, as_cert):
    as_cert("bob")
    file_hash = hash_from(upload(app, zip_bytes(b"blue")))
    with app.app_context():
        blue = db.session.query(Group).filter_by(name="blue").one()
        v = VideoStream()
        v.path = "bluecam"
        v.uid = "uid-bluecam"
        v.mediamtx_settings = "{}"
        v.groups = [blue]
        db.session.add(v)
        db.session.commit()

    admin = web_client(app, "admin")
    r = admin.delete("/api/groups", query_string={"group_name": "blue"})
    assert r.status_code == 409
    assert r.json["orphaned_items"] == {"data packages": 1, "video streams": 1}
    with app.app_context():
        assert db.session.query(Group).filter_by(name="blue").first() is not None
    as_cert("alice")
    assert download(app, file_hash).status_code == 403

    # Items that keep another group don't block it
    assert admin.patch(
        "/api/data_packages/groups", json={"hash": file_hash, "groups": ["blue", "red"]}
    ).status_code == 200
    assert admin.patch(
        "/api/video_streams/groups", json={"path": "bluecam", "groups": ["red"]}
    ).status_code == 200
    r = admin.delete("/api/groups", query_string={"group_name": "blue"})
    assert r.status_code == 200, r.json
    with app.app_context():
        assert db.session.query(DataPackage).filter_by(hash=file_hash).one().group_names == ["red"]


def test_pairwise_disconnect_refused_while_it_is_the_only_group_of_items(app):
    with app.app_context():
        group = Group()
        group.name = f"{group_policy.PAIRWISE_PREFIX}alice__bob"
        group.type = Group.SYSTEM
        db.session.add(group)
        db.session.flush()
        dp = DataPackage()
        dp.filename = "pair.zip"
        dp.hash = "pairhash"
        dp.submission_time = datetime.datetime.now(datetime.timezone.utc)
        dp.mime_type = "application/zip"
        dp.size = 1
        dp.groups = [group]
        db.session.add(dp)
        db.session.commit()

    admin = web_client(app, "admin")
    r = admin.delete("/api/users/visibility", query_string={"source": "alice", "target": "bob"})
    assert r.status_code == 409
    assert r.json["orphaned_items"]["data packages"] == 1


# --- 7: thumbnail paths are normalised before the group check -----------------------------------


def test_thumbnail_path_normalised(app):
    with app.app_context():
        v = VideoStream()
        v.path = "redcam"
        v.uid = "uid-redcam"
        v.mediamtx_settings = "{}"
        v.groups = [db.session.query(Group).filter_by(name="red").one()]
        db.session.add(v)
        db.session.commit()
    folder = os.path.join(app.config["RAVEN_DATA_FOLDER"], "mediamtx", "recordings", "redcam")
    os.makedirs(os.path.join(folder, "sub"))
    for f in (os.path.join(folder, "thumbnail.png"), os.path.join(folder, "sub", "thumbnail.png")):
        with open(f, "wb") as out:
            out.write(b"PNGDATA")

    bob = web_client(app, "bob")
    for path in ("redcam", "redcam/", "/redcam", "x/../redcam", "redcam/.", "redcam/sub",
                 "../recordings/redcam", "..", "/"):
        r = bob.get("/api/videos/thumbnail", query_string={"path": path})
        assert r.status_code == 400, path
    assert bob.get(
        "/api/videos/thumbnail", query_string={"path": "bluecam", "recording": "../redcam/thumbnail"}
    ).status_code == 400

    alice = web_client(app, "alice")
    r = alice.get("/api/videos/thumbnail", query_string={"path": "redcam/"})
    assert r.status_code == 200 and r.data == b"PNGDATA"


# --- 8: /Marti/vcm uid collisions ---------------------------------------------------------------


def vcm(uid, path, alias="cam"):
    return (
        f"<videoConnections><feed><protocol>rtsp</protocol><alias>{alias}</alias><uid>{uid}</uid>"
        f"<address>10.0.0.1</address><port>8554</port><path>{path}</path></feed>"
        f"</videoConnections>"
    )


def test_vcm_uid_collision(app, as_cert):
    as_cert("alice")
    client = app.test_client()
    assert client.post("/Marti/vcm", data=vcm("u-1", "/redcam")).status_code == 200

    # Same uid, new path: a clean 409 rather than a 500
    r = client.post("/Marti/vcm", data=vcm("u-1", "/othercam"))
    assert r.status_code == 409
    # Another group's feed: 403, untouched
    as_cert("bob")
    assert client.post("/Marti/vcm", data=vcm("u-1", "/bobcam")).status_code == 403
    assert client.post("/Marti/vcm", data=vcm("u-9", "/redcam", alias="x")).status_code == 403
    with app.app_context():
        assert [(v.path, v.uid, v.alias) for v in db.session.query(VideoStream)] == [
            ("redcam", "u-1", "cam")
        ]
    # The owner group updates it in place
    as_cert("ann")
    assert client.post("/Marti/vcm", data=vcm("u-1", "/redcam", alias="new")).status_code == 200
    with app.app_context():
        assert db.session.get(VideoStream, "redcam").alias == "new"
