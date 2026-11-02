"""
Tests for the device profile preview/export/import/extras endpoints
(raven/blueprints/raven_api/device_profile_tools_api.py).

Minimal Flask app (sqlite, only the blueprint under test), like test_error_log_api.py.
"""

import io
import time
import zipfile
from datetime import datetime

import pytest
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.blueprints.raven_api import device_profile_tools_api as tools  # noqa: E402
from raven.blueprints.raven_api.device_profile_tools_api import (  # noqa: E402
    device_profile_tools_api_blueprint,
)
from raven.defaultconfig import DefaultConfig  # noqa: E402
from raven.models.DataPackage import DataPackage  # noqa: E402
from raven.models.DeviceProfileSet import DeviceProfileSet  # noqa: E402
from raven.models.DeviceProfileSetting import DeviceProfileSetting  # noqa: E402
from raven.models.DeviceProfileTarget import DeviceProfileTarget  # noqa: E402
from raven.models.Packages import Packages  # noqa: E402

STR = "class java.lang.String"
BOOL = "class java.lang.Boolean"
INT = "class java.lang.Integer"

GOOD_PREF = b"""<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<preferences>
  <preference version="1" name="cot_streams">
    <entry key="count" class="class java.lang.Integer">1</entry>
    <entry key="description0" class="class java.lang.String">My server</entry>
    <entry key="connectString0" class="class java.lang.String">tak.example.com:8089:ssl</entry>
    <entry key="caPassword0" class="class java.lang.String">atakatak</entry>
  </preference>
  <preference version="1" name="com.atakmap.app_preferences">
    <entry key="locationTeam" class="class java.lang.String">Cyan</entry>
    <entry key="atakRoleType" class="class java.lang.String">Team Lead</entry>
    <entry key="displayServerConnectionWidget" class="class java.lang.Boolean">true</entry>
    <entry key="locationReportingStrategy" class="class java.lang.String">Dynamic</entry>
    <entry key="constantReportingRateUnreliable" class="class java.lang.Integer">30</entry>
    <entry key="bestDeviceUID" class="class java.lang.String">ANDROID-abc123</entry>
    <entry key="locationCallsign" class="class java.lang.String">VIPER</entry>
    <entry key="clientPassword" class="class java.lang.String">hunter2</entry>
    <entry key="certificateLocation" class="class java.lang.String">/sdcard/atak/cert/me.p12</entry>
    <entry key="atakUpdateServerUrl" class="class java.lang.String">https://x/api/packages</entry>
    <entry key="some_set" class="class java.util.HashSet">a,b</entry>
    <entry key="bad_bool" class="class java.lang.Boolean">maybe</entry>
    <entry key="enabled1" class="class java.lang.Boolean">true</entry>
    <entry key="mapScaleRange" class="class java.lang.String">25</entry>
  </preference>
</preferences>
"""

EXPECTED_KEPT = {
    "locationTeam": ("Cyan", STR),
    "atakRoleType": ("Team Lead", STR),
    "displayServerConnectionWidget": ("true", BOOL),
    "locationReportingStrategy": ("Dynamic", STR),
    "constantReportingRateUnreliable": ("30", INT),
    # Number-looking String stays a String (ATAK reads it with parseInt(getString()))
    "mapScaleRange": ("25", STR),
}


@pytest.fixture
def app(tmp_path):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
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

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(device_profile_tools_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _login(app, client, username):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username=username).fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()


@pytest.fixture
def admin(app):
    client = app.test_client()
    _login(app, client, "admin")
    return client


@pytest.fixture
def alice(app):
    client = app.test_client()
    _login(app, client, "alice")
    return client


def upload(client, data: bytes, filename="prefs.pref"):
    return client.post(
        "/api/device-profiles/import",
        data={"file": (io.BytesIO(data), filename)},
        content_type="multipart/form-data",
    )


def make_profile(app, name, settings, everyone=True, enrollment=True, connection=False, targets=()):
    with app.app_context():
        profile = DeviceProfileSet(
            name=name,
            enabled=True,
            apply_on_enrollment=enrollment,
            apply_on_connection=connection,
            target_everyone=everyone,
            created_at=datetime(2026, 1, 1),
            updated_at=datetime(2026, 1, 1),
        )
        profile.settings = [DeviceProfileSetting(key=k, value=v, value_class=c) for k, v, c in settings]
        profile.targets = [DeviceProfileTarget(kind=k, value=v) for k, v in targets]
        db.session.add(profile)
        db.session.commit()
        return profile.id


def add_extras(app):
    with app.app_context():
        common = dict(mime_type="application/zip", size=1, submission_time=datetime(2026, 1, 1))
        db.session.add_all(
            [
                DataPackage(filename="maps.zip", hash="h1", install_on_enrollment=True, install_on_connection=False, **common),
                DataPackage(filename="overlays.zip", hash="h2", install_on_enrollment=False, install_on_connection=True, **common),
                DataPackage(filename="unused.zip", hash="h3", install_on_enrollment=False, install_on_connection=False, **common),
            ]
        )
        pkg = dict(platform="Android", plugin_type="plugin", version="1", file_size=1, publish_time=datetime(2026, 1, 1))
        db.session.add_all(
            [
                Packages(name="Remote Clear", package_name="a", file_name="a.apk", install_on_enrollment=True, install_on_connection=True, **pkg),
                Packages(name="Idle", package_name="b", file_name="b.apk", install_on_enrollment=False, install_on_connection=False, **pkg),
            ]
        )
        db.session.commit()


# --- import ---


def test_import_good_pref(admin):
    r = upload(admin, GOOD_PREF)
    assert r.status_code == 200, r.json
    got = {s["key"]: (s["value"], s["value_class"]) for s in r.json["settings"]}
    assert got == EXPECTED_KEPT

    skipped = {s["key"]: s["reason"] for s in r.json["skipped"]}
    for key in ("count", "description0", "connectString0"):
        assert "connection" in skipped[key].lower()
    assert "password" in skipped["caPassword0"].lower()
    assert "identity" in skipped["bestDeviceUID"].lower()
    assert "identity" in skipped["locationCallsign"].lower()
    assert "password" in skipped["clientPassword"].lower()
    assert "certificate" in skipped["certificateLocation"].lower()
    assert "server" in skipped["atakUpdateServerUrl"].lower()
    assert "unsupported" in skipped["some_set"].lower()
    assert "bad_bool" in skipped
    assert "connection" in skipped["enabled1"].lower()
    # Nothing secret leaks into the result
    assert "hunter2" not in r.get_data(as_text=True)
    assert "atakatak" not in r.get_data(as_text=True)


def test_import_zip_data_package(admin):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("MANIFEST/manifest.xml", "<MissionPackageManifest version='2'/>")
        zf.writestr("abc/preference.pref", GOOD_PREF)
        zf.writestr(
            "abc/extra.pref",
            b'<preferences><preference version="1" name="com.atakmap.app_preferences">'
            b'<entry key="locationTeam" class="class java.lang.String">Red</entry>'
            b"</preference></preferences>",
        )
    r = upload(admin, buf.getvalue(), "package.zip")
    assert r.status_code == 200, r.json
    got = {s["key"]: s["value"] for s in r.json["settings"]}
    assert set(got) == set(EXPECTED_KEPT)
    assert got["locationTeam"] in ("Red", "Cyan")


def test_import_zip_without_pref(admin):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hi")
    r = upload(admin, buf.getvalue(), "x.zip")
    assert r.status_code == 400
    assert "No .pref" in r.json["error"]


def test_import_zip_slip_rejected(admin):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.pref", GOOD_PREF)
    r = upload(admin, buf.getvalue(), "x.zip")
    assert r.status_code == 400
    assert "Unsafe" in r.json["error"]


def test_import_zip_too_many_entries(admin):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(tools.MAX_ZIP_ENTRIES + 1):
            zf.writestr(f"f{i}.txt", "x")
    r = upload(admin, buf.getvalue(), "x.zip")
    assert r.status_code == 400
    assert "too many" in r.json["error"]


def test_import_zip_bomb_member_rejected(admin):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.pref", b"<preferences>" + b" " * (tools.MAX_PREF_BYTES + 10) + b"</preferences>")
    assert len(buf.getvalue()) < tools.MAX_UPLOAD_BYTES
    r = upload(admin, buf.getvalue(), "x.zip")
    assert r.status_code == 400
    assert "too large" in r.json["error"]


@pytest.mark.parametrize(
    "payload",
    [
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
        b'<preferences><preference name="x"><entry key="a" class="class java.lang.String">&lol2;</entry>'
        b"</preference></preferences>",
        b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b'<preferences><preference name="x"><entry key="a" class="class java.lang.String">&xxe;</entry>'
        b"</preference></preferences>",
    ],
)
def test_import_doctype_rejected(admin, payload):
    r = upload(admin, payload)
    assert r.status_code == 400
    assert "DOCTYPE" in r.json["error"]


def test_import_oversize_rejected(admin):
    r = upload(admin, b"<preferences>" + b" " * (tools.MAX_UPLOAD_BYTES + 1) + b"</preferences>")
    assert r.status_code == 413


def test_import_garbage_and_wrong_root(admin):
    assert upload(admin, b"not xml at all").status_code == 400
    r = upload(admin, b"<html><body/></html>")
    assert r.status_code == 400
    assert "ATAK" in r.json["error"]


def test_import_no_file(admin):
    r = admin.post("/api/device-profiles/import", data={}, content_type="multipart/form-data")
    assert r.status_code == 400


# --- export ---


def test_export_round_trip(app, admin):
    settings = [
        ("locationTeam", "Dark Blue", STR),
        ("displayServerConnectionWidget", "false", BOOL),
        ("constantReportingRateUnreliable", "15", INT),
        ("custom_text", 'a <tricky> & "quoted" value', STR),
    ]
    pid = make_profile(app, "Team / Alpha: defaults", settings)

    r = admin.get(f"/api/device-profiles/{pid}/export")
    assert r.status_code == 200
    disposition = r.headers["Content-Disposition"]
    assert disposition.startswith("attachment;")
    assert 'filename="Team _ Alpha_ defaults.pref"' in disposition
    body = r.get_data()
    assert b'name="com.atakmap.app_preferences"' in body

    r2 = upload(admin, body, "Team _ Alpha_ defaults.pref")
    assert r2.status_code == 200, r2.json
    assert r2.json["skipped"] == []
    got = sorted((s["key"], s["value"], s["value_class"]) for s in r2.json["settings"])
    assert got == sorted(settings)


def test_export_missing_profile(admin):
    assert admin.get("/api/device-profiles/9999/export").status_code == 404


def test_safe_filename():
    assert tools.safe_filename('../../etc/"passwd"\r\n') == "etc_passwd.pref"
    assert tools.safe_filename("") == "device-profile.pref"


# --- preview & extras ---


def test_preview(app, admin):
    add_extras(app)
    make_profile(app, "Everyone", [("locationTeam", "Cyan", STR), ("atakRoleType", "Medic", STR)])
    make_profile(
        app,
        "Alice",
        [("locationTeam", "Red", STR)],
        everyone=False,
        targets=[("user", "alice")],
    )
    make_profile(app, "Conn only", [("repoX", "1", STR)], enrollment=False, connection=True)

    r = admin.get("/api/device-profiles/preview", query_string={"username": "alice", "phase": "enrollment"})
    assert r.status_code == 200, r.json
    by_key = {s["key"]: s for s in r.json["settings"]}
    assert set(by_key) == {"locationTeam", "atakRoleType"}
    assert by_key["locationTeam"]["value"] == "Red"
    assert by_key["locationTeam"]["profile_name"] == "Alice"
    assert by_key["atakRoleType"]["profile_name"] == "Everyone"
    assert r.json["data_packages"] == [{"name": "maps.zip"}]
    assert r.json["plugins"] == [{"name": "Remote Clear"}]

    r = admin.get("/api/device-profiles/preview", query_string={"username": "admin", "phase": "connection"})
    assert r.status_code == 200
    assert [s["key"] for s in r.json["settings"]] == ["repoX"]
    assert r.json["data_packages"] == [{"name": "overlays.zip"}]
    assert r.json["plugins"] == [{"name": "Remote Clear"}]


def test_preview_bad_phase(admin):
    r = admin.get("/api/device-profiles/preview", query_string={"phase": "sometimes"})
    assert r.status_code == 400


def test_extras(app, admin):
    add_extras(app)
    r = admin.get("/api/device-profiles/extras")
    assert r.status_code == 200
    assert r.json == {
        "data_packages": [
            {"name": "maps.zip", "install_on_enrollment": True, "install_on_connection": False},
            {"name": "overlays.zip", "install_on_enrollment": False, "install_on_connection": True},
        ],
        "plugins": [
            {"name": "Remote Clear", "install_on_enrollment": True, "install_on_connection": True},
        ],
    }


# --- auth ---


def test_non_admin_forbidden(app, alice):
    pid = make_profile(app, "P", [("locationTeam", "Cyan", STR)])
    assert alice.get("/api/device-profiles/extras").status_code == 403
    assert alice.get("/api/device-profiles/preview?phase=enrollment&username=alice").status_code == 403
    assert alice.get(f"/api/device-profiles/{pid}/export").status_code == 403
    assert upload(alice, GOOD_PREF).status_code == 403


def test_anonymous_rejected(app):
    client = app.test_client()
    # 302 to the login page in this bare app; the real app answers JSON 401
    assert client.get("/api/device-profiles/extras").status_code in (302, 401, 403)
    assert upload(client, GOOD_PREF).status_code in (302, 401, 403)


def test_preview_device_only(app, admin):
    make_profile(app, "Everyone", [("locationTeam", "Cyan", STR)])
    make_profile(app, "Phone", [("locationTeam", "Green", STR)], everyone=False, targets=[("device", "ANDROID-1")])
    r = admin.get("/api/device-profiles/preview", query_string={"eud_uid": "ANDROID-1", "phase": "enrollment"})
    assert r.status_code == 200
    assert r.json["settings"][0]["value"] == "Green"
    assert r.json["settings"][0]["profile_name"] == "Phone"


def _add_file(app, profile_id, zip_path):
    from raven.models.DeviceProfileFile import DeviceProfileFile

    with app.app_context():
        profile = db.session.get(DeviceProfileSet, profile_id)
        profile.files.append(
            DeviceProfileFile(
                filename=zip_path.rsplit("/", 1)[-1],
                zip_path=zip_path,
                stored_name=f"stored-{profile_id}-{zip_path.replace('/', '-')}",
                size=4,
                sha256="0" * 64,
                created_at=datetime(2026, 1, 1),
            )
        )
        db.session.commit()


def test_preview_files_and_tool(app, admin):
    add_extras(app)
    everyone = make_profile(app, "Everyone", [("locationTeam", "Cyan", STR)])
    _add_file(app, everyone, "maps/base.xml")
    alice = make_profile(app, "Alice", [], everyone=False, targets=[("user", "alice")])
    _add_file(app, alice, "maps/base.xml")
    _add_file(app, alice, "alice.pref")
    tool = make_profile(app, "Mission", [("missionX", "1", STR)])
    with app.app_context():
        db.session.get(DeviceProfileSet, tool).tool = "mission"
        db.session.commit()
    _add_file(app, tool, "mission.pref")

    r = admin.get("/api/device-profiles/preview", query_string={"username": "alice", "phase": "enrollment"})
    assert r.status_code == 200, r.json
    files = {f["zip_path"]: f["profile_name"] for f in r.json["files"]}
    assert files == {"alice.pref": "Alice", "maps/base.xml": "Alice"}
    assert "missionX" not in {s["key"] for s in r.json["settings"]}

    r = admin.get("/api/device-profiles/preview", query_string={"username": "alice", "phase": "tool", "tool": "Mission"})
    assert r.status_code == 200, r.json
    assert [s["key"] for s in r.json["settings"]] == ["missionX"]
    assert [f["zip_path"] for f in r.json["files"]] == ["mission.pref"]
    assert r.json["data_packages"] == [] and r.json["plugins"] == []

    r = admin.get("/api/device-profiles/preview", query_string={"username": "alice", "phase": "tool"})
    assert r.status_code == 400
