"""Device profiles: CRUD + validation (raven/blueprints/raven_api/device_profile_api.py),
resolution precedence (raven/device_profiles.py), the enrollment/connection data packages
(raven/blueprints/marti_api/device_profile_marti_api.py) and the legacy-row migration mapping
(raven/migrations/versions/d3f1a7c95b20_device_profile_sets.py).

Minimal sqlite Flask app, as in tests/test_group_policies.py.
"""

import base64
import datetime
import importlib.util
import io
import os
import time
import zipfile
from xml.etree import ElementTree

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

from raven import device_profiles  # noqa: E402
from raven.audit import init_audit  # noqa: E402
from raven.blueprints.marti_api import device_profile_marti_api as marti  # noqa: E402
from raven.blueprints.raven_api.device_profile_api import device_profile_api_blueprint  # noqa: E402
from raven.models.AuditEvent import AuditEvent  # noqa: E402
from raven.models.DeviceProfileSet import DeviceProfileSet  # noqa: E402
from raven.models.EUD import EUD  # noqa: E402
from raven.models.Group import Group  # noqa: E402
from raven.models.GroupUser import GroupUser  # noqa: E402

BOOL = "class java.lang.Boolean"
STR = "class java.lang.String"
INT = "class java.lang.Integer"
LONG = "class java.lang.Long"
FLOAT = "class java.lang.Float"


@pytest.fixture
def app(tmp_path, monkeypatch):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        UPLOAD_FOLDER=str(tmp_path),
        RAVEN_ENABLE_LDAP=False,
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        WTF_CSRF_ENABLED=False,
        SECURITY_PASSWORD_HASH="plaintext",
        SECURITY_USER_IDENTITY_ATTRIBUTES=[
            {"username": {"mapper": lambda x: x, "case_insensitive": True}}
        ],
        RAVEN_CA_PASSWORD="atakatak",
        RAVEN_PROFILE_MAP_SOURCES=False,
    )
    db.init_app(app)
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    init_audit(app)
    app.register_blueprint(device_profile_api_blueprint)
    app.register_blueprint(marti.device_profile_marti_api_blueprint)

    # No CA in these tests: the truststore and remote clear key are stand-ins
    monkeypatch.setattr(marti, "export_onboard_truststore", lambda *a, **k: b"p12")
    monkeypatch.setattr(marti.remote_clear, "public_key_der_b64", lambda: "PUBKEY")

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("x"), roles=["administrator"])
        alice = ds.create_user(username="alice", password=hash_password("goodpass"), roles=["user"])
        bob = ds.create_user(username="bob", password=hash_password("goodpass"), roles=["user"])
        db.session.flush()
        for name in ("team", "other"):
            g = Group()
            g.name = name
            g.type = Group.SYSTEM
            db.session.add(g)
        db.session.flush()
        team = db.session.query(Group).filter_by(name="team").one()
        db.session.add(GroupUser(user_id=alice.id, group_id=team.id, direction="OUT", enabled=True))
        db.session.add(EUD(uid="ANDROID-alice", callsign="ALPHA", user_id=alice.id))
        db.session.add(EUD(uid="ANDROID-bob", callsign="BRAVO", user_id=bob.id))
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _login(app, username):
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
    return _login(app, "admin")


def profile_input(**overrides):
    data = {
        "name": "Base",
        "description": "d",
        "enabled": True,
        "apply_on_enrollment": True,
        "apply_on_connection": True,
        "target_everyone": True,
        "targets": [],
        "settings": [{"key": "locationTeam", "value": "Cyan", "value_class": STR}],
    }
    data.update(overrides)
    return data


def create(admin, **overrides):
    r = admin.post("/api/device-profiles", json=profile_input(**overrides))
    assert r.status_code == 200, r.json
    return r.json["profile"]


def audit_actions(app):
    with app.app_context():
        return [
            (e.action, e.actor)
            for e in db.session.query(AuditEvent)
            .filter_by(category="device_profiles")
            .order_by(AuditEvent.id)
        ]


def basic(username, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()}


def pref_entries(response):
    assert response.status_code == 200, response.data
    with zipfile.ZipFile(io.BytesIO(response.data)) as z:
        xml = z.read("5c2bfcae3d98c9f4d262172df99ebac5/preference.pref")
    root = ElementTree.fromstring(xml)
    return {e.get("key"): (e.text, e.get("class")) for e in root.iter("entry")}


# --- CRUD ---


def test_crud_roundtrip_and_audit(admin, app):
    p = create(
        admin,
        target_everyone=False,
        targets=[
            {"kind": "group", "value": "team"},
            {"kind": "user", "value": "ALICE"},
            {"kind": "device", "value": "ANDROID-alice"},
            {"kind": "device", "value": "never-seen"},
        ],
    )
    assert p["name"] == "Base" and p["id"]
    assert p["targets"] == [
        {"kind": "group", "value": "team", "label": "team"},
        {"kind": "user", "value": "alice", "label": "alice"},  # stored as the account spells it
        {"kind": "device", "value": "ANDROID-alice", "label": "ALPHA"},
        {"kind": "device", "value": "never-seen", "label": "never-seen"},
    ]
    assert p["settings"] == [{"key": "locationTeam", "value": "Cyan", "value_class": STR}]
    assert p["created_at"].endswith("Z") and p["updated_at"]

    listed = admin.get("/api/device-profiles").json
    assert [x["id"] for x in listed] == [p["id"]]

    r = admin.put(
        f"/api/device-profiles/{p['id']}",
        json=profile_input(
            name="Renamed",
            settings=[
                {"key": "locationTeam", "value": "Red", "value_class": STR},
                {"key": "displayRed", "value": "TRUE", "value_class": BOOL},
            ],
        ),
    )
    assert r.status_code == 200, r.json
    updated = r.json["profile"]
    assert updated["name"] == "Renamed"
    assert updated["targets"] == [] and updated["target_everyone"] is True
    assert {s["key"]: s["value"] for s in updated["settings"]} == {
        "locationTeam": "Red",
        "displayRed": "true",
    }

    r = admin.post(f"/api/device-profiles/{p['id']}/duplicate")
    assert r.status_code == 200, r.json
    assert r.json["profile"]["name"] == "Renamed (copy)"
    assert r.json["profile"]["settings"] == updated["settings"]
    r = admin.post(f"/api/device-profiles/{p['id']}/duplicate")
    assert r.json["profile"]["name"] == "Renamed (copy 2)"

    assert admin.delete(f"/api/device-profiles/{p['id']}").json == {"success": True}
    assert admin.delete(f"/api/device-profiles/{p['id']}").status_code == 404
    assert admin.put(f"/api/device-profiles/{p['id']}", json=profile_input()).status_code == 404
    assert len(admin.get("/api/device-profiles").json) == 2

    assert audit_actions(app) == [
        ("profile_created", "admin"),
        ("profile_updated", "admin"),
        ("profile_duplicated", "admin"),
        ("profile_duplicated", "admin"),
        ("profile_deleted", "admin"),
    ]


def test_settings_cascade_on_delete(admin, app):
    p = create(admin)
    admin.delete(f"/api/device-profiles/{p['id']}")
    with app.app_context():
        from raven.models.DeviceProfileSetting import DeviceProfileSetting

        assert db.session.query(DeviceProfileSetting).count() == 0


def test_non_admin_forbidden(app):
    alice = _login(app, "alice")
    assert alice.get("/api/device-profiles").status_code == 403
    assert alice.post("/api/device-profiles", json=profile_input()).status_code == 403
    assert app.test_client().get("/api/device-profiles").status_code in (401, 302)


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"name": ""}, "Name is required"),
        ({"name": None}, "Name is required"),
        ({"target_everyone": False, "targets": []}, "Choose who"),
        ({"targets": [{"kind": "group", "value": "nope"}]}, "does not exist"),
        ({"targets": [{"kind": "user", "value": "nobody"}]}, "does not exist"),
        ({"targets": [{"kind": "team", "value": "x"}]}, "Target kind"),
        ({"enabled": "yes"}, "enabled must be"),
        ({"settings": [{"key": "", "value": "x", "value_class": STR}]}, "needs a key"),
        ({"settings": [{"key": "a b", "value": "x", "value_class": STR}]}, "not a valid"),
        ({"settings": [{"key": "k", "value": "x", "value_class": "class java.lang.Double"}]}, "value_class"),
        ({"settings": [{"key": "k", "value": "yes", "value_class": BOOL}]}, "true or false"),
        ({"settings": [{"key": "k", "value": "1.5", "value_class": INT}]}, "whole number"),
        ({"settings": [{"key": "k", "value": "", "value_class": INT}]}, "whole number"),
        ({"settings": [{"key": "k", "value": "99999999999", "value_class": INT}]}, "out of range"),
        ({"settings": [{"key": "k", "value": "abc", "value_class": FLOAT}]}, "not a number"),
        ({"settings": [{"key": "k", "value": "nan", "value_class": FLOAT}]}, "not a number"),
        (
            {
                "settings": [
                    {"key": "k", "value": "1", "value_class": STR},
                    {"key": "k", "value": "2", "value_class": STR},
                ]
            },
            "more than once",
        ),
    ],
)
def test_validation_errors(admin, overrides, message):
    r = admin.post("/api/device-profiles", json=profile_input(**overrides))
    assert r.status_code == 400
    assert r.json["success"] is False
    assert message in r.json["error"]


def test_duplicate_name_rejected(admin):
    create(admin)
    r = admin.post("/api/device-profiles", json=profile_input(name="base"))
    assert r.status_code == 400 and "already exists" in r.json["error"]
    other = create(admin, name="Other")
    r = admin.put(f"/api/device-profiles/{other['id']}", json=profile_input(name="Base"))
    assert r.status_code == 400
    # Keeping its own name is fine
    r = admin.put(f"/api/device-profiles/{other['id']}", json=profile_input(name="Other"))
    assert r.status_code == 200


def test_value_coercion():
    v = device_profiles.validate_setting
    assert v({"key": "k", "value": "True", "value_class": BOOL})["value"] == "true"
    assert v({"key": "k", "value": False, "value_class": BOOL})["value"] == "false"
    assert v({"key": "k", "value": " 42 ", "value_class": INT})["value"] == "42"
    assert v({"key": "k", "value": "-7", "value_class": INT})["value"] == "-7"
    assert v({"key": "k", "value": 9999999999, "value_class": LONG})["value"] == "9999999999"
    assert v({"key": "k", "value": "1.25", "value_class": FLOAT})["value"] == "1.25"
    assert v({"key": "k", "value": 3, "value_class": FLOAT})["value"] == "3"
    assert v({"key": "k", "value": "  keep spaces ", "value_class": STR})["value"] == "  keep spaces "
    assert v({"key": "k", "value": None, "value_class": STR})["value"] == ""
    # Numeric text stays a String, unconverted (ATAK parses those prefs from strings)
    assert v({"key": "k", "value": "42", "value_class": STR}) == {"key": "k", "value": "42", "value_class": STR}
    assert v({"key": "k", "value": "007", "value_class": STR})["value"] == "007"
    # Short forms are normalised to the full ATAK class
    assert v({"key": "k", "value": "1", "value_class": "Integer"})["value_class"] == INT
    assert v({"key": "k", "value": "x"})["value_class"] == STR
    with pytest.raises(device_profiles.ProfileValidationError):
        v({"key": "k", "value": "١٢", "value_class": INT})  # non-ASCII digits
    # Python-only float spellings ATAK's Float.parseFloat rejects
    for bad in ("1_0", "nan", "inf"):
        with pytest.raises(device_profiles.ProfileValidationError):
            v({"key": "k", "value": bad, "value_class": FLOAT})
    # Characters XML can't carry would break the whole preference.pref on the device
    with pytest.raises(device_profiles.ProfileValidationError):
        v({"key": "k", "value": "a\x01b", "value_class": STR})
    with pytest.raises(device_profiles.ProfileValidationError):
        v({"key": "k\x02", "value": "x", "value_class": STR})
    assert v({"key": "k", "value": "a\tb\nc", "value_class": STR})["value"] == "a\tb\nc"


# --- resolution ---


def _resolve(app, phase, username, eud_uid):
    with app.app_context():
        return {
            s["key"]: (s["value"], s["profile_name"])
            for s in device_profiles.resolve_settings(phase, username, eud_uid)
        }


def test_precedence_everyone_group_user_device(admin, app):
    def s(value):
        return [{"key": "locationTeam", "value": value, "value_class": STR}]

    create(admin, name="Device", target_everyone=False, targets=[{"kind": "device", "value": "ANDROID-alice"}], settings=s("Device"))
    create(admin, name="User", target_everyone=False, targets=[{"kind": "user", "value": "alice"}], settings=s("User"))
    create(admin, name="Group", target_everyone=False, targets=[{"kind": "group", "value": "team"}], settings=s("Group"))
    create(
        admin,
        name="Everyone",
        settings=s("Everyone") + [{"key": "displayRed", "value": "true", "value_class": BOOL}],
    )

    assert _resolve(app, "connection", "alice", "ANDROID-alice")["locationTeam"] == ("Device", "Device")
    assert _resolve(app, "connection", "alice", None)["locationTeam"] == ("User", "User")
    assert _resolve(app, "connection", "alice", "other-device")["locationTeam"] == ("User", "User")
    assert _resolve(app, "connection", "bob", "ANDROID-bob")["locationTeam"] == ("Everyone", "Everyone")
    assert _resolve(app, "connection", None, None) == {
        "displayRed": ("true", "Everyone"),
        "locationTeam": ("Everyone", "Everyone"),
    }
    # Keys only set at a lower level still come through
    assert _resolve(app, "connection", "alice", "ANDROID-alice")["displayRed"] == ("true", "Everyone")
    # Username matching is case-insensitive
    assert _resolve(app, "connection", "ALICE", None)["locationTeam"] == ("User", "User")

    # Group membership counts only while it's enabled and unexpired
    with app.app_context():
        m = db.session.query(GroupUser).one()
        m.expires_at = datetime.datetime(2000, 1, 1)
        db.session.commit()
    admin_user_profile = [p for p in admin.get("/api/device-profiles").json if p["name"] == "User"][0]
    admin.delete(f"/api/device-profiles/{admin_user_profile['id']}")
    assert _resolve(app, "connection", "alice", None)["locationTeam"] == ("Everyone", "Everyone")


def test_tie_newest_profile_wins_and_most_specific_match_counts(admin, app):
    old = create(admin, name="Old", settings=[{"key": "k", "value": "old", "value_class": STR}])
    create(admin, name="New", settings=[{"key": "k", "value": "new", "value_class": STR}])
    assert _resolve(app, "enrollment", "bob", None)["k"] == ("new", "New")

    # Editing "Old" makes it the newest
    time.sleep(0.01)
    admin.put(
        f"/api/device-profiles/{old['id']}",
        json=profile_input(name="Old", settings=[{"key": "k", "value": "old2", "value_class": STR}]),
    )
    assert _resolve(app, "enrollment", "bob", None)["k"] == ("old2", "Old")

    # A profile targeting everyone AND bob ranks as a user match for bob
    create(
        admin,
        name="Both",
        targets=[{"kind": "user", "value": "bob"}],
        settings=[{"key": "k", "value": "both", "value_class": STR}],
    )
    create(admin, name="Newest everyone", settings=[{"key": "k", "value": "e", "value_class": STR}])
    assert _resolve(app, "enrollment", "bob", None)["k"] == ("both", "Both")
    assert _resolve(app, "enrollment", "alice", None)["k"] == ("e", "Newest everyone")


def test_phase_and_enabled_filters(admin, app):
    create(admin, name="Enroll", apply_on_connection=False, settings=[{"key": "a", "value": "1", "value_class": STR}])
    create(admin, name="Connect", apply_on_enrollment=False, settings=[{"key": "b", "value": "1", "value_class": STR}])
    create(admin, name="Off", enabled=False, settings=[{"key": "c", "value": "1", "value_class": STR}])
    assert set(_resolve(app, "enrollment", "bob", None)) == {"a"}
    assert set(_resolve(app, "connection", "bob", None)) == {"b"}
    with app.app_context(), pytest.raises(ValueError):
        device_profiles.resolve_settings("bogus", None, None)


# --- Marti data packages ---


def test_enrollment_profile_uses_basic_auth_user(admin, app):
    create(admin, name="Everyone", settings=[{"key": "locationTeam", "value": "Cyan", "value_class": STR}])
    create(
        admin,
        name="Alice",
        target_everyone=False,
        targets=[{"kind": "user", "value": "alice"}],
        settings=[
            {"key": "locationTeam", "value": "Red", "value_class": STR},
            {"key": "atakRoleType", "value": "Medic", "value_class": STR},
            # Overrides a built-in entry instead of duplicating it
            {"key": "repoStartupSync", "value": "false", "value_class": BOOL},
        ],
    )
    create(
        admin,
        name="Bob device",
        target_everyone=False,
        targets=[{"kind": "device", "value": "ANDROID-bob"}],
        settings=[{"key": "locationCallsign", "value": "B1", "value_class": STR}],
    )
    client = app.test_client()
    assert client.get("/Marti/api/tls/profile/enrollment").status_code == 401
    assert client.get("/Marti/api/tls/profile/enrollment", headers=basic("alice", "bad")).status_code == 401

    r = client.get("/Marti/api/tls/profile/enrollment", headers=basic("alice", "goodpass"))
    entries = pref_entries(r)
    assert entries["locationTeam"] == ("Red", STR)
    assert entries["atakRoleType"] == ("Medic", STR)
    assert entries["repoStartupSync"] == ("false", BOOL)
    with zipfile.ZipFile(io.BytesIO(r.data)) as z:
        xml = z.read("5c2bfcae3d98c9f4d262172df99ebac5/preference.pref").decode()
    assert xml.count('key="repoStartupSync"') == 1

    # A built-in entry keeps its class (ATAK reads it with getBoolean), and the update server CA
    # entries describe the truststore in the same zip, so profiles can't change them
    create(
        admin,
        name="Bad types",
        target_everyone=False,
        targets=[{"kind": "user", "value": "bob"}],
        settings=[
            {"key": "deviceProfileEnableOnConnect", "value": "true", "value_class": STR},
            {"key": "appMgmtEnableUpdateServer", "value": "1", "value_class": INT},
            {"key": "updateServerCaPassword", "value": "nope", "value_class": STR},
        ],
    )
    entries = pref_entries(client.get("/Marti/api/tls/profile/enrollment", headers=basic("bob", "goodpass")))
    assert entries["deviceProfileEnableOnConnect"] == ("true", BOOL)
    assert entries["appMgmtEnableUpdateServer"] == ("true", BOOL)
    assert entries["updateServerCaPassword"][0] != "nope"

    entries = pref_entries(client.get("/Marti/api/tls/profile/enrollment", headers=basic("bob", "goodpass")))
    assert entries["locationTeam"] == ("Cyan", STR)
    assert "atakRoleType" not in entries

    # Bob's device settings: only for bob, not for alice claiming bob's device uid
    r = client.get(
        "/Marti/api/tls/profile/enrollment?clientUid=ANDROID-bob", headers=basic("bob", "goodpass")
    )
    assert pref_entries(r)["locationCallsign"] == ("B1", STR)
    r = client.get(
        "/Marti/api/tls/profile/enrollment?clientUid=ANDROID-bob", headers=basic("alice", "goodpass")
    )
    assert "locationCallsign" not in pref_entries(r)


class _FakeCert:
    def __init__(self, cn):
        self._cn = cn

    def get_subject(self):
        return type("Subject", (), {"commonName": self._cn})()


def test_connection_profile_requires_auth_and_resolves(admin, app, monkeypatch):
    create(admin, name="Everyone", apply_on_enrollment=False, settings=[{"key": "locationTeam", "value": "Cyan", "value_class": STR}])
    create(
        admin,
        name="Team",
        apply_on_enrollment=False,
        target_everyone=False,
        targets=[{"kind": "group", "value": "team"}],
        settings=[{"key": "locationTeam", "value": "Green", "value_class": STR}],
    )
    create(
        admin,
        name="Alice phone",
        apply_on_enrollment=False,
        target_everyone=False,
        targets=[{"kind": "device", "value": "ANDROID-alice"}],
        settings=[
            {"key": "locationCallsign", "value": "A1", "value_class": STR},
            {"key": "ravenclear.server_pubkey", "value": "evil", "value_class": STR},
        ],
    )
    client = app.test_client()
    url = "/Marti/api/device/profile/connection?clientUid=ANDROID-alice&syncSecago=-1"

    # No cert, no credentials: refused on both routes
    assert client.get(url).status_code == 401
    assert client.get("/api/connection?clientUid=ANDROID-alice").status_code == 401
    # An unverifiable cert header is no better
    assert client.get(url, headers={"X-Ssl-Cert": "garbage"}).status_code == 401

    # Verified client cert for alice (as nginx forwards on 8443)
    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("alice"))
    entries = pref_entries(client.get(url))
    assert entries["locationTeam"] == ("Green", STR)  # group beats everyone
    assert entries["locationCallsign"] == ("A1", STR)  # device-targeted
    assert entries["ravenclear.server_pubkey"] == ("PUBKEY", STR)  # protected
    assert entries["repoStartupSync"] == ("true", BOOL)

    # bob's cert asking for alice's device gets bob's settings, not her device's
    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("bob"))
    entries = pref_entries(client.get(url))
    assert entries["locationTeam"] == ("Cyan", STR)
    assert "locationCallsign" not in entries

    # Basic credentials work too
    monkeypatch.setattr(marti, "verify_client_cert", lambda: False)
    entries = pref_entries(client.get(url, headers=basic("alice", "goodpass")))
    assert entries["locationCallsign"] == ("A1", STR)
    assert client.get(url, headers=basic("alice", "bad")).status_code == 401

    # Legacy opt-out: anonymous callers get the claimed device's settings
    app.config["RAVEN_CONNECTION_PROFILE_REQUIRE_AUTH"] = False
    entries = pref_entries(client.get(url))
    assert entries["locationTeam"] == ("Green", STR)
    assert entries["locationCallsign"] == ("A1", STR)


def test_connection_sync_secago_only_sends_recent_profiles(admin, app, monkeypatch):
    create(admin, name="Old", apply_on_enrollment=False, settings=[{"key": "a", "value": "1", "value_class": STR}])
    create(admin, name="New", apply_on_enrollment=False, settings=[{"key": "b", "value": "1", "value_class": STR}])
    with app.app_context():
        old = db.session.query(DeviceProfileSet).filter_by(name="Old").one()
        old.updated_at = datetime.datetime(2020, 1, 1)
        db.session.commit()
    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("bob"))
    client = app.test_client()
    entries = pref_entries(client.get("/Marti/api/device/profile/connection?syncSecago=3600"))
    assert "b" in entries and "a" not in entries
    entries = pref_entries(client.get("/Marti/api/device/profile/connection?syncSecago=-1"))
    assert "a" in entries and "b" in entries


# --- legacy migration mapping ---


def _migration():
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "raven",
        "migrations",
        "versions",
        "d3f1a7c95b20_device_profile_sets.py",
    )
    spec = importlib.util.spec_from_file_location("dp_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _row(id, key, value="v", value_class=STR, enrollment=True, connection=False, active=True, eud_uid=None, t=None):
    return {
        "id": id,
        "preference_key": key,
        "preference_value": value,
        "value_class": value_class,
        "enrollment": enrollment,
        "connection": connection,
        "active": active,
        "publish_time": t or datetime.datetime(2026, 1, 1),
        "eud_uid": eud_uid,
    }


def test_migration_mapping():
    build = _migration().build_profiles
    rows = [
        _row(1, "", eud_uid="ANDROID-1"),  # the live DB's junk row
        _row(2, "   "),
        _row(3, "locationTeam", "Cyan"),
        _row(4, "displayRed", "true", BOOL, enrollment=False, connection=True),
        _row(5, "locationTeam", "Red", t=datetime.datetime(2026, 2, 1)),  # newer duplicate wins
        _row(6, "oldThing", "1", INT, active=False),
        _row(7, "locationCallsign", "A1", eud_uid="ANDROID-1", enrollment=False, connection=True),
        _row(8, "mapScale", "5", "Integer", eud_uid="ANDROID-2"),
        _row(9, "nullValue", None, None, eud_uid="ANDROID-2", enrollment=None),
    ]
    profiles = {p["name"]: p for p in build(rows, {"ANDROID-1": "ALPHA"})}
    assert set(profiles) == {
        "Default settings",
        "Default settings (inactive)",
        "Settings for ALPHA",
        "Settings for ANDROID-2",
    }

    default = profiles["Default settings"]
    assert default["target_everyone"] is True and default["targets"] == []
    assert default["enabled"] is True
    assert default["apply_on_enrollment"] is True and default["apply_on_connection"] is True
    assert default["settings"] == [
        {"key": "displayRed", "value": "true", "value_class": BOOL},
        {"key": "locationTeam", "value": "Red", "value_class": STR},
    ]
    assert default["updated_at"] == datetime.datetime(2026, 2, 1)

    inactive = profiles["Default settings (inactive)"]
    assert inactive["enabled"] is False
    assert inactive["settings"] == [{"key": "oldThing", "value": "1", "value_class": INT}]

    alpha = profiles["Settings for ALPHA"]
    assert alpha["target_everyone"] is False
    assert alpha["targets"] == [{"kind": "device", "value": "ANDROID-1"}]
    assert alpha["apply_on_enrollment"] is False and alpha["apply_on_connection"] is True
    assert alpha["settings"] == [{"key": "locationCallsign", "value": "A1", "value_class": STR}]

    two = profiles["Settings for ANDROID-2"]
    assert two["settings"] == [
        {"key": "mapScale", "value": "5", "value_class": INT},
        {"key": "nullValue", "value": "", "value_class": STR},
    ]
    assert two["apply_on_enrollment"] is True  # one row enrolls, the NULL one doesn't


def test_migration_mapping_only_junk_and_name_clash():
    build = _migration().build_profiles
    assert build([_row(1, "", eud_uid="X")], {}) == []
    # A device whose callsign is literally "Default settings"-like can't collide on name
    profiles = build(
        [_row(1, "a", eud_uid="U1"), _row(2, "b", eud_uid="U2")], {"U1": "SAME", "U2": "SAME"}
    )
    assert sorted(p["name"] for p in profiles) == ["Settings for SAME", "Settings for SAME (2)"]


@pytest.mark.parametrize("map_sources", [False, True])
def test_enrollment_sends_packages_and_settings_with_map_sources_on_or_off(admin, app, map_sources):
    from raven.models.DataPackage import DataPackage

    app.config["RAVEN_PROFILE_MAP_SOURCES"] = map_sources
    create(admin, name="Everyone", settings=[{"key": "locationTeam", "value": "Cyan", "value_class": STR}])
    with app.app_context():
        dp = DataPackage()
        dp.filename = "welcome.zip"
        dp.hash = "abc123"
        dp.submission_time = datetime.datetime(2026, 1, 1)
        dp.mime_type = "application/zip"
        dp.size = 3
        dp.install_on_enrollment = True
        db.session.add(dp)
        db.session.commit()
    with open(os.path.join(app.config["UPLOAD_FOLDER"], "abc123.zip"), "wb") as f:
        f.write(b"zip")

    r = app.test_client().get("/Marti/api/tls/profile/enrollment", headers=basic("bob", "goodpass"))
    assert pref_entries(r)["locationTeam"] == ("Cyan", STR)
    with zipfile.ZipFile(io.BytesIO(r.data)) as z:
        names = z.namelist()
    assert "5c2bfcae3d98c9f4d262172df99ebac5/welcome.zip" in names
    assert any(n.startswith("maps/") for n in names) is map_sources


# --- files in profiles ---


def upload(admin, profile_id, files, folder=None):
    """files: [(name, bytes)]"""
    data = {"file": [(io.BytesIO(body), name) for name, body in files]}
    if folder is not None:
        data["folder"] = folder
    return admin.post(
        f"/api/device-profiles/{profile_id}/files", data=data, content_type="multipart/form-data"
    )


def zip_manifest(response):
    """(zip names, manifest Content zipEntry list, manifest Configuration parameters)"""
    assert response.status_code == 200, response.data
    with zipfile.ZipFile(io.BytesIO(response.data)) as z:
        names = z.namelist()
        root = ElementTree.fromstring(z.read("MANIFEST/manifest.xml"))
        bodies = {n: z.read(n) for n in names}
    entries = [c.get("zipEntry") for c in root.iter("Content")]
    params = {p.get("name"): p.get("value") for p in root.find("Configuration").iter("Parameter")}
    return names, entries, params, bodies


def test_group_targeted_profile_reaches_group_member_only(admin, app):
    profile = create(
        admin,
        name="Team kit",
        target_everyone=False,
        targets=[{"kind": "group", "value": "team"}],
        settings=[{"key": "locationTeam", "value": "Green", "value_class": STR}],
    )
    assert upload(admin, profile["id"], [("team.pref", b"<preferences/>")]).status_code == 200
    client = app.test_client()

    # alice is in "team"
    r = client.get("/Marti/api/tls/profile/enrollment", headers=basic("alice", "goodpass"))
    assert pref_entries(r)["locationTeam"] == ("Green", STR)
    names, entries, _, _ = zip_manifest(r)
    assert "team.pref" in names and "team.pref" in entries

    # bob isn't
    r = client.get("/Marti/api/tls/profile/enrollment", headers=basic("bob", "goodpass"))
    assert "locationTeam" not in pref_entries(r)
    names, entries, _, _ = zip_manifest(r)
    assert "team.pref" not in names and "team.pref" not in entries


def test_files_in_zip_with_manifest_and_precedence(admin, app, monkeypatch):
    everyone = create(admin, name="Everyone")
    alice = create(
        admin,
        name="Alice",
        target_everyone=False,
        targets=[{"kind": "user", "value": "alice"}],
        settings=[{"key": "locationTeam", "value": "Red", "value_class": STR}],
    )
    r = upload(admin, everyone["id"], [("basemap.xml", b"everyone"), ("ca.p12", b"\x00\x01")], folder="maps")
    assert r.status_code == 200, r.json
    assert [f["zip_path"] for f in r.json["files"]] == ["maps/basemap.xml", "maps/ca.p12"]
    assert upload(admin, alice["id"], [("basemap.xml", b"alice")], folder="maps").status_code == 200
    # Unsafe names are cleaned, not trusted
    r = upload(admin, everyone["id"], [("../../etc/passwd.pref", b"x")], folder="a/b")
    assert r.json["files"][0]["zip_path"] == "a/b/passwd.pref"

    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("alice"))
    r = app.test_client().get("/Marti/api/device/profile/connection?syncSecago=-1")
    names, entries, params, bodies = zip_manifest(r)
    assert params["onReceiveDelete"] == "true" and params["uid"]
    # Settings still go in the .pref file, listed in the manifest
    assert "5c2bfcae3d98c9f4d262172df99ebac5/preference.pref" in entries
    assert pref_entries(r)["locationTeam"] == ("Red", STR)
    for path in ("maps/basemap.xml", "maps/ca.p12", "a/b/passwd.pref"):
        assert path in names and path in entries
    # Same zip path: the user-targeted profile beats everyone
    assert bodies["maps/basemap.xml"] == b"alice"
    assert len(names) == len(set(names))

    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("bob"))
    _, _, _, bodies = zip_manifest(app.test_client().get("/Marti/api/device/profile/connection"))
    assert bodies["maps/basemap.xml"] == b"everyone"


def test_file_validation_replace_remove_and_audit(admin, app):
    profile = create(admin, name="Files")
    pid = profile["id"]
    folder = os.path.join(app.config["RAVEN_DATA_FOLDER"], "device_profile_files")

    assert upload(admin, pid, [("a.pref", b"")]).status_code == 400  # empty
    assert upload(admin, pid, [("x.pref", b"x")], folder="MANIFEST").status_code == 400
    assert upload(admin, pid, [("x.pref", b"x")], folder="5c2bfcae3d98c9f4d262172df99ebac5").status_code == 400
    assert upload(admin, pid, [("x.pref", b"x")], folder="a/../b").status_code == 400
    assert upload(admin, pid, [("...", b"x")]).status_code == 400
    assert upload(admin, 9999, [("a.pref", b"x")]).status_code == 404
    assert admin.post(f"/api/device-profiles/{pid}/files").status_code == 400

    app.config["RAVEN_DEVICE_PROFILE_MAX_FILE_MB"] = 1
    r = upload(admin, pid, [("big.bin", b"x" * (1024 * 1024 + 1))])
    assert r.status_code == 400 and "at most" in r.json["error"]
    app.config["RAVEN_DEVICE_PROFILE_MAX_FILES"] = 1
    assert upload(admin, pid, [("one.pref", b"1")]).status_code == 200
    assert upload(admin, pid, [("two.pref", b"2")]).status_code == 400
    # Nothing left behind by the rejected uploads
    assert len(os.listdir(folder)) == 1

    # Same path replaces (doesn't count against the limit) and drops the old bytes
    r = upload(admin, pid, [("one.pref", b"new")])
    assert r.status_code == 200
    files = r.json["profile"]["files"]
    assert len(files) == 1 and files[0]["size"] == 3
    assert len(os.listdir(folder)) == 1

    fid = files[0]["id"]
    d = admin.get(f"/api/device-profiles/{pid}/files/{fid}")
    assert d.status_code == 200 and d.data == b"new"
    assert admin.get(f"/api/device-profiles/9999/files/{fid}").status_code == 404

    # Duplicating copies the bytes, so removing from one leaves the other intact
    copy = admin.post(f"/api/device-profiles/{pid}/duplicate").json["profile"]
    assert [f["zip_path"] for f in copy["files"]] == ["one.pref"]
    assert len(os.listdir(folder)) == 2

    r = admin.delete(f"/api/device-profiles/{pid}/files/{fid}")
    assert r.status_code == 200 and r.json["profile"]["files"] == []
    assert len(os.listdir(folder)) == 1
    assert admin.get(f"/api/device-profiles/{copy['id']}/files/{copy['files'][0]['id']}").data == b"new"

    # Deleting a profile removes its files from disk
    admin.delete(f"/api/device-profiles/{copy['id']}")
    assert os.listdir(folder) == []

    actions = [a for a, _ in audit_actions(app)]
    assert actions.count("profile_file_added") == 2
    assert actions.count("profile_file_removed") == 1
    assert all(actor == "admin" for _, actor in audit_actions(app))

    # Non-admins can't upload
    r = upload(_login(app, "alice"), pid, [("a.pref", b"x")])
    assert r.status_code in (401, 403)


def test_profile_file_overrides_builtin_map_source(admin, app):
    app.config["RAVEN_PROFILE_MAP_SOURCES"] = True
    builtin = sorted(
        os.listdir(os.path.join(os.path.dirname(device_profiles.__file__), "maps"))
    )[0]
    profile = create(admin, name="Maps")
    upload(admin, profile["id"], [(builtin, b"mine")], folder="maps")
    r = app.test_client().get("/Marti/api/tls/profile/enrollment", headers=basic("bob", "goodpass"))
    names, entries, _, bodies = zip_manifest(r)
    assert names.count(f"maps/{builtin}") == 1 and entries.count(f"maps/{builtin}") == 1
    assert bodies[f"maps/{builtin}"] == b"mine"


# --- tool profiles ---


def test_tool_profile_endpoint(admin, app, monkeypatch):
    url = "/Marti/api/device/profile/tool/mission"
    client = app.test_client()
    assert client.get(url).status_code == 401

    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("alice"))
    # Nothing for the tool yet
    assert client.get(url).status_code == 204

    # Bad tool names are rejected on save
    r = admin.post("/api/device-profiles", json=profile_input(name="Bad", tool="mis sion"))
    assert r.status_code == 400

    team = create(
        admin,
        name="Mission tool",
        tool="Mission",
        target_everyone=False,
        targets=[{"kind": "group", "value": "team"}],
        settings=[{"key": "missionSetting", "value": "on", "value_class": STR}],
    )
    assert team["tool"] == "Mission"
    upload(admin, team["id"], [("mission.pref", b"<preferences/>")])
    create(admin, name="Other tool", tool="other", settings=[{"key": "otherSetting", "value": "1", "value_class": STR}])

    # Tool profiles never ride along on enrollment/connection
    entries = pref_entries(client.get("/Marti/api/device/profile/connection"))
    assert "missionSetting" not in entries and "otherSetting" not in entries
    names, _, _, _ = zip_manifest(client.get("/Marti/api/device/profile/connection"))
    assert "mission.pref" not in names

    # alice (in team) gets it; the tool name matches case-insensitively
    r = client.get("/Marti/api/device/profile/tool/MISSION?clientUid=ANDROID-alice")
    names, entries_list, params, _ = zip_manifest(r)
    assert params["name"] == "Device Profile (MISSION)"
    assert "mission.pref" in names and "mission.pref" in entries_list
    entries = pref_entries(r)
    assert entries == {"missionSetting": ("on", STR)}  # only the tool's own settings

    # bob isn't in team: nothing applies
    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("bob"))
    assert client.get(url).status_code == 204
    assert pref_entries(client.get("/Marti/api/device/profile/tool/other")) == {"otherSetting": ("1", STR)}

    # syncSecago: unchanged since the last sync -> 204
    with app.app_context():
        p = db.session.query(DeviceProfileSet).filter_by(name="Other tool").one()
        p.updated_at = datetime.datetime(2020, 1, 1)
        db.session.commit()
    assert client.get("/Marti/api/device/profile/tool/other?syncSecago=3600").status_code == 204
    assert client.get("/Marti/api/device/profile/tool/other?syncSecago=-1").status_code == 200

    # Disabled -> 204
    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("alice"))
    body = profile_input(
        name="Mission tool",
        tool="Mission",
        enabled=False,
        target_everyone=False,
        targets=[{"kind": "group", "value": "team"}],
    )
    assert admin.put(f"/api/device-profiles/{team['id']}", json=body).status_code == 200
    assert client.get(url).status_code == 204

    # Clearing the tool name makes it an ordinary profile again
    body.update(enabled=True, tool="", apply_on_connection=True)
    r = admin.put(f"/api/device-profiles/{team['id']}", json=body)
    assert r.json["profile"]["tool"] is None
    assert "locationTeam" in pref_entries(client.get("/Marti/api/device/profile/connection"))
    assert client.get(url).status_code == 204

    # Audit records the tool
    with app.app_context():
        details = [e.details for e in db.session.query(AuditEvent).filter_by(action="profile_created")]
    assert any("tool Mission" in d for d in details)


# --- review fixes ---


def _team_package(app, filename="team-only.zip", file_hash="teamhash"):
    from raven.models.DataPackage import DataPackage

    with app.app_context():
        dp = DataPackage()
        dp.filename = filename
        dp.hash = file_hash
        dp.submission_time = datetime.datetime(2026, 1, 1)
        dp.mime_type = "application/zip"
        dp.size = 3
        dp.install_on_connection = True
        dp.groups = [db.session.query(Group).filter_by(name="team").one()]
        db.session.add(dp)
        db.session.commit()
    with open(os.path.join(app.config["UPLOAD_FOLDER"], f"{file_hash}.zip"), "wb") as f:
        f.write(b"zip")
    return f"5c2bfcae3d98c9f4d262172df99ebac5/{filename}"


def test_unauthenticated_connection_profile_gets_no_group_packages(app, monkeypatch):
    """With RAVEN_CONNECTION_PROFILE_REQUIRE_AUTH off the claimed clientUid's account is only
    used for settings: group-restricted data packages are filtered as for anyone."""
    entry = _team_package(app)
    url = "/Marti/api/device/profile/connection?clientUid=ANDROID-alice&syncSecago=-1"
    client = app.test_client()

    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("alice"))
    names, _, _, _ = zip_manifest(client.get(url))
    assert entry in names

    monkeypatch.setattr(marti, "verify_client_cert", lambda: False)
    app.config["RAVEN_CONNECTION_PROFILE_REQUIRE_AUTH"] = False
    names, entries, _, _ = zip_manifest(client.get(url))
    assert entry not in names and entry not in entries


def test_profile_zip_is_spooled_not_held_in_memory(app, monkeypatch):
    import tempfile

    monkeypatch.setattr(marti, "ZIP_SPOOL_BYTES", 1024)
    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("alice"))
    built = []
    real = marti._zip_spool

    def spool():
        built.append(real())
        return built[-1]

    monkeypatch.setattr(marti, "_zip_spool", spool)
    response = app.test_client().get("/Marti/api/device/profile/connection?syncSecago=-1")
    zip_manifest(response)
    assert isinstance(built[0], tempfile.SpooledTemporaryFile)
    response.close()
    assert built[0].closed


def test_merged_profile_files_are_capped_per_response(admin, app, monkeypatch):
    first = create(admin, name="First")
    second = create(admin, name="Second")
    assert upload(admin, first["id"], [("a.bin", b"x" * 600)]).status_code == 200
    assert upload(admin, second["id"], [("b.bin", b"y" * 600)]).status_code == 200
    # Each profile is within the limit on its own; together they're over it
    monkeypatch.setattr(
        marti,
        "file_limits",
        lambda: {"max_file_bytes": 1000, "max_total_bytes": 1000, "max_files": 50},
    )
    monkeypatch.setattr(marti, "verify_client_cert", lambda: _FakeCert("alice"))
    names, entries, _, _ = zip_manifest(
        app.test_client().get("/Marti/api/device/profile/connection?syncSecago=-1")
    )
    assert ("a.bin" in names) != ("b.bin" in names)
    assert ("a.bin" in entries) != ("b.bin" in entries)


def test_same_path_twice_in_one_upload_reports_only_the_kept_file(admin, app):
    profile = create(admin, name="Dupes")
    r = upload(admin, profile["id"], [("x.pref", b"first"), ("x.pref", b"second")])
    assert r.status_code == 200, r.json
    assert [f["zip_path"] for f in r.json["files"]] == ["x.pref"]
    assert r.json["files"][0]["id"] is not None
    assert len(r.json["profile"]["files"]) == 1
    fid = r.json["files"][0]["id"]
    assert admin.get(f"/api/device-profiles/{profile['id']}/files/{fid}").data == b"second"
    # Only the kept file is left on disk
    with app.app_context():
        folder = device_profiles.files_folder()
    assert len(os.listdir(folder)) == 1
