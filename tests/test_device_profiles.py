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
