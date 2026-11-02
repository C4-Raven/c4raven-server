"""Admin action audit log: the central after_request hook in raven/audit.py that records every
state-changing web API request as an "admin" event, and the events API / downloads in
raven/blueprints/raven_api/security_audit_api.py.

Minimal sqlite Flask app, as in tests/test_group_policies.py: no RabbitMQ, Postgres or scheduler.
"""

import csv
import datetime
import io
import time

import pytest
from flask import Flask, jsonify
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.audit import (  # noqa: E402
    ADMIN_ACTION_LABELS,
    init_audit,
    is_sensitive_key,
    record_audit_event,
)
from raven.blueprints.raven_api.group_api import group_api  # noqa: E402
from raven.blueprints.raven_api.security_audit_api import (  # noqa: E402
    security_audit_api_blueprint,
)
from raven.blueprints.raven_api.user_api import user_api_blueprint  # noqa: E402
from raven.models.AuditEvent import AuditEvent  # noqa: E402

SECRET = "hunter2-very-secret"


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
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    init_audit(app)
    app.register_blueprint(group_api)
    app.register_blueprint(user_api_blueprint)
    app.register_blueprint(security_audit_api_blueprint)

    # Stand-ins for endpoints that aren't worth spinning up here
    @app.route("/api/test/echo/<thing_id>", methods=["POST", "DELETE"])
    def echo(thing_id):
        return jsonify({"success": True})

    @app.route("/api/test/soft_fail", methods=["POST"])
    def soft_fail():
        return jsonify({"success": False, "error": "Nope"})

    @app.route("/api/test/csrf", methods=["POST"])
    def csrf_rejected():
        from flask_wtf.csrf import CSRFError

        raise CSRFError("The CSRF token is missing.")

    @app.route("/api/language/<lang_code>", methods=["PUT"])
    def set_language(lang_code):
        return jsonify({"success": True})

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("x"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("x"), roles=["user"])
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _client(app, username):
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
    return _client(app, "admin")


def admin_rows(app):
    with app.app_context():
        return [
            e.to_json()
            for e in db.session.query(AuditEvent)
            .filter_by(category="admin")
            .order_by(AuditEvent.id)
            .all()
        ]


def test_group_create_records_admin_row_with_secrets_redacted(app, admin):
    r = admin.post(
        "/api/groups",
        json={
            "name": "Ops",
            "description": "Operations",
            "password": SECRET,
            "api_token": SECRET,
            "privateKey": SECRET,
            "cert_pem": "-----BEGIN CERTIFICATE-----abc",
            "stream_url": f"rtsp://cam:{SECRET}@10.0.0.5/live",
            "settings": {"anything": SECRET},
        },
        headers={"User-Agent": "pytest-agent"},
    )
    assert r.status_code == 200, r.json

    rows = admin_rows(app)
    assert len(rows) == 1
    row = rows[0]
    assert row["action"] == "add_group"
    assert row["actor"] == "admin"
    assert row["success"] is True
    assert row["summary"] == "Created group: Ops"
    assert row["user_agent"] == "pytest-agent"
    details = row["details"]
    assert details.startswith("POST /api/groups · HTTP 200")
    assert "name=Ops" in details and "description=Operations" in details
    assert "password=[redacted]" in details
    assert "api_token=[redacted]" in details
    assert "privateKey=[redacted]" in details
    assert "cert_pem=[redacted]" in details
    assert "stream_url=rtsp://***@10.0.0.5/live" in details
    assert "settings={1 fields}" in details
    # group_api records its own group_created event; the admin row points to it
    assert "Also logged: groups/group_created" in details
    with app.app_context():
        assert db.session.query(AuditEvent).filter_by(action="group_created").count() == 1
        for event in db.session.query(AuditEvent).all():
            assert SECRET not in (event.details or "")
            assert SECRET not in (event.summary or "")


def test_gets_are_not_recorded(app, admin):
    admin.post("/api/groups", json={"name": "Ops"})
    before = len(admin_rows(app))
    assert admin.get("/api/groups").status_code == 200
    assert admin.get("/api/groups/members", query_string={"name": "Ops"}).status_code == 200
    assert admin.get("/api/security/audit/events").status_code == 200
    assert len(admin_rows(app)) == before


def test_failure_status_recorded_as_unsuccessful(app, admin):
    # Duplicate group: 400
    admin.post("/api/groups", json={"name": "Ops"})
    r = admin.post("/api/groups", json={"name": "Ops"})
    assert r.status_code == 400
    row = admin_rows(app)[-1]
    assert row["action"] == "add_group"
    assert row["success"] is False
    assert "HTTP 400" in row["details"]
    assert "already exists" in row["details"]

    # 200 with {"success": false} is a failure too
    admin.post("/api/test/soft_fail")
    row = admin_rows(app)[-1]
    assert row["success"] is False
    assert "Error: Nope" in row["details"]


def test_non_admin_forbidden_attempt_is_recorded(app):
    alice = _client(app, "alice")
    r = alice.post("/api/groups", json={"name": "Sneaky"})
    assert r.status_code == 403
    row = admin_rows(app)[-1]
    assert row["actor"] == "alice" or row["username"] == "alice"
    assert row["success"] is False
    assert "HTTP 403" in row["details"]


def test_anonymous_and_skipped_endpoints_not_recorded(app, admin):
    anon = app.test_client()
    assert anon.post("/api/groups", json={"name": "x"}).status_code in (401, 403)
    assert admin.put("/api/language/de").status_code == 200
    assert admin.post("/api/test/csrf").status_code == 400
    assert admin_rows(app) == [], admin_rows(app)


def test_view_args_and_query_targets(app, admin):
    admin.delete("/api/test/echo/42?force=true&token=abc")
    row = admin_rows(app)[-1]
    assert row["action"] == "echo"
    assert row["summary"] == "DELETE /api/test/echo/42"
    assert "thing_id=42" in row["details"] and "force=true" in row["details"]
    assert "token=[redacted]" in row["details"] and "abc" not in row["details"]


def test_target_username_and_user_admin_events(app, admin):
    r = admin.post("/api/user/role", json={"username": "alice", "roles": ["administrator"]})
    assert r.status_code == 200, r.json
    row = admin_rows(app)[-1]
    assert row["action"] == "set_user_role"
    assert row["username"] == "alice" and row["actor"] == "admin"
    assert row["summary"] == "Changed user role: alice"
    assert "roles=[administrator]" in row["details"]


def test_sensitive_key_names():
    for key in (
        "password",
        "new_password",
        "confirmPassword",
        "token",
        "access_token",
        "client_secret",
        "private_key",
        "apiKey",
        "key",
        "code",
        "psk",
        "csr",
        "passphrase",
    ):
        assert is_sensitive_key(key, "x"), key
    for key in ("name", "username", "description", "group_name", "preference_key", "lang"):
        assert not is_sensitive_key(key, "x"), key
    # Certificate material is redacted, a certificate validity in days is not
    assert is_sensitive_key("certificate", "MIIB...")
    assert not is_sensitive_key("certificate_validity", 365)


def test_every_label_is_a_string_or_method_map():
    for view, label in ADMIN_ACTION_LABELS.items():
        assert isinstance(label, (str, dict)), view


# --- events API ---


def test_events_api_filters(app, admin):
    admin.post("/api/groups", json={"name": "Ops"})
    admin.post("/api/groups", json={"name": "Ops"})  # fails
    admin.post("/api/user/role", json={"username": "alice", "roles": ["user"]})
    with app.app_context():
        record_audit_event("auth", "web_login", username="admin")

    data = admin.get("/api/security/audit/events").get_json()
    assert {e["category"] for e in data["events"]} == {"admin"}
    assert data["total"] == 3
    assert "admin" in data["actors"]
    assert {"action": "add_group", "label": "Created group"} in data["actions"]

    data = admin.get("/api/security/audit/events?action=add_group").get_json()
    assert [e["action"] for e in data["events"]] == ["add_group", "add_group"]

    data = admin.get("/api/security/audit/events?success=false").get_json()
    assert len(data["events"]) == 1 and data["events"][0]["success"] is False

    data = admin.get("/api/security/audit/events?actor=nobody").get_json()
    assert data["events"] == []

    data = admin.get("/api/security/audit/events?search=Changed%20user%20role").get_json()
    assert [e["action"] for e in data["events"]] == ["set_user_role"]

    data = admin.get("/api/security/audit/events?category=auth").get_json()
    assert [e["action"] for e in data["events"]] == ["web_login"]

    # Date range
    with app.app_context():
        old = db.session.query(AuditEvent).filter_by(action="set_user_role").one()
        old.timestamp = datetime.datetime(2026, 1, 15, 12, 0)
        db.session.commit()
    data = admin.get(
        "/api/security/audit/events?start=2026-01-15&end=2026-01-15&days=3650"
    ).get_json()
    assert [e["action"] for e in data["events"]] == ["set_user_role"]
    data = admin.get(
        "/api/security/audit/events?start=2026-01-16T00:00:00Z&end=2026-01-20&days=3650"
    ).get_json()
    assert data["events"] == []


def test_security_report_hides_admin_rows_unless_asked(app, admin):
    admin.post("/api/groups", json={"name": "Ops"})
    data = admin.get("/api/security/audit").get_json()
    assert "admin" not in {e["category"] for e in data["events"]}
    assert "group_created" in {e["action"] for e in data["events"]}
    data = admin.get("/api/security/audit?category=admin").get_json()
    assert {e["category"] for e in data["events"]} == {"admin"}
    data = admin.get("/api/security/audit?actor=admin&action=group_created").get_json()
    assert [e["action"] for e in data["events"]] == ["group_created"]


def test_downloads(app, admin):
    admin.post("/api/groups", json={"name": "=cmd", "password": SECRET})

    r = admin.get("/api/security/audit/events/download")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert 'filename="admin-actions-' in r.headers["Content-Disposition"]
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))
    assert len(rows) == 1
    assert rows[0]["action"] == "add_group" and rows[0]["success"] == "true"
    assert rows[0]["summary"] == "Created group: =cmd"
    assert rows[0]["details"].startswith("POST /api/groups")
    assert SECRET not in r.get_data(as_text=True)

    r = admin.get("/api/security/audit/events/download?format=txt")
    assert r.mimetype == "text/plain"
    body = r.get_data(as_text=True)
    assert "C4 Raven Admin Actions" in body and "add_group" in body

    # The security report: TXT as before, plus CSV of its events
    r = admin.get("/api/security/audit/download")
    assert r.mimetype == "text/plain" and "EVENT LOG" in r.get_data(as_text=True)
    r = admin.get("/api/security/audit/download?format=csv")
    assert r.mimetype == "text/csv"
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))
    assert {row["action"] for row in rows} == {"group_created"}


def test_csv_neutralises_formulas(app, admin):
    with app.app_context():
        record_audit_event("admin", "x", actor="admin", summary="=HYPERLINK(1)")
    r = admin.get("/api/security/audit/events/download")
    rows = list(csv.DictReader(io.StringIO(r.get_data(as_text=True))))
    assert rows[0]["summary"] == "'=HYPERLINK(1)"


def test_non_admin_cannot_read_the_log(app):
    alice = _client(app, "alice")
    for path in (
        "/api/security/audit/events",
        "/api/security/audit/events/download",
        "/api/security/audit/download?format=csv",
    ):
        assert alice.get(path).status_code == 403, path
    anon = app.test_client()
    assert anon.get("/api/security/audit/events").status_code in (401, 403)


def test_hook_never_breaks_the_request(app, admin, monkeypatch):
    import raven.audit as audit

    def boom(*args, **kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(audit, "admin_request_fields", boom)
    r = admin.post("/api/groups", json={"name": "Ops"})
    assert r.status_code == 200
    with app.app_context():
        assert db.session.query(AuditEvent).filter_by(action="group_created").count() == 1


# --- redaction of values (review findings) ---


def _fields(path, **kwargs):
    from raven import audit

    with Flask("x").test_request_context(path, method="POST", **kwargs):
        return audit.admin_request_fields()


def test_device_profile_pair_value_redacted_when_key_names_a_secret():
    fields = _fields(
        "/api/profiles",
        data={"preference_key": "caPassword0", "preference_value": SECRET, "eud_uid": "x"},
    )
    assert fields["preference_key"] == "caPassword0"
    assert fields["preference_value"] == "[redacted]"
    for key in ("clientPassword0", "enrollmentPassword", "updateServerCaPassword"):
        fields = _fields("/api/profiles", json={"preference_key": key, "preference_value": SECRET})
        assert fields["preference_value"] == "[redacted]", key
    # An ordinary setting's value is still shown
    fields = _fields(
        "/api/profiles", json={"preference_key": "locationCallsign", "preference_value": "ALPHA"}
    )
    assert fields["preference_value"] == "ALPHA"
    # Other name/value shapes
    assert _fields("/api/x", json={"key": "apiToken", "value": SECRET})["value"] == "[redacted]"
    assert _fields("/api/x", json={"name": "ssh_key", "value": SECRET})["value"] == "[redacted]"
    assert _fields("/api/x", json={"name": "color", "value": "red"})["value"] == "red"


def test_device_profile_set_settings_are_only_counted():
    fields = _fields(
        "/api/device-profiles",
        json={
            "name": "Ops",
            "settings": [
                {"key": "clientPassword0", "value": SECRET, "value_class": "String"},
                {"key": "locationCallsign", "value": "ALPHA", "value_class": "String"},
            ],
        },
    )
    assert fields["settings"] == "[2 items]"
    assert SECRET not in repr(fields)


def test_secret_query_parameters_inside_values_are_masked():
    fields = _fields(
        "/api/mediamtx/stream/add",
        json={"path": "cam", "source": f"srt://h:8890?streamid=publish:cam&passphrase={SECRET}"},
    )
    assert fields["source"] == "srt://h:8890?streamid=publish:cam&passphrase=***"
    fields = _fields(
        "/api/mediamtx/stream/add", json={"source": f"rtsp://h/live?token={SECRET}&x=1"}
    )
    assert fields["source"] == "rtsp://h/live?token=***&x=1"
    fields = _fields("/api/x", json={"urls": [f"https://h/a?access_token={SECRET}", "plain"]})
    assert SECRET not in fields["urls"] and "plain" in fields["urls"]


def test_more_sensitive_key_names():
    for key in (
        "jwt",
        "id_jwt",
        "client_key",
        "clientKey",
        "ssh_key",
        "encryption_key",
        "hmac",
        "hmac_key",
        "passphrase",
        "srt_passphrase",
    ):
        assert is_sensitive_key(key, "x"), key
    for key in ("preference_key", "sort_key", "name", "monkey"):
        assert not is_sensitive_key(key, "x"), key
    fields = _fields(
        "/api/x?apiKey=zzz&access_token=yyy&jwt=QQQ",
        json={"clientKey": "k", "truststorePass": "t", "values": ["s1", "s2"]},
    )
    for key in ("apiKey", "access_token", "jwt", "clientKey", "truststorePass"):
        assert fields[key] == "[redacted]", key


def test_new_labels_match_real_views():
    import importlib

    views = {
        "revoke_certificate": "raven.blueprints.raven_api.certificate_api",
        "revoke_certificate_by_serial": "raven.blueprints.raven_api.certificate_api",
        "revoke_all_user_certificates": "raven.blueprints.raven_api.certificate_api",
        "edit_data_package_groups": "raven.blueprints.raven_api.data_package_api",
        "edit_video_stream_groups": "raven.blueprints.raven_api.video_api",
        "upload_profile_files": "raven.blueprints.raven_api.device_profile_api",
        "delete_profile_file": "raven.blueprints.raven_api.device_profile_api",
        "put_retention": "raven.blueprints.raven_api.retention_api",
    }
    for view, module in views.items():
        assert callable(getattr(importlib.import_module(module), view)), view
        assert isinstance(ADMIN_ACTION_LABELS[view], str), view
    assert ADMIN_ACTION_LABELS["allow_enrollment"]


def test_serial_is_a_target():
    from raven import audit

    with Flask("x").test_request_context(
        "/api/certificates/revoke", method="POST", json={"serial": "0A1B2C", "reason": "lost"}
    ):
        assert audit._admin_target(audit.admin_request_fields()) == "0A1B2C"


def test_filter_menus_group_by_action(app, admin):
    for name in ("Ops", "Blue", "Red", "Green"):
        admin.post("/api/groups", json={"name": name})
    data = admin.get("/api/security/audit/events").get_json()
    add_group = [a for a in data["actions"] if a["action"] == "add_group"]
    assert add_group == [{"action": "add_group", "label": "Created group"}]
    assert data["actors"] == ["admin"]
