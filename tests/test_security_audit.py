"""
Tests for the security audit trail (raven/audit.py, raven/models/AuditEvent.py) and the admin
Security Audit API (raven/blueprints/raven_api/security_audit_api.py).

Same minimal sqlite Flask app approach as tests/test_cert_issuance_authz.py: only the blueprints
under test, no RabbitMQ / Postgres / scheduler.
"""

import base64
import datetime
import time

import pytest
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.audit import client_ip, init_audit, record_audit_event
from raven.blueprints.marti_api.certificate_enrollment_api import (
    certificate_authority_api_blueprint,
)
from raven.blueprints.raven_api.security_audit_api import security_audit_api_blueprint
from raven.blueprints.raven_api.user_api import user_api_blueprint
from raven.defaultconfig import DefaultConfig
from raven.extensions import babel
from raven.models.AuditEvent import AuditEvent
from tests.test_cert_issuance_authz import ca_template  # noqa: F401  (session CA fixture)


@pytest.fixture
def app(tmp_path):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_CA_FOLDER=str(tmp_path / "ca"),
        RAVEN_ENABLE_LDAP=False,
        RAVEN_TURNSTILE_ENABLE=False,
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS=True,
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
    app.register_blueprint(security_audit_api_blueprint)
    app.register_blueprint(user_api_blueprint)
    app.register_blueprint(certificate_authority_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        # Still on the install-time default password, no 2FA
        ds.create_user(
            username="admin", password=hash_password("password"), roles=["administrator"]
        )
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
        ds.create_user(username="bob", password=hash_password("bobpass"), roles=["user"])
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _login_session(app, client, username):
    """Logs in by session, without going through /api/login (no audit event)."""
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username=username).fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()


def _events(app, **filters):
    with app.app_context():
        return [
            e.to_json()
            for e in db.session.query(AuditEvent).filter_by(**filters).order_by(AuditEvent.id).all()
        ]


# --- record_audit_event ---


def test_record_audit_event_writes_row(app):
    with app.app_context():
        assert record_audit_event(
            "auth", "web_login", username="alice", details="hi", ip="10.0.0.1"
        )
    events = _events(app)
    assert len(events) == 1
    assert events[0]["action"] == "web_login"
    assert events[0]["ip"] == "10.0.0.1"
    assert events[0]["success"] is True
    assert events[0]["timestamp"].endswith("Z")


def test_record_audit_event_never_raises_without_app_context():
    assert record_audit_event("auth", "web_login", username="alice") is False


def test_record_audit_event_never_raises_when_table_missing(app):
    with app.app_context():
        AuditEvent.__table__.drop(db.engine)
        assert record_audit_event("auth", "web_login", username="alice") is False


def test_record_audit_event_failure_does_not_break_callers_session(app):
    with app.app_context():
        user = app.security.datastore.find_user(username="bob")
        user.email = "bob@example.com"
        db.session.add(user)
        # category is NOT NULL: the insert fails on its own connection
        assert record_audit_event(None, "broken") is False
        db.session.commit()
        assert app.security.datastore.find_user(username="bob").email == "bob@example.com"


def test_record_audit_event_drops_actor_equal_to_username_and_truncates(app):
    with app.app_context():
        record_audit_event(
            "auth", "x" * 200, username="alice", actor="ALICE", user_agent="u" * 2000
        )
    event = _events(app)[0]
    assert event["actor"] is None
    assert len(event["action"]) == 64
    assert len(event["user_agent"]) == 512


def test_client_ip_respects_proxy_headers(app):
    with app.test_request_context("/", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}):
        assert client_ip() == "203.0.113.9"
    with app.test_request_context("/", headers={"X-Real-IP": "198.51.100.4"}):
        assert client_ip() == "198.51.100.4"
    # A non-local peer is not overridden by headers it supplied itself
    with app.test_request_context(
        "/", headers={"X-Real-IP": "1.2.3.4"}, environ_base={"REMOTE_ADDR": "192.0.2.50"}
    ):
        assert client_ip() == "192.0.2.50"


# --- login hooks ---


def test_login_success_and_logout_produce_events(app):
    client = app.test_client()
    r = client.post(
        "/api/login",
        json={"username": "alice", "password": "alicepass"},
        headers={"X-Forwarded-For": "203.0.113.7", "User-Agent": "pytest-browser"},
    )
    assert r.status_code == 200, r.get_data(as_text=True)

    logins = _events(app, action="web_login")
    assert len(logins) == 1
    assert logins[0]["username"] == "alice"
    assert logins[0]["ip"] == "203.0.113.7"
    assert logins[0]["user_agent"] == "pytest-browser"
    assert logins[0]["success"] is True
    assert logins[0]["category"] == "auth"

    client.post("/api/logout")
    logouts = _events(app, action="logout")
    assert len(logouts) == 1
    assert logouts[0]["username"] == "alice"


def test_login_failure_produces_event(app):
    client = app.test_client()
    r = client.post(
        "/api/login",
        json={"username": "alice", "password": "wrong"},
        headers={"X-Real-IP": "198.51.100.20"},
    )
    assert r.status_code == 400

    failed = _events(app, action="web_login_failed")
    assert len(failed) == 1
    assert failed[0]["username"] == "alice"
    assert failed[0]["ip"] == "198.51.100.20"
    assert failed[0]["success"] is False
    # The attempted password is never recorded
    assert "wrong" not in (failed[0]["details"] or "")
    assert not _events(app, action="web_login")


def test_failed_enrollment_produces_event(app):
    client = app.test_client()
    auth = "Basic " + base64.b64encode(b"bob:nope").decode()
    r = client.post(
        "/Marti/api/tls/signClient/v2?clientUid=ANDROID-123",
        data="csr",
        headers={"Authorization": auth},
    )
    assert r.status_code == 401
    failed = _events(app, action="enroll_failed")
    assert len(failed) == 1
    assert failed[0]["username"] == "bob"
    assert failed[0]["category"] == "enrollment"
    assert "ANDROID-123" in failed[0]["details"]


def test_user_admin_actions_produce_events(app):
    client = app.test_client()
    _login_session(app, client, "admin")

    r = client.post("/api/user/role", json={"username": "bob", "roles": ["administrator"]})
    assert r.status_code == 200, r.get_data(as_text=True)
    r = client.post(
        "/api/user/password/reset", json={"username": "alice", "new_password": "newpass123"}
    )
    assert r.status_code == 200, r.get_data(as_text=True)

    role = _events(app, action="role_changed")
    assert len(role) == 1
    assert role[0]["username"] == "bob" and role[0]["actor"] == "admin"
    assert "administrator" in role[0]["details"]

    reset = _events(app, action="password_reset_by_admin")
    assert len(reset) == 1
    assert reset[0]["username"] == "alice" and reset[0]["actor"] == "admin"
    assert not _events(app, action="password_change")


# --- audit API ---


def _seed_bruteforce(app):
    with app.app_context():
        for _ in range(6):
            record_audit_event(
                "auth", "web_login_failed", username="admin", success=False, ip="192.0.2.66"
            )
        record_audit_event("enrollment", "enroll_qr", username="alice", ip="10.1.1.1")
        record_audit_event("enrollment", "enroll_zip", username="bob", ip="10.1.1.2")


def test_audit_json_shape(app):
    _seed_bruteforce(app)
    client = app.test_client()
    _login_session(app, client, "admin")

    r = client.get("/api/security/audit?days=30")
    assert r.status_code == 200, r.get_data(as_text=True)
    data = r.get_json()

    assert set(data) == {"generated_at", "days", "summary", "findings", "users", "events"}
    assert data["days"] == 30
    assert set(data["summary"]) == {
        "web_logins",
        "failed_logins",
        "qr_enrollments",
        "zip_enrollments",
        "credential_enrollments",
        "active_users",
        "certificates_revoked",
        "findings",
    }
    assert all(isinstance(v, int) for v in data["summary"].values())
    assert data["summary"]["failed_logins"] == 6
    assert data["summary"]["qr_enrollments"] == 1
    assert data["summary"]["zip_enrollments"] == 1
    assert data["summary"]["findings"] == len(data["findings"])

    for finding in data["findings"]:
        assert set(finding) == {"severity", "title", "detail"}
        assert finding["severity"] in ("high", "medium", "low", "info")
    titles = " | ".join(f["title"] for f in data["findings"])
    assert "without two-factor" in titles
    assert "default password" in titles
    assert "Repeated failed logins from 1 IP" in titles
    # high before medium/low/info
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    severities = [order[f["severity"]] for f in data["findings"]]
    assert severities == sorted(severities)

    users = {u["username"]: u for u in data["users"]}
    assert set(users) == {"admin", "alice", "bob"}
    assert set(users["alice"]) == {
        "username",
        "roles",
        "active",
        "site_access",
        "last_login_at",
        "last_login_ip",
        "current_login_at",
        "current_login_ip",
        "login_count",
        "tfa_enabled",
        "passkeys",
        "certificates",
        "devices",
        "enrollment_methods",
    }
    assert users["admin"]["roles"] == ["administrator"]
    assert users["alice"]["enrollment_methods"] == ["qr"]
    assert users["bob"]["enrollment_methods"] == ["zip"]
    assert users["alice"]["tfa_enabled"] is False
    assert users["alice"]["passkeys"] == 0

    events = data["events"]
    assert len(events) == 8
    assert set(events[0]) == {
        "id",
        "timestamp",
        "category",
        "action",
        "username",
        "actor",
        "ip",
        "user_agent",
        "success",
        "details",
    }
    # newest first
    assert [e["id"] for e in events] == sorted((e["id"] for e in events), reverse=True)


def test_audit_filters(app):
    _seed_bruteforce(app)
    client = app.test_client()
    _login_session(app, client, "admin")

    data = client.get("/api/security/audit?category=enrollment").get_json()
    assert {e["action"] for e in data["events"]} == {"enroll_qr", "enroll_zip"}

    data = client.get("/api/security/audit?search=192.0.2.66&limit=2").get_json()
    assert len(data["events"]) == 2
    assert all(e["ip"] == "192.0.2.66" for e in data["events"])

    # Old events fall outside the window
    with app.app_context():
        old = db.session.query(AuditEvent).filter_by(action="enroll_qr").one()
        old.timestamp = datetime.datetime.now(datetime.timezone.utc).replace(
            tzinfo=None
        ) - datetime.timedelta(days=10)
        db.session.commit()
    data = client.get("/api/security/audit?days=7").get_json()
    assert data["summary"]["qr_enrollments"] == 0
    assert "enroll_qr" not in {e["action"] for e in data["events"]}


def test_audit_download(app):
    _seed_bruteforce(app)
    client = app.test_client()
    _login_session(app, client, "admin")

    r = client.get("/api/security/audit/download?days=30")
    assert r.status_code == 200
    assert r.mimetype == "text/plain"
    disposition = r.headers["Content-Disposition"]
    assert disposition.startswith("attachment;")
    assert 'filename="security-audit-' in disposition and disposition.endswith('.txt"')
    body = r.get_data(as_text=True)
    for section in ("SUMMARY", "FINDINGS", "USERS", "EVENT LOG"):
        assert section in body
    assert "192.0.2.66" in body
    assert "web_login_failed" in body


def test_non_admin_forbidden(app):
    client = app.test_client()
    _login_session(app, client, "alice")
    assert client.get("/api/security/audit").status_code == 403
    assert client.get("/api/security/audit/download").status_code == 403


def test_anonymous_rejected(app):
    client = app.test_client()
    assert client.get("/api/security/audit").status_code in (401, 403)


# --- enrollment method: QR token vs username/password (needs the openssl CLI) ---


@pytest.fixture
def enroll_app(app, tmp_path, monkeypatch, request):
    import shutil

    if not shutil.which("openssl"):
        pytest.skip("needs the openssl CLI")
    from cryptography.hazmat.primitives import serialization

    from tests.test_cert_issuance_authz import CA_PASSWORD

    ca_template = request.getfixturevalue("ca_template")
    monkeypatch.chdir(tmp_path)
    ca = tmp_path / "enroll-ca"
    shutil.copytree(ca_template, ca)
    key = serialization.load_pem_private_key(
        (ca / "certs" / "raven" / "raven.nopass.key").read_bytes(), password=None
    )
    (ca / "certs" / "raven" / "raven.pub").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    app.config.update(
        RAVEN_CA_FOLDER=str(ca),
        RAVEN_CA_PASSWORD=CA_PASSWORD,
        RAVEN_CA_EXPIRATION_TIME=30,
        RAVEN_MARTI_HTTPS_PORT=8443,
    )
    return app


def test_enrollment_distinguishes_qr_token_from_credentials(enroll_app):
    from raven.models.Token import Token
    from tests.test_cert_issuance_authz import _basic, _csr_body

    app = enroll_app
    with app.app_context():
        token = Token(username="alice", creation=int(time.time()), max_uses=5)
        token.hash_token()
        db.session.add(token)
        db.session.commit()
        jwt_token = token.generate_token()

    def sign(password, uid):
        body, _ = _csr_body(["alice"])
        return app.test_client().post(
            "/Marti/api/tls/signClient/v2",
            query_string={"clientUid": uid},
            data=body,
            headers={"Authorization": _basic("alice", password), "Accept": "application/json"},
        )

    assert sign("alicepass", "ANDROID-pw").status_code == 200
    assert sign(jwt_token, "ANDROID-qr").status_code == 200

    creds = _events(app, action="enroll_credentials")
    qr = _events(app, action="enroll_qr")
    assert len(creds) == 1 and "ANDROID-pw" in creds[0]["details"]
    assert len(qr) == 1 and "ANDROID-qr" in qr[0]["details"]
    assert creds[0]["username"] == qr[0]["username"] == "alice"

    client = app.test_client()
    _login_session(app, client, "admin")
    data = client.get("/api/security/audit").get_json()
    alice = next(u for u in data["users"] if u["username"] == "alice")
    assert alice["enrollment_methods"] == ["credentials", "qr"]
    assert alice["certificates"] == 2
    assert {d["uid"] for d in alice["devices"]} == {"ANDROID-pw", "ANDROID-qr"}
    assert data["summary"]["qr_enrollments"] == 1
    assert data["summary"]["credential_enrollments"] == 1
