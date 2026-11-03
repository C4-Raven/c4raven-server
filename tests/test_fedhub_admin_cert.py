"""
Tests for serving the Federation Hub admin cert and its import password
(/api/fedhub/admin_cert and /api/fedhub/admin_cert/password in
raven/blueprints/raven_api/federation_hub_api.py).

Builds a minimal Flask app (sqlite, only the blueprint under test) like test_error_log_api.py.
The cert and password paths come from RAVEN_FEDHUB_ADMIN_P12 /
RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE, pointed at files under tmp_path.
"""

import time

import pytest
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.blueprints.raven_api.federation_hub_api import federation_hub_api
from raven.defaultconfig import DefaultConfig

P12_BYTES = b"\x30\x82\x01\x02not-really-a-p12"


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
        # Never fall back to the real /opt/tak defaults in tests
        RAVEN_FEDHUB_ADMIN_P12=str(tmp_path / "missing.p12"),
        RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE=str(tmp_path / "missing.password"),
    )
    db.init_app(app)
    babel.init_app(app)  # the routes under test return gettext() messages

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(federation_hub_api)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.create_user(
            username="admin", password=hash_password("adminpass"), roles=["administrator"]
        )
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _login(app, client, verified=True):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username="admin").fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()
        if verified:
            session["fedhub_cert_2fa_verified_at"] = time.time()


@pytest.fixture
def admin(app):
    client = app.test_client()
    _login(app, client)
    return client


def test_defaults_match_legacy_paths():
    assert (
        DefaultConfig.RAVEN_FEDHUB_ADMIN_P12
        == "/opt/tak/federation-hub/certs/files/fedhub-admin.p12"
    )
    assert (
        DefaultConfig.RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE
        == "/opt/tak/federation-hub/certs/.fedhub-cert-passwords"
    )


def test_legacy_passwords_file(app, admin, tmp_path):
    # Federation Hub's own shell-env file, at its legacy name
    pw = tmp_path / ".fedhub-cert-passwords"
    pw.write_text("CAPASS=ca-secret\nPASS=p12-secret\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.status_code == 200
    assert r.json == {"password": "p12-secret"}


def test_legacy_format_under_another_name(app, admin, tmp_path):
    pw = tmp_path / "copied-passwords"
    pw.write_text("CAPASS=ca-secret\nPASS=p12-secret\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.status_code == 200
    assert r.json == {"password": "p12-secret"}


def test_legacy_file_without_pass_line(app, admin, tmp_path):
    pw = tmp_path / ".fedhub-cert-passwords"
    pw.write_text("CAPASS=ca-secret\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.status_code == 500
    assert r.json["error"] == "Certificate password not found"


@pytest.mark.parametrize("content", ["s3cr=et!\n", "  s3cr=et!  \n\n", "s3cr=et!"])
def test_single_line_password_file(app, admin, tmp_path, content):
    pw = tmp_path / "fedhub-admin.p12.password"
    pw.write_text(content)
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.status_code == 200
    assert r.json == {"password": "s3cr=et!"}


def test_single_line_password_that_looks_like_pass_line(app, admin, tmp_path):
    # Only one line and not the legacy file name: taken verbatim
    pw = tmp_path / "fedhub-admin.p12.password"
    pw.write_text("PASS=abc\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.json == {"password": "PASS=abc"}


def test_empty_password_file(app, admin, tmp_path):
    pw = tmp_path / "fedhub-admin.p12.password"
    pw.write_text("\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.status_code == 500
    assert r.json == {"success": False, "error": "Certificate password not found"}


def test_custom_p12_path(app, admin, tmp_path):
    p12 = tmp_path / "fedhub" / "fedhub-admin.p12"
    p12.parent.mkdir()
    p12.write_bytes(P12_BYTES)
    app.config["RAVEN_FEDHUB_ADMIN_P12"] = str(p12)
    r = admin.get("/api/fedhub/admin_cert")
    assert r.status_code == 200
    assert r.data == P12_BYTES
    assert r.headers["Content-Type"] == "application/x-pkcs12"
    assert r.headers["Content-Disposition"] == "attachment; filename=fedhub-admin.p12"


def test_config_read_at_request_time(app, admin, tmp_path):
    first = tmp_path / "a.password"
    first.write_text("first\n")
    second = tmp_path / "b.password"
    second.write_text("second\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(first)
    assert admin.get("/api/fedhub/admin_cert/password").json == {"password": "first"}
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(second)
    assert admin.get("/api/fedhub/admin_cert/password").json == {"password": "second"}


def test_missing_p12(admin):
    r = admin.get("/api/fedhub/admin_cert")
    assert r.status_code == 500
    assert r.json == {"success": False, "error": "Admin certificate not found"}


def test_missing_password_file(admin):
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.status_code == 500
    assert r.json == {"success": False, "error": "Certificate password not found"}


def test_unreadable_password_file(app, admin, tmp_path):
    # A directory stands in for a file Raven can't read (OSError), without needing chmod/root
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(tmp_path)
    r = admin.get("/api/fedhub/admin_cert/password")
    assert r.status_code == 500
    assert r.json == {"success": False, "error": "Certificate password not found"}


def test_2fa_still_required(app, tmp_path):
    pw = tmp_path / "fedhub-admin.p12.password"
    pw.write_text("secret\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    client = app.test_client()
    _login(app, client, verified=False)
    assert client.get("/api/fedhub/admin_cert/password").status_code == 403
    assert client.get("/api/fedhub/admin_cert").status_code == 403
