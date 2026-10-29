"""
Tests for the per-user certificate lifetime (User.cert_validity_days).

An admin can set how many days a user's certs are valid for on the Users page. It applies to the
next cert issued by either route: the data package from POST /api/certificate and ATAK enrollment
via POST /Marti/api/tls/signClient/v2. NULL means the server default, RAVEN_CA_EXPIRATION_TIME,
which is also the maximum.

Reuses the throwaway-CA sqlite app from tests/test_cert_issuance_authz.py (CA expiration 30 days).
"""

import datetime
import os
import shutil

import pytest
from cryptography import x509
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password

from raven.extensions import db

from tests.test_cert_issuance_authz import (  # noqa: F401 (ca_template is a fixture)
    CA_PASSWORD,
    _login,
    _sign,
    _signed_cert,
    ca_template,
)

from raven.blueprints.marti_api.certificate_enrollment_api import (
    certificate_authority_api_blueprint,
)
from raven.blueprints.raven_api.api import api_blueprint
from raven.blueprints.raven_api.data_package_api import data_package_api
from raven.blueprints.raven_api.user_api import user_api_blueprint
from raven.defaultconfig import DefaultConfig
from raven.extensions import babel

MAX_DAYS = 30  # RAVEN_CA_EXPIRATION_TIME below


@pytest.fixture
def app(tmp_path, ca_template, monkeypatch):
    # Same as the test_cert_issuance_authz app, plus the user API (certificate_validity)
    monkeypatch.chdir(tmp_path)

    ca = tmp_path / "ca"
    shutil.copytree(ca_template, ca)
    uploads = tmp_path / "uploads"
    uploads.mkdir()

    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_CA_FOLDER=str(ca),
        RAVEN_CA_PASSWORD=CA_PASSWORD,
        RAVEN_CA_EXPIRATION_TIME=MAX_DAYS,
        RAVEN_SSL_STREAMING_PORT=8089,
        RAVEN_MARTI_HTTPS_PORT=8443,
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
    app.register_blueprint(api_blueprint)
    app.register_blueprint(data_package_api)
    app.register_blueprint(certificate_authority_api_blueprint)
    app.register_blueprint(user_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
        ds.create_user(username="bob", password=hash_password("bobpass"), roles=["user"])
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _client(app, username):
    client = app.test_client()
    _login(app, client, username)
    return client


def _set_days(app, username, days):
    with app.app_context():
        user = app.security.datastore.find_user(username=username)
        user.cert_validity_days = days
        db.session.commit()


def _lifetime_days(cert):
    delta = cert.not_valid_after_utc - cert.not_valid_before_utc
    return round(delta.total_seconds() / 86400)


def _issued_cert(app, username):
    path = os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", username, username + ".pem")
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _cert_row_days(app, **filters):
    from raven.models.Certificate import Certificate

    with app.app_context():
        row = db.session.query(Certificate).filter_by(**filters).order_by(Certificate.id.desc()).first()
        expires = row.expiration_date
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=datetime.timezone.utc)
        return (expires - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400


# ---------------------------------------------------------------- raven.cert_validity


@pytest.mark.parametrize(
    "value,expected",
    [(None, None), ("", None), ("  ", None), (1, 1), (MAX_DAYS, MAX_DAYS), ("7", 7), (" 12 ", 12)],
)
def test_validate_cert_days_accepts(app, value, expected):
    from raven.cert_validity import validate_cert_days

    with app.app_context():
        assert validate_cert_days(value) == expected


@pytest.mark.parametrize(
    "value", [0, -1, MAX_DAYS + 1, True, False, 1.5, "abc", "1.5", "-3", "0", [7], {"d": 7}]
)
def test_validate_cert_days_rejects(app, value):
    from raven.cert_validity import validate_cert_days

    with app.app_context(), pytest.raises(ValueError):
        validate_cert_days(value)


def test_max_and_resolve(app):
    from raven.cert_validity import max_cert_days, resolve_cert_days
    from raven.models.user import User

    with app.app_context():
        assert max_cert_days() == MAX_DAYS
        assert resolve_cert_days(None) == MAX_DAYS
        for stored, expected in [(None, MAX_DAYS), (10, 10), (MAX_DAYS, MAX_DAYS)]:
            assert resolve_cert_days(User(username="x", cert_validity_days=stored)) == expected
        # A stored value that's no longer valid (e.g. the server max was lowered) falls back
        for stale in (0, -5, MAX_DAYS + 100):
            assert resolve_cert_days(User(username="x", cert_validity_days=stale)) == MAX_DAYS


# ---------------------------------------------------------------- /api/users/certificate_validity


def test_get_validity_requires_login(app):
    r = app.test_client().get(
        "/api/users/certificate_validity",
        query_string={"username": "alice"},
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 401


def test_get_validity_default_and_self(app):
    alice = _client(app, "alice")
    r = alice.get("/api/users/certificate_validity")
    assert r.status_code == 200, r.json
    assert r.json["success"] is True
    assert r.json["username"] == "alice"
    assert r.json["cert_validity_days"] is None
    assert r.json["effective_days"] == MAX_DAYS
    assert r.json["default_days"] == MAX_DAYS
    assert r.json["max_days"] == MAX_DAYS

    assert alice.get(
        "/api/users/certificate_validity", query_string={"username": "alice"}
    ).status_code == 200


def test_non_admin_cannot_view_others(app):
    alice = _client(app, "alice")
    r = alice.get("/api/users/certificate_validity", query_string={"username": "bob"})
    assert r.status_code == 403


def test_admin_get_any_and_unknown(app):
    admin = _client(app, "admin")
    _set_days(app, "bob", 5)
    r = admin.get("/api/users/certificate_validity", query_string={"username": "bob"})
    assert r.status_code == 200
    assert r.json["cert_validity_days"] == 5 and r.json["effective_days"] == 5
    r = admin.get("/api/users/certificate_validity", query_string={"username": "nosuchuser"})
    assert r.status_code == 404


def test_non_admin_cannot_set(app):
    alice = _client(app, "alice")
    for target in ("alice", "bob"):
        r = alice.put(
            "/api/users/certificate_validity", json={"username": target, "cert_validity_days": 1}
        )
        assert r.status_code == 403, target
    with app.app_context():
        assert app.security.datastore.find_user(username="alice").cert_validity_days is None


def test_admin_set_and_reset(app):
    admin = _client(app, "admin")
    r = admin.put("/api/users/certificate_validity", json={"username": "bob", "cert_validity_days": 7})
    assert r.status_code == 200, r.json
    assert r.json["cert_validity_days"] == 7 and r.json["effective_days"] == 7
    with app.app_context():
        assert app.security.datastore.find_user(username="bob").cert_validity_days == 7

    # Strings from a form input are fine too
    r = admin.put("/api/users/certificate_validity", json={"username": "bob", "cert_validity_days": "9"})
    assert r.status_code == 200 and r.json["cert_validity_days"] == 9

    # null resets to the server default
    r = admin.put(
        "/api/users/certificate_validity", json={"username": "bob", "cert_validity_days": None}
    )
    assert r.status_code == 200
    assert r.json["cert_validity_days"] is None and r.json["effective_days"] == MAX_DAYS
    with app.app_context():
        assert app.security.datastore.find_user(username="bob").cert_validity_days is None


@pytest.mark.parametrize("bad", [0, -1, MAX_DAYS + 1, "abc", 1.5, True])
def test_admin_set_invalid(app, bad):
    _set_days(app, "bob", 4)
    admin = _client(app, "admin")
    r = admin.put("/api/users/certificate_validity", json={"username": "bob", "cert_validity_days": bad})
    assert r.status_code == 400, bad
    assert r.json["success"] is False
    with app.app_context():
        assert app.security.datastore.find_user(username="bob").cert_validity_days == 4


def test_admin_set_unknown_user(app):
    admin = _client(app, "admin")
    r = admin.put(
        "/api/users/certificate_validity", json={"username": "nosuchuser", "cert_validity_days": 3}
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- issuance uses the setting


def test_api_certificate_default_lifetime(app):
    admin = _client(app, "admin")
    r = admin.post("/api/certificate", json={"username": "bob"})
    assert r.status_code == 200, r.json
    assert r.json["cert_validity_days"] == MAX_DAYS
    assert r.json["filename"] == "bob_CONFIG.zip"
    assert r.json["hash"]
    assert _lifetime_days(_issued_cert(app, "bob")) == MAX_DAYS
    assert round(_cert_row_days(app, username="bob")) == MAX_DAYS


def test_api_certificate_uses_user_lifetime(app):
    _set_days(app, "bob", 7)
    admin = _client(app, "admin")
    r = admin.post("/api/certificate", json={"username": "bob"})
    assert r.status_code == 200, r.json
    assert r.json["cert_validity_days"] == 7
    assert _lifetime_days(_issued_cert(app, "bob")) == 7
    assert round(_cert_row_days(app, username="bob")) == 7

    # The returned hash is the data package, which (being private) its owner can download
    dl = _client(app, "bob").get("/api/data_packages/download", query_string={"hash": r.json["hash"]})
    assert dl.status_code == 200


def test_api_certificate_self_service_uses_admin_setting(app):
    # A user re-issuing their own cert can't escape the admin's lifetime
    _set_days(app, "alice", 3)
    alice = _client(app, "alice")
    r = alice.post("/api/certificate", json={"username": "alice", "days": MAX_DAYS})
    assert r.status_code == 200, r.json
    assert _lifetime_days(_issued_cert(app, "alice")) == 3


def test_enrollment_default_lifetime(app):
    r, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-default")
    assert r.status_code == 200, r.data
    assert _lifetime_days(_signed_cert(r)) == MAX_DAYS
    assert round(_cert_row_days(app, eud_uid="ANDROID-default")) == MAX_DAYS


def test_enrollment_uses_user_lifetime(app):
    _set_days(app, "alice", 5)
    r, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-five")
    assert r.status_code == 200, r.data
    assert _lifetime_days(_signed_cert(r)) == 5
    assert round(_cert_row_days(app, eud_uid="ANDROID-five")) == 5

    # Other users are unaffected
    r, _ = _sign(app, "bob", "bobpass", ["bob"], uid="ANDROID-bob")
    assert _lifetime_days(_signed_cert(r)) == MAX_DAYS


def test_ca_days_parameter(app):
    from raven.certificate_authority import CertificateAuthority
    from raven.extensions import logger

    # generate_zip() reads request.url_root for the server address
    with app.test_request_context("/"):
        ca = CertificateAuthority(logger, app)
        ca.issue_certificate("carol", False, days=2)
        assert _lifetime_days(_issued_cert(app, "carol")) == 2
        ca.issue_certificate("dave", False)
        assert _lifetime_days(_issued_cert(app, "dave")) == MAX_DAYS


def test_api_certificate_download_returns_zip(app):
    import io
    import zipfile

    _set_days(app, "bob", 9)
    admin = _client(app, "admin")
    r = admin.post("/api/certificate", json={"username": "bob", "download": True})
    assert r.status_code == 200, r.data
    assert r.mimetype == "application/zip"
    assert "attachment" in r.headers["Content-Disposition"]
    assert "bob_CONFIG.zip" in r.headers["Content-Disposition"]

    # The outer package holds the manifest and the inner zip with the user's cert
    names = zipfile.ZipFile(io.BytesIO(r.data)).namelist()
    assert any(n.endswith("MANIFEST/manifest.xml") for n in names), names
    assert any(n.endswith("bob.zip") for n in names), names

    # Same lifetime as the JSON path
    assert _lifetime_days(_issued_cert(app, "bob")) == 9
    assert round(_cert_row_days(app, username="bob")) == 9


def test_api_certificate_download_not_for_others(app):
    alice = _client(app, "alice")
    r = alice.post("/api/certificate", json={"username": "bob", "download": True})
    assert r.status_code == 403
    assert r.mimetype == "application/json"


def test_package_truststore_opens_with_pref_password(app):
    # truststore-root.p12 left under an old password (RAVEN_CA_PASSWORD changed after install):
    # the package must still ship a truststore that opens with the password its pref gives
    import io
    import re
    import subprocess
    import zipfile

    from cryptography.hazmat.primitives.serialization import pkcs12

    ca = app.config["RAVEN_CA_FOLDER"]
    subprocess.run(
        ["openssl", "pkcs12", "-export", "-nokeys", "-in", os.path.join(ca, "ca.pem"),
         "-out", os.path.join(ca, "truststore-root.p12"), "-passout", "pass:atakatak"],
        check=True,
        capture_output=True,
    )

    admin = _client(app, "admin")
    r = admin.post("/api/certificate", json={"username": "bob", "download": True})
    assert r.status_code == 200, r.data

    outer = zipfile.ZipFile(io.BytesIO(r.data))
    inner_name = next(n for n in outer.namelist() if n.endswith("bob.zip"))
    inner = zipfile.ZipFile(io.BytesIO(outer.read(inner_name)))
    files = {n.rsplit("/", 1)[-1]: inner.read(n) for n in inner.namelist()}

    pref = files["preference.pref"].decode()
    ca_password = re.search(r'key="caPassword"[^>]*>([^<]*)<', pref).group(1)
    client_password = re.search(r'key="clientPassword"[^>]*>([^<]*)<', pref).group(1)

    _, _, extra = pkcs12.load_key_and_certificates(files["truststore-root.p12"], ca_password.encode())
    assert len(extra) == 1
    key, cert, _ = pkcs12.load_key_and_certificates(files["bob.p12"], client_password.encode())
    assert key is not None and cert is not None


def test_truststore_endpoint_opens_with_ca_password(app):
    # Same stale-password case, for the unauthenticated /api/truststore download
    import subprocess

    from cryptography.hazmat.primitives.serialization import pkcs12

    ca = app.config["RAVEN_CA_FOLDER"]
    subprocess.run(
        ["openssl", "pkcs12", "-export", "-nokeys", "-in", os.path.join(ca, "ca.pem"),
         "-out", os.path.join(ca, "truststore-root.p12"), "-passout", "pass:atakatak"],
        check=True,
        capture_output=True,
    )

    r = app.test_client().get("/api/truststore")
    assert r.status_code == 200
    assert "attachment" in r.headers["Content-Disposition"]
    _, _, extra = pkcs12.load_key_and_certificates(r.data, CA_PASSWORD.encode())
    assert len(extra) == 1
