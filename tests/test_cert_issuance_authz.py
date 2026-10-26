"""
Authorization tests for client certificate issuance.

The client cert's CN is the user's identity on the SSL streaming port, so whoever can get a cert
with CN=<user> can act as that user. Covers:

* POST /api/certificate (raven_api/api.py): non-admins may only issue for themselves, admins for
  anyone; the resulting data package (which holds the p12) is private to its owner.
* POST /Marti/api/tls/signClient/v2 (certificate_enrollment_api.py): the issued cert's CN is the
  authenticated user, whatever CN the CSR asked for.

Same minimal sqlite Flask app approach as tests/test_vpn_onboarding.py, plus a real throwaway CA
made with raven.certificate_authority (needs the openssl CLI, >= 3.0 for the subject override).
"""

import base64
import json
import os
import shutil
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.blueprints.marti_api.certificate_enrollment_api import (
    basic_auth,
    certificate_authority_api_blueprint,
)
from raven.blueprints.raven_api.api import api_blueprint
from raven.blueprints.raven_api.data_package_api import data_package_api
from raven.certificate_authority import CertificateAuthority
from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, logger

CA_PASSWORD = "capass"


class _CAApp:
    """Just enough of a Flask app for CertificateAuthority.create_ca()."""

    def __init__(self, ca_folder):
        self.config = {
            "RAVEN_CA_FOLDER": ca_folder,
            "RAVEN_CA_PASSWORD": CA_PASSWORD,
            "RAVEN_CA_NAME": "Raven-Test-CA",
            "RAVEN_CA_EXPIRATION_TIME": 30,
            "RAVEN_CA_SUBJECT": DefaultConfig.RAVEN_CA_SUBJECT,
        }


@pytest.fixture(scope="session")
def ca_template(tmp_path_factory):
    folder = str(tmp_path_factory.mktemp("ca-template") / "ca")
    cwd = os.getcwd()
    try:
        CertificateAuthority(logger, _CAApp(folder)).create_ca()
    finally:
        os.chdir(cwd)
    assert os.path.exists(os.path.join(folder, "truststore-root.p12"))
    return folder


@pytest.fixture
def app(tmp_path, ca_template, monkeypatch):
    # generate_zip() chdirs into the cert folder; put the cwd back afterwards
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
        RAVEN_CA_EXPIRATION_TIME=30,
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
    babel.init_app(app)  # the routes under test return gettext() messages

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(api_blueprint)
    app.register_blueprint(data_package_api)
    app.register_blueprint(certificate_authority_api_blueprint)

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


def _login(app, client, username):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username=username).fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()


def _basic(username, password):
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def _issued_cn(app, username):
    path = os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", username, username + ".pem")
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]


def _cert_packages(app):
    from raven.models.DataPackage import DataPackage

    with app.app_context():
        return {
            dp.filename: (dp.hash, dp.tool, dp.keywords, dp.user.username if dp.user else None)
            for dp in db.session.query(DataPackage).all()
        }


# ---------------------------------------------------------------- /api/certificate


def test_api_certificate_requires_login(app):
    r = app.test_client().post("/api/certificate", json={"username": "alice"})
    assert r.status_code == 401


def test_non_admin_cannot_issue_for_another_user(app):
    client = app.test_client()
    _login(app, client, "alice")
    for victim in ("admin", "bob", "ADMIN"):
        r = client.post("/api/certificate", json={"username": victim})
        assert r.status_code == 403, victim
    assert not os.path.exists(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "admin"))
    assert not os.path.exists(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "bob"))
    assert _cert_packages(app) == {}


def test_non_admin_can_issue_own_cert_and_package_is_private(app):
    alice = app.test_client()
    _login(app, alice, "alice")
    r = alice.post("/api/certificate", json={"username": "alice"})
    assert r.status_code == 200, r.json
    assert _issued_cn(app, "alice") == ["alice"]

    packages = _cert_packages(app)
    file_hash, tool, keywords, owner = packages["alice_CONFIG.zip"]
    assert tool == "private" and keywords != "public" and owner == "alice"

    from raven.models.Certificate import Certificate

    with app.app_context():
        cert = db.session.query(Certificate).filter_by(username="alice").one()
        assert cert.common_name == "alice"
        # create_ca() puts the truststore at the CA folder root
        assert cert.truststore_filename == os.path.join(
            app.config["RAVEN_CA_FOLDER"], "truststore-root.p12"
        )
        assert os.path.exists(cert.truststore_filename)

    # The owner can download it; another user can neither list nor download it
    assert alice.get("/api/data_packages/download", query_string={"hash": file_hash}).status_code == 200

    bob = app.test_client()
    _login(app, bob, "bob")
    assert bob.get("/api/data_packages/download", query_string={"hash": file_hash}).status_code == 403
    listing = bob.get("/api/data_packages").json
    assert file_hash not in json.dumps(listing)

    # Re-issuing (the Users page does this) keeps it private and still works
    assert alice.post("/api/certificate", json={"username": "alice"}).status_code == 200
    assert _cert_packages(app)["alice_CONFIG.zip"][1] == "private"


def test_admin_can_issue_for_any_user(app):
    client = app.test_client()
    _login(app, client, "admin")
    r = client.post("/api/certificate", json={"username": "bob"})
    assert r.status_code == 200, r.json
    assert _issued_cn(app, "bob") == ["bob"]
    _hash, tool, _kw, owner = _cert_packages(app)["bob_CONFIG.zip"]
    # Owned by the cert's user (so bob can fetch it), not by the admin who generated it
    assert tool == "private" and owner == "bob"

    bob = app.test_client()
    _login(app, bob, "bob")
    assert bob.get("/api/data_packages/download", query_string={"hash": _hash}).status_code == 200

    r = client.post("/api/certificate", json={"username": "nosuchuser"})
    assert r.status_code == 400


# ---------------------------------------------------------------- signClient/v2


def _csr_body(cns):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZZ")]
    attrs += [x509.NameAttribute(NameOID.COMMON_NAME, cn) for cn in cns]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attrs))
        .sign(key, hashes.SHA256())
    )
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    # ATAK sends the base64 body without the PEM armour
    body = (
        pem.replace("-----BEGIN CERTIFICATE REQUEST-----\n", "")
        .replace("-----END CERTIFICATE REQUEST-----\n", "")
        .strip()
    )
    return body, key


def _sign(app, username, password, cns, uid="ANDROID-test"):
    body, key = _csr_body(cns)
    r = app.test_client().post(
        "/Marti/api/tls/signClient/v2",
        query_string={"clientUid": uid, "version": "3"},
        data=body,
        headers={"Authorization": _basic(username, password), "Accept": "application/json"},
    )
    return r, key


def _signed_cert(response):
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + response.json["signedCert"].strip()
        + "\n-----END CERTIFICATE-----\n"
    )
    return x509.load_pem_x509_certificate(pem.encode())


def _cns(cert):
    return [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]


def test_basic_auth_returns_username(app):
    with app.app_context():
        assert basic_auth(_basic("alice", "alicepass")) == "alice"
        assert basic_auth(_basic("alice", "wrong")) is False


def test_sign_csr_requires_auth(app):
    r, _ = _sign(app, "alice", "wrong", ["alice"])
    assert r.status_code == 401


def test_sign_csr_with_matching_cn(app):
    r, key = _sign(app, "alice", "alicepass", ["alice"])
    assert r.status_code == 200, r.data
    cert = _signed_cert(r)
    assert _cns(cert) == ["alice"]
    # Signed for the CSR's own key
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()


@pytest.mark.parametrize("csr_cns", [["admin"], ["alice", "admin"], ["admin", "alice"], []])
def test_sign_csr_forces_cn_to_authenticated_user(app, csr_cns):
    r, key = _sign(app, "alice", "alicepass", csr_cns)
    assert r.status_code == 200, r.data
    cert = _signed_cert(r)
    assert _cns(cert) == ["alice"]
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    # O/OU come from the server config, issuer is still the CA
    org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    assert [a.value for a in org] == [DefaultConfig.RAVEN_CA_ORGANIZATION]
    assert cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Raven-Test-CA"
    # Nothing was written under the requested CN
    assert not os.path.exists(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "admin"))

    from raven.models.Certificate import Certificate
    from raven.models.EUD import EUD

    with app.app_context():
        row = db.session.query(Certificate).filter_by(eud_uid="ANDROID-test").one()
        assert row.common_name == "alice" and row.username == "alice"
        eud = db.session.query(EUD).filter_by(uid="ANDROID-test").one()
        assert eud.user.username == "alice"
