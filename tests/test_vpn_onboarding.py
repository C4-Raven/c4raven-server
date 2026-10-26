"""
Tests for VPN/IP onboarding (raven/blueprints/raven_api/onboard_api.py), the scoped onboarding
link tokens, and the enrollment token checks in Token.verify_token / basic_auth.

These build a minimal Flask app (sqlite, only the blueprints under test) instead of using
raven.app.create_app(), which needs RabbitMQ, Postgres migrations and the scheduler.
"""

import base64
import datetime
import io
import os
import shutil
import time
import zipfile
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import db

# The User model (imported by the blueprints below) needs Flask-Security's model mixins bound to
# Raven's db first, same as create_app() does.
try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.blueprints.marti_api.certificate_enrollment_api import (
    basic_auth,
    certificate_authority_api_blueprint,
)
from raven.blueprints.raven_api.onboard_api import (
    build_onboard_package,
    classify_address,
    create_onboard_token,
    export_onboard_truststore,
    normalize_ipv4,
    onboard_api_blueprint,
    truststore_filename,
    verify_onboard_token,
)
from raven.certificate_authority import CertificateAuthority
from raven.defaultconfig import DefaultConfig
from raven.eud_handler.EudHandler import authenticate_eud_credentials
from raven.models.Token import Token

TRUSTSTORE = b"not-really-a-p12"
HAVE_OPENSSL = shutil.which("openssl") is not None


def _pref_entries(pref_xml: bytes) -> dict:
    root = ElementTree.fromstring(pref_xml)
    streams = [p for p in root.findall("preference") if p.get("name") == "cot_streams"]
    assert len(streams) == 1
    return {e.get("key"): (e.get("class"), e.text) for e in streams[0].findall("entry")}


def _write_ca_cert(ca, key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Raven-Test-CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (ca / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


@pytest.fixture
def app(tmp_path):
    ca = tmp_path / "ca"
    (ca / "certs" / "raven").mkdir(parents=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (ca / "certs" / "raven" / "raven.nopass.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (ca / "certs" / "raven" / "raven.pub").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    (ca / "truststore-root.p12").write_bytes(TRUSTSTORE)
    _write_ca_cert(ca, key)

    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_CA_FOLDER=str(ca),
        RAVEN_CA_PASSWORD="capass",
        RAVEN_SSL_STREAMING_PORT=8089,
        RAVEN_MARTI_HTTP_PORT=8080,
        RAVEN_ENABLE_LDAP=False,
        RAVEN_DOMAIN=None,
        RAVEN_VPN_QR_DEFAULT_EXPIRATION_HOURS=24,
        RAVEN_ONBOARD_TRUSTSTORE_PASSWORD="atakatak",
        RAVEN_CA_NAME="Raven-Test-CA",
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
    app.register_blueprint(onboard_api_blueprint)
    app.register_blueprint(certificate_authority_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
        ds.create_user(username="bob", password=hash_password("bobpass"), roles=["user"])
        ds.create_user(username="Carol.X", password=hash_password("carolpass"), roles=["user"])
        ds.create_user(
            username="gone", password=hash_password("gonepass"), roles=["user"], active=False
        )
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def _login(app, client, username):
    with app.app_context():
        user = app.security.datastore.find_user(username=username)
        uniquifier = user.fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()


def _make_token(username, max_uses=None, expiration=None) -> str:
    token = Token()
    token.creation = int(time.time())
    token.username = username
    token.max_uses = max_uses
    token.expiration = expiration
    token.total_uses = 0
    token.hash_token()
    db.session.add(token)
    db.session.commit()
    return token.generate_token()


def _basic(username, password):
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def _qr(client, **body):
    return client.post("/api/vpn_qr_string", json=body)


def _link_token(response):
    return response.json["url"].rsplit("/", 1)[1]


# ---------------------------------------------------------------- Token.verify_token / basic_auth


def test_verify_token_rejects_other_users_token(app):
    with app.app_context():
        token = _make_token("alice")
        assert Token.verify_token(token, "alice")
        assert not Token.verify_token(token, "bob")
        assert not Token.verify_token(token, "")


def test_verify_token_subject_match_is_case_insensitive(app):
    with app.app_context():
        token = _make_token("alice")
        assert Token.verify_token(token, "ALICE", consume=False)


def test_basic_auth_rejects_token_for_another_user(app):
    with app.test_request_context():
        token = _make_token("alice")
        assert basic_auth(_basic("alice", token))
        assert not basic_auth(_basic("bob", token))
        assert not basic_auth(_basic("admin", token))
        assert basic_auth(_basic("bob", "bobpass"))
        assert not basic_auth(None)


def test_verify_token_consume_false_does_not_count(app):
    with app.app_context():
        token = _make_token("alice", max_uses=1)
        for _ in range(3):
            assert Token.verify_token(token, "alice", consume=False)
        assert db.session.query(Token).filter_by(username="alice").first().total_uses == 0

        assert Token.verify_token(token, "alice")
        assert db.session.query(Token).filter_by(username="alice").first().total_uses == 1
        assert not Token.verify_token(token, "alice")
        assert not Token.verify_token(token, "alice", consume=False)
        assert Token.verify_token(token, "alice", consume=False, check_max=False)


def test_enrollment_profile_requires_credentials(app):
    from raven.blueprints.marti_api.device_profile_marti_api import (
        device_profile_marti_api_blueprint,
    )

    app.register_blueprint(device_profile_marti_api_blueprint)
    client = app.test_client()
    assert client.get("/Marti/api/tls/profile/enrollment").status_code == 401
    assert (
        client.get(
            "/Marti/api/tls/profile/enrollment",
            headers={"Authorization": _basic("alice", "wrong")},
        ).status_code
        == 401
    )


# ---------------------------------------------------------------- onboarding link tokens


def test_onboard_token_is_not_an_enrollment_credential(app):
    """The link in a VPN QR must not authenticate anywhere an enrollment token/password does."""
    with app.test_request_context():
        link = create_onboard_token("alice", int(time.time()) + 3600)
        assert verify_onboard_token(link).username == "alice"

        assert not Token.verify_token(link, "alice")
        assert not Token.verify_token(link, "alice", consume=False, check_max=False)
        assert not basic_auth(_basic("alice", link))
        assert not basic_auth(
            _basic("alice", link), consume_token=False, check_token_max=False
        )
        assert authenticate_eud_credentials(app, "alice", link) is None


def test_verify_token_rejects_scoped_token_even_if_in_db(app):
    """Defence in depth: a scoped JWT is rejected even if its hash were somehow in the DB."""
    with app.app_context():
        token = Token()
        token.creation = int(time.time())
        token.username = "alice"
        token.total_uses = 0
        claims = token.to_json(True)
        claims["scope"] = "onboard"
        import hashlib, json as _json

        token.token_hash = hashlib.sha256(_json.dumps(claims).encode()).hexdigest()
        db.session.add(token)
        db.session.commit()
        with open(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "raven", "raven.nopass.key"), "rb") as k:
            scoped = jwt.encode(claims, k.read(), algorithm="RS256")
        assert not Token.verify_token(scoped, "alice", consume=False)


def test_enrollment_token_is_not_an_onboard_token(app):
    with app.app_context():
        enrollment = _make_token("alice")
        assert verify_onboard_token(enrollment) is None


def test_verify_onboard_token_rejections(app):
    with app.app_context():
        assert verify_onboard_token(create_onboard_token("gone", int(time.time()) + 60)) is None
        assert verify_onboard_token(create_onboard_token("nobody", int(time.time()) + 60)) is None
        assert verify_onboard_token("garbage") is None
        assert verify_onboard_token("") is None
        assert verify_onboard_token("x" * 5000) is None

        key = open(
            os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "raven", "raven.nopass.key"), "rb"
        ).read()
        now = int(time.time())
        base = {
            "sub": "alice", "iat": now, "exp": now + 60, "iss": "Raven", "aud": "Raven",
            "scope": "onboard", "jti": "x",
        }
        assert verify_onboard_token(jwt.encode(base, key, algorithm="RS256")).username == "alice"
        for change in (
            {"scope": "enroll"},
            {"aud": "Other"},
            {"iss": "Other"},
            {"exp": now - 10},
        ):
            assert verify_onboard_token(jwt.encode({**base, **change}, key, algorithm="RS256")) is None
        for missing in ("scope", "exp", "jti", "sub"):
            claims = {k: v for k, v in base.items() if k != missing}
            assert verify_onboard_token(jwt.encode(claims, key, algorithm="RS256")) is None

        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert verify_onboard_token(jwt.encode(base, other, algorithm="RS256")) is None


# ---------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    "value,expected",
    [
        ("100.76.118.201", "100.76.118.201"),
        (" 10.0.0.5 ", "10.0.0.5"),
        ("fd7a:115c:a1e0::1", None),
        ("[fd7a:115c:a1e0::1]", None),
        ("tak.example.com", None),
        ("raven-box", None),
        ("http://10.0.0.5", None),
        ("10.0.0.5:8080", None),
        ("10.0.0.5/x", None),
        ("10.0.0.256", None),
        ("0.0.0.0", None),
        ("127.0.0.1", None),
        ("", None),
        (None, None),
        (5, None),
    ],
)
def test_normalize_ipv4(value, expected):
    assert normalize_ipv4(value) == expected


def test_classify_address():
    assert classify_address("wt0", "100.76.118.201") == "vpn"
    assert classify_address("wg0", "10.8.0.1") == "vpn"
    assert classify_address("eth0", "100.100.1.1") == "vpn"  # CGNAT
    assert classify_address("eth0", "192.168.1.10") == "lan"
    assert classify_address("eth0", "8.8.8.8") == "public"
    assert classify_address("lo", "127.0.0.1") is None
    assert classify_address("eth0", "169.254.1.1") is None
    assert classify_address("docker0", "172.17.0.1") is None
    assert classify_address("tailscale0", "fd7a:115c:a1e0::1") is None  # IPv4 only


def test_truststore_filename():
    assert truststore_filename("100.76.118.201") == "raven-100-76-118-201-truststore.p12"


def test_build_onboard_package_contents():
    data = build_onboard_package("100.76.118.201", 8089, TRUSTSTORE, "atakatak")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        manifest = ElementTree.fromstring(z.read("MANIFEST/manifest.xml"))
        params = {
            p.get("name"): p.get("value") for p in manifest.find("Configuration").findall("Parameter")
        }
        assert params["onReceiveDelete"] == "true"
        assert params["name"] == "Raven_100.76.118.201"
        entries = [c.get("zipEntry") for c in manifest.find("Contents").findall("Content")]
        assert sorted(entries) == sorted(n for n in names if n != "MANIFEST/manifest.xml")

        p12 = [n for n in names if n.endswith(".p12")]
        assert len(p12) == 1
        assert p12[0].endswith("/raven-100-76-118-201-truststore.p12")
        assert z.read(p12[0]) == TRUSTSTORE

        pref = [n for n in names if n.endswith(".pref")]
        assert len(pref) == 1
        entries = _pref_entries(z.read(pref[0]))

    assert entries == {
        "count": ("class java.lang.Integer", "1"),
        "description0": ("class java.lang.String", "Raven (100.76.118.201)"),
        "enabled0": ("class java.lang.Boolean", "true"),
        "connectString0": ("class java.lang.String", "100.76.118.201:8089:ssl"),
        "caLocation0": (
            "class java.lang.String",
            "/storage/emulated/0/atak/cert/raven-100-76-118-201-truststore.p12",
        ),
        "caPassword0": ("class java.lang.String", "atakatak"),
        "enrollForCertificateWithTrust0": ("class java.lang.Boolean", "true"),
        "enrollUseTrust0": ("class java.lang.Boolean", "true"),
    }


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs the openssl CLI")
def test_export_onboard_truststore(app):
    data = export_onboard_truststore(app.config["RAVEN_CA_FOLDER"], "atakatak", "Raven-Test-CA")
    key, cert, extra = pkcs12.load_key_and_certificates(data, b"atakatak")
    assert key is None and cert is None
    assert len(extra) == 1
    assert extra[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Raven-Test-CA"
    with pytest.raises(Exception):
        pkcs12.load_key_and_certificates(data, b"capass")


# ---------------------------------------------------------------- endpoints


def test_server_addresses(app):
    client = app.test_client()
    assert client.get("/api/server_addresses").status_code in (401, 302)
    _login(app, client, "alice")
    r = client.get("/api/server_addresses")
    assert r.status_code == 200
    assert set(r.json) == {"addresses", "domain"}
    for a in r.json["addresses"]:
        assert set(a) == {"address", "interface", "kind"}
        assert a["kind"] in ("vpn", "lan", "public")
        assert normalize_ipv4(a["address"]) == a["address"]


def test_vpn_qr_string_format(app):
    client = app.test_client()
    _login(app, client, "alice")
    exp = int(time.time()) + 3600
    r = _qr(client, host="100.76.118.201", expiration=exp)
    assert r.status_code == 200, r.json
    body = r.json
    assert set(body) == {"success", "qr_string", "url", "host", "username", "expiration"}
    assert body["success"] is True
    assert body["host"] == "100.76.118.201"
    assert body["username"] == "alice"
    assert body["expiration"] == exp
    assert body["url"].startswith("http://100.76.118.201:8080/api/onboard/")

    qr = urlparse(body["qr_string"])
    assert body["qr_string"].startswith("tak://com.atakmap.app/import?url=")
    assert "/" not in body["qr_string"].split("url=", 1)[1]
    assert parse_qs(qr.query)["url"][0] == body["url"]

    claims = jwt.decode(_link_token(r), options={"verify_signature": False})
    assert claims["sub"] == "alice" and claims["exp"] == exp
    assert claims["scope"] == "onboard" and claims["jti"]
    assert claims["aud"] == "Raven" and claims["iss"] == "Raven"
    assert "max" not in claims


@pytest.mark.parametrize(
    "host", ["fd7a:115c:a1e0::1", "tak.example.com", "http://1.2.3.4", "1.2.3.4:80", "a/b", "", None]
)
def test_vpn_qr_string_rejects_non_ipv4_hosts(app, host):
    client = app.test_client()
    _login(app, client, "alice")
    r = _qr(client, host=host)
    assert r.status_code == 400
    assert "IPv4" in r.json["error"]


def test_vpn_qr_string_default_expiration(app):
    client = app.test_client()
    _login(app, client, "alice")
    before = int(time.time())
    r = _qr(client, host="10.0.0.5")
    assert r.status_code == 200
    exp = r.json["expiration"]
    assert before + 24 * 3600 <= exp <= int(time.time()) + 24 * 3600
    assert jwt.decode(_link_token(r), options={"verify_signature": False})["exp"] == exp

    app.config["RAVEN_VPN_QR_DEFAULT_EXPIRATION_HOURS"] = 2
    exp = _qr(client, host="10.0.0.5").json["expiration"]
    assert abs(exp - (int(time.time()) + 2 * 3600)) <= 2

    explicit = int(time.time()) + 7 * 24 * 3600
    assert _qr(client, host="10.0.0.5", expiration=explicit).json["expiration"] == explicit
    assert _qr(client, host="10.0.0.5", expiration=explicit * 1000).json["expiration"] == explicit

    assert _qr(client, host="10.0.0.5", expiration=before - 60).status_code == 400
    assert _qr(client, host="10.0.0.5", expiration="soon").status_code == 400


def test_vpn_qr_string_does_not_touch_enrollment_token(app):
    client = app.test_client()
    _login(app, client, "alice")
    with app.app_context():
        enrollment = _make_token("alice", max_uses=3)
        before = db.session.query(Token).filter_by(username="alice").one()
        snapshot = (before.token_hash, before.creation, before.total_uses, before.max_uses)

    first = _link_token(_qr(client, host="10.0.0.5"))
    second = _link_token(_qr(client, host="10.0.0.5"))
    assert first != second  # unique jti

    with app.app_context():
        rows = db.session.query(Token).filter_by(username="alice").all()
        assert len(rows) == 1
        t = rows[0]
        assert (t.token_hash, t.creation, t.total_uses, t.max_uses) == snapshot
        assert Token.verify_token(enrollment, "alice", consume=False)
        # Both links stay valid until they expire
        assert verify_onboard_token(first).username == "alice"
        assert verify_onboard_token(second).username == "alice"

    # No Token rows are created for users who didn't have one
    _login(app, client, "bob")
    assert _qr(client, host="10.0.0.5").status_code == 200
    with app.app_context():
        assert db.session.query(Token).filter_by(username="bob").count() == 0


def test_vpn_qr_string_permissions(app):
    client = app.test_client()
    assert _qr(client, host="10.0.0.5").status_code in (401, 302)

    _login(app, client, "alice")
    r = _qr(client, host="10.0.0.5", username="bob")
    assert r.status_code == 403
    # Own username in another case is still "self"
    r = _qr(client, host="10.0.0.5", username="ALICE")
    assert r.status_code == 200 and r.json["username"] == "alice"

    admin = app.test_client()
    _login(app, admin, "admin")
    r = _qr(admin, host="10.0.0.5", username="bob")
    assert r.status_code == 200 and r.json["username"] == "bob"
    # Case-insensitive lookup, stored spelling returned and signed
    r = _qr(admin, host="10.0.0.5", username="carol.x")
    assert r.status_code == 200 and r.json["username"] == "Carol.X"
    assert jwt.decode(_link_token(r), options={"verify_signature": False})["sub"] == "Carol.X"
    assert _qr(admin, host="10.0.0.5", username="nobody").status_code == 404


@pytest.mark.skipif(not HAVE_OPENSSL, reason="needs the openssl CLI")
def test_onboard_download(app):
    client = app.test_client()
    _login(app, client, "alice")
    path = urlparse(_qr(client, host="100.76.118.201").json["url"]).path

    anon = app.test_client()
    r = anon.get(path, base_url="http://100.76.118.201:8080")
    assert r.status_code == 200
    assert r.mimetype == "application/zip"
    assert "no-store" in r.headers["Cache-Control"]
    assert 'filename="Raven_100.76.118.201.zip"' in r.headers["Content-Disposition"]

    # Host comes from the address the phone actually used, not the one in the QR
    r2 = anon.get(path, base_url="http://10.9.9.9:8080")
    assert r2.status_code == 200
    with zipfile.ZipFile(io.BytesIO(r2.data)) as z:
        pref = [n for n in z.namelist() if n.endswith(".pref")][0]
        entries = _pref_entries(z.read(pref))
        assert entries["connectString0"][1] == "10.9.9.9:8089:ssl"
        assert entries["caPassword0"][1] == "atakatak"
        p12 = [n for n in z.namelist() if n.endswith("raven-10-9-9-9-truststore.p12")]
        assert len(p12) == 1
        _, _, certs = pkcs12.load_key_and_certificates(z.read(p12[0]), b"atakatak")
        assert len(certs) == 1

    # Repeated downloads work and create no Token rows
    assert anon.get(path, base_url="http://10.9.9.9:8080").status_code == 200
    with app.app_context():
        assert db.session.query(Token).count() == 0

    # Reached by hostname (not an IPv4 literal): no package
    assert anon.get(path, base_url="http://tak.example.com:8080").status_code == 404


def test_onboard_rejects_bad_tokens(app):
    anon = app.test_client()
    assert anon.get("/api/onboard/garbage").status_code == 404

    with app.app_context():
        enrollment = _make_token("alice")
        expired = create_onboard_token("alice", int(time.time()) - 10)
        inactive = create_onboard_token("gone", int(time.time()) + 600)
    # A regular enrollment token can't be used as an onboarding link
    assert anon.get(f"/api/onboard/{enrollment}").status_code == 404
    assert anon.get(f"/api/onboard/{expired}").status_code == 404
    assert anon.get(f"/api/onboard/{inactive}").status_code == 404

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    forged = jwt.encode(
        {"sub": "alice", "iss": "Raven", "aud": "Raven", "iat": now, "exp": now + 60,
         "scope": "onboard", "jti": "x"},
        other,
        algorithm="RS256",
    )
    assert anon.get(f"/api/onboard/{forged}").status_code == 404


# ---------------------------------------------------------------- CA common-name safety


@pytest.mark.parametrize(
    "name", ["alice", "Carol.X", "first_last", "jean-luc", "user@example.org", "Zoë", "用户1"]
)
def test_validate_common_name_accepts_usernames(name):
    assert CertificateAuthority.validate_common_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "a b", "a;rm -rf /", "$(id)", "a`id`", "a|b", "a&b", "a/b", "../x", "..", ".hidden",
     "-rf", "a'b", 'a"b', "a\nb", "a*", None, "x" * 256],
)
def test_validate_common_name_rejects_unsafe(name):
    with pytest.raises(ValueError):
        CertificateAuthority.validate_common_name(name)


def test_issue_certificate_rejects_unsafe_name(app):
    ca = CertificateAuthority(None, app)
    with pytest.raises(ValueError):
        ca.issue_certificate("x; touch /tmp/pwned")
    with pytest.raises(ValueError):
        ca.sign_csr(b"", "$(id)")
