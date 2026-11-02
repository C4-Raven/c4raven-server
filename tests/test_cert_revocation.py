"""
Tests for client certificate revocation: raven/cert_revocation.py (crl_index.txt + ca.crl),
the admin certificate API (raven/blueprints/raven_api/certificate_api.py), the app-layer
X-Ssl-Cert check, and the SSL streaming port (EudServerSSL's CRL-checking context, the
eud_control "revoke" message).

Same minimal sqlite Flask app and real throwaway CA as tests/test_cert_issuance_authz.py (needs
the openssl CLI). RabbitMQ isn't available, so the live-session kick is stubbed out and checked
for the serials it was asked to drop.
"""

import datetime
import json
import os
import shutil
import socket
import ssl
import threading
from urllib.parse import quote

import pytest
from cryptography import x509
from flask import Flask, jsonify
from flask_security import Security, SQLAlchemyUserDatastore, hash_password

from raven.extensions import db

from tests.test_cert_issuance_authz import (  # noqa: F401 (ca_template is a fixture)
    CA_PASSWORD,
    _login,
    _sign,
    _signed_cert,
    ca_template,
)

from raven import cert_revocation
from raven.audit import init_audit
from raven.blueprints.marti_api.certificate_enrollment_api import (
    certificate_authority_api_blueprint,
)
from raven.blueprints.raven_api.api import api_blueprint
from raven.blueprints.raven_api.certificate_api import certificate_api_blueprint
from raven.blueprints.raven_api.data_package_api import data_package_api
from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, logger


@pytest.fixture
def kicks(monkeypatch):
    sent = []

    def fake_kick(app, serials, logger=None):
        sent.extend(cert_revocation.normalize_serial(s) for s in serials)
        return True

    monkeypatch.setattr(cert_revocation, "kick_revoked_sessions", fake_kick)
    return sent


@pytest.fixture
def app(tmp_path, ca_template, monkeypatch, kicks):
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
        RAVEN_PROTECTED_USERNAMES=["Admin"],
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
    app.register_blueprint(api_blueprint)
    app.register_blueprint(data_package_api)
    app.register_blueprint(certificate_authority_api_blueprint)
    app.register_blueprint(certificate_api_blueprint)

    # Stands in for any Marti route nginx proxies with X-Ssl-Cert
    @app.route("/Marti/test/ping")
    def ping():
        return jsonify({"ok": True})

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        ds.create_user(username="Admin", password=hash_password("superpass"), roles=["administrator"])
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


def _issue_package(app, username):
    """Issue a cert data package via POST /api/certificate; returns the cert PEM."""
    r = _client(app, "admin").post("/api/certificate", json={"username": username})
    assert r.status_code == 200, r.json
    path = os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", username, username + ".pem")
    with open(path, "rb") as f:
        return f.read()


def _rows(app, **filters):
    from raven.models.Certificate import Certificate

    with app.app_context():
        return [
            c.revocation_json()
            for c in db.session.query(Certificate).filter_by(**filters).order_by(Certificate.id).all()
        ]


def _crl(app):
    with open(os.path.join(app.config["RAVEN_CA_FOLDER"], "ca.crl"), "rb") as f:
        return x509.load_pem_x509_crl(f.read())


def _crl_serials(app):
    return {format(entry.serial_number, "X") for entry in _crl(app)}


def _audit(app, action):
    from raven.models.AuditEvent import AuditEvent

    with app.app_context():
        return [e.to_json() for e in db.session.query(AuditEvent).filter_by(action=action).all()]


# ---------------------------------------------------------------- raven.cert_revocation


@pytest.mark.parametrize(
    "value,expected",
    [
        (255, "FF"),
        ("ff", "FF"),
        ("0x00ff", "FF"),
        ("00:FF", "FF"),
        ("0186A0", "186A0"),
        (" 186a0 ", "186A0"),
        (0, "0"),
        (None, None),
        ("", None),
        ("xyz", None),
        (True, None),
        (-1, None),
    ],
)
def test_normalize_serial(value, expected):
    assert cert_revocation.normalize_serial(value) == expected


def test_revoke_writes_index_and_regenerates_crl(app):
    folder = app.config["RAVEN_CA_FOLDER"]
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    # An odd-length serial (openssl pads it) and a GeneralizedTime (>= 2050) expiry
    revoked = cert_revocation.revoke(
        folder,
        CA_PASSWORD,
        [
            {"serial": "186A0", "not_after": expiry, "subject": "/CN=alice", "reason": "keyCompromise"},
            {
                "serial": 0xABCDEF12,
                "not_after": datetime.datetime(2060, 1, 1, tzinfo=datetime.timezone.utc),
                "subject": "/O=x/CN=bob\twith tab",
                "reason": "superseded",
            },
        ],
    )
    assert revoked == ["186A0", "ABCDEF12"]

    with open(os.path.join(folder, "crl_index.txt")) as f:
        lines = f.read().splitlines()
    assert len(lines) == 2
    fields = lines[0].split("\t")
    assert fields[0] == "R" and fields[3] == "0186A0" and fields[2].endswith(",keyCompromise")
    assert lines[1].split("\t")[1] == "20600101000000Z"
    assert len(lines[1].split("\t")) == 6  # the tab in the subject didn't add a field

    crl = _crl(app)
    reasons = {
        format(e.serial_number, "X"): e.extensions.get_extension_for_class(x509.CRLReason).value.reason
        for e in crl
    }
    assert reasons == {
        "186A0": x509.ReasonFlags.key_compromise,
        "ABCDEF12": x509.ReasonFlags.superseded,
    }
    assert crl.next_update_utc - datetime.datetime.now(datetime.timezone.utc) > datetime.timedelta(
        days=cert_revocation.CRL_DAYS - 1
    )
    assert cert_revocation.is_revoked(folder, "0x186a0")
    assert not cert_revocation.is_revoked(folder, "186A1")

    # Revoking again is a no-op for the index but still succeeds
    assert cert_revocation.revoke(
        folder, CA_PASSWORD, [{"serial": "186A0", "not_after": expiry, "reason": "unspecified"}]
    ) == []
    with open(os.path.join(folder, "crl_index.txt")) as f:
        assert len(f.read().splitlines()) == 2


def test_revoke_rejects_bad_input(app):
    folder = app.config["RAVEN_CA_FOLDER"]
    now = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(ValueError):
        cert_revocation.revoke(folder, CA_PASSWORD, [{"serial": "zz", "not_after": now}])
    with pytest.raises(ValueError):
        cert_revocation.revoke(
            folder, CA_PASSWORD, [{"serial": "01", "not_after": now, "reason": "removeFromCRL"}]
        )
    with open(os.path.join(folder, "crl_index.txt")) as f:
        assert f.read() == ""


def test_ensure_crl_recreates_missing_and_expiring(app, monkeypatch):
    folder = app.config["RAVEN_CA_FOLDER"]
    assert cert_revocation.ensure_crl(folder, CA_PASSWORD) is False  # fresh from create_ca

    os.remove(os.path.join(folder, "ca.crl"))
    assert cert_revocation.ensure_crl(folder, CA_PASSWORD) is True
    assert cert_revocation.crl_next_update(folder) is not None

    # A CRL with less than CRL_REFRESH_DAYS left is replaced by a full-length one
    monkeypatch.setattr(cert_revocation, "CRL_DAYS", 2)
    cert_revocation.generate_crl(folder, CA_PASSWORD)
    monkeypatch.undo()
    assert cert_revocation.ensure_crl(folder, CA_PASSWORD) is True
    remaining = cert_revocation.crl_next_update(folder) - datetime.datetime.now(datetime.timezone.utc)
    assert remaining > datetime.timedelta(days=cert_revocation.CRL_REFRESH_DAYS)


def test_ensure_crl_recreates_missing_index(app):
    folder = app.config["RAVEN_CA_FOLDER"]
    os.remove(os.path.join(folder, "crl_index.txt"))
    os.remove(os.path.join(folder, "ca.crl"))
    assert cert_revocation.ensure_crl(folder, CA_PASSWORD) is True
    assert os.path.exists(os.path.join(folder, "crl_index.txt"))


def test_new_certs_get_wide_random_serials(app):
    serials = {cert_revocation.serial_from_pem(_issue_package(app, "alice")) for _ in range(3)}
    assert len(serials) == 3
    assert all(int(s, 16) > 100000 for s in serials)


# ---------------------------------------------------------------- issuance records the serial


def test_issued_certs_record_serial(app):
    pem = _issue_package(app, "alice")
    r, _ = _sign(app, "bob", "bobpass", ["bob"], uid="ANDROID-bob")
    assert r.status_code == 200, r.json

    alice = _rows(app, username="alice")
    bob = _rows(app, username="bob")
    assert alice[0]["serial_number"] == cert_revocation.serial_from_pem(pem)
    assert bob[0]["serial_number"] == format(_signed_cert(r).serial_number, "X")
    assert alice[0]["status"] == bob[0]["status"] == "valid"


# ---------------------------------------------------------------- the admin API


def test_list_requires_admin(app):
    assert app.test_client().get(
        "/api/certificates", headers={"Accept": "application/json"}
    ).status_code in (401, 403)
    assert _client(app, "alice").get("/api/certificates").status_code == 403
    assert _client(app, "alice").post("/api/certificates/1/revoke", json={}).status_code == 403
    assert _client(app, "alice").post(
        "/api/certificates/revoke_user", json={"username": "bob"}
    ).status_code == 403
    assert _client(app, "alice").post(
        "/api/certificates/revoke", json={"serial": "01"}
    ).status_code == 403


def test_list_filters_by_user(app):
    _issue_package(app, "alice")
    _issue_package(app, "bob")
    admin = _client(app, "admin")
    r = admin.get("/api/certificates", query_string={"username": "ALICE"})
    assert r.status_code == 200
    assert [c["username"] for c in r.json["results"]] == ["alice"]
    assert "cert_password" not in r.json["results"][0]
    assert "keyCompromise" in r.json["reasons"]
    assert r.json["crl_next_update"]
    assert len(admin.get("/api/certificates").json["results"]) == 2


def test_revoke_certificate(app, kicks):
    pem = _issue_package(app, "alice")
    serial = cert_revocation.serial_from_pem(pem)
    cert_id = _rows(app, username="alice")[0]["id"]

    r = _client(app, "admin").post(
        f"/api/certificates/{cert_id}/revoke",
        json={"reason": "keyCompromise", "note": "Phone lost on patrol"},
    )
    assert r.status_code == 200, r.json
    assert r.json["revoked"][0]["status"] == "revoked"
    assert r.json["sessions_disconnected"] is True

    row = _rows(app, username="alice")[0]
    assert row["revoked_at"] and row["revocation_reason"] == "keyCompromise"
    assert serial in _crl_serials(app)
    assert kicks == [serial]

    events = _audit(app, "cert_revoked")
    assert len(events) == 1
    assert events[0]["category"] == "certificate"
    assert events[0]["username"] == "alice" and events[0]["actor"] == "admin"
    assert "Phone lost on patrol" in events[0]["details"] and serial in events[0]["details"]

    # The account stays active so the user can enroll a new device
    with app.app_context():
        assert app.security.datastore.find_user(username="alice").active

    again = _client(app, "admin").post(f"/api/certificates/{cert_id}/revoke", json={})
    assert again.status_code == 400


def test_revoke_validates_input(app):
    _issue_package(app, "alice")
    cert_id = _rows(app, username="alice")[0]["id"]
    admin = _client(app, "admin")
    assert admin.post(f"/api/certificates/{cert_id}/revoke", json={"reason": "nope"}).status_code == 400
    assert admin.post("/api/certificates/9999/revoke", json={}).status_code == 404
    assert admin.post("/api/certificates/revoke", json={"serial": "not hex"}).status_code == 400
    assert admin.post("/api/certificates/revoke_user", json={"username": "ghost"}).status_code == 400
    assert _rows(app, username="alice")[0]["status"] == "valid"


def test_protected_account_certs_cant_be_revoked_by_others(app):
    _issue_package(app, "Admin")
    cert_id = _rows(app, username="Admin")[0]["id"]
    admin = _client(app, "admin")
    assert admin.post(f"/api/certificates/{cert_id}/revoke", json={}).status_code == 403
    assert admin.post("/api/certificates/revoke_user", json={"username": "Admin"}).status_code == 403
    assert _client(app, "Admin").post(f"/api/certificates/{cert_id}/revoke", json={}).status_code == 200


def test_revoke_all_for_user(app, kicks):
    r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    r2, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a2")
    _issue_package(app, "bob")
    alice_serials = {format(_signed_cert(r).serial_number, "X") for r in (r1, r2)}

    r = _client(app, "admin").post(
        "/api/certificates/revoke_user", json={"username": "alice", "reason": "affiliationChanged"}
    )
    assert r.status_code == 200, r.json
    assert len(r.json["revoked"]) == 2 and r.json["skipped"] == []
    assert {c["status"] for c in _rows(app, username="alice")} == {"revoked"}
    assert _rows(app, username="bob")[0]["status"] == "valid"
    assert _crl_serials(app) == alice_serials
    assert set(kicks) == alice_serials
    assert len(_audit(app, "cert_revoked")) == 2

    # Running it again finds nothing left to revoke
    r = _client(app, "admin").post("/api/certificates/revoke_user", json={"username": "alice"})
    assert r.status_code == 200 and r.json["revoked"] == []


def test_revoke_by_serial_without_a_row(app, kicks):
    r = _client(app, "admin").post(
        "/api/certificates/revoke", json={"serial": "0x0A0B0C", "reason": "keyCompromise"}
    )
    assert r.status_code == 200, r.json
    assert "A0B0C" in _crl_serials(app)
    assert kicks == ["A0B0C"]
    assert _audit(app, "cert_revoked")[0]["details"].startswith("Certificate serial A0B0C")
    assert _client(app, "admin").post(
        "/api/certificates/revoke", json={"serial": "a0b0c"}
    ).status_code == 400


def test_legacy_row_serial_recovered_from_disk(app):
    from raven.models.Certificate import Certificate

    pem = _issue_package(app, "alice")
    with app.app_context():
        db.session.query(Certificate).update({Certificate.serial_number: None})
        db.session.commit()

    rows = _client(app, "admin").get("/api/certificates").json["results"]
    assert rows[0]["serial_number"] == cert_revocation.serial_from_pem(pem)


def test_legacy_row_without_file_cant_be_revoked(app):
    from raven.models.Certificate import Certificate

    _issue_package(app, "alice")
    with app.app_context():
        db.session.query(Certificate).update({Certificate.serial_number: None})
        db.session.commit()
    os.remove(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "alice", "alice.pem"))
    cert_id = _rows(app, username="alice")[0]["id"]

    r = _client(app, "admin").post(f"/api/certificates/{cert_id}/revoke", json={})
    assert r.status_code == 409
    assert _rows(app, username="alice")[0]["status"] == "valid"
    assert _crl_serials(app) == set()


def test_reenrolling_after_revocation_gets_a_working_cert(app):
    r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    _client(app, "admin").post("/api/certificates/revoke_user", json={"username": "alice"})
    r2, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-new")
    assert r2.status_code == 200
    new_serial = format(_signed_cert(r2).serial_number, "X")
    assert not cert_revocation.is_revoked(app.config["RAVEN_CA_FOLDER"], new_serial)
    statuses = {c["serial_number"]: c["status"] for c in _rows(app, username="alice")}
    assert statuses[new_serial] == "valid"
    assert statuses[format(_signed_cert(r1).serial_number, "X")] == "revoked"


# ---------------------------------------------------------------- X-Ssl-Cert (nginx) check


def test_forwarded_revoked_cert_is_rejected(app):
    pem = _issue_package(app, "alice")
    other = _issue_package(app, "bob")
    header = {"X-Ssl-Cert": quote(pem.decode())}
    client = app.test_client()

    assert client.get("/Marti/test/ping", headers=header).status_code == 200

    cert_id = _rows(app, username="alice")[0]["id"]
    _client(app, "admin").post(f"/api/certificates/{cert_id}/revoke", json={})

    r = client.get("/Marti/test/ping", headers=header)
    assert r.status_code == 403
    assert client.get("/Marti/test/ping", headers={"X-Ssl-Cert": quote(other.decode())}).status_code == 200
    # No header (web UI on 443) or a garbage one isn't affected
    assert client.get("/Marti/test/ping").status_code == 200
    assert client.get("/Marti/test/ping", headers={"X-Ssl-Cert": "junk"}).status_code == 200


def test_verify_client_cert_refuses_revoked(app):
    from raven.blueprints.marti_api.marti_api import verify_client_cert

    pem = _issue_package(app, "alice")
    header = {"X-Ssl-Cert": quote(pem.decode())}
    with app.test_request_context("/", headers=header):
        assert verify_client_cert()
    cert_id = _rows(app, username="alice")[0]["id"]
    _client(app, "admin").post(f"/api/certificates/{cert_id}/revoke", json={})
    with app.test_request_context("/", headers=header):
        assert verify_client_cert() is False


# ---------------------------------------------------------------- SSL streaming port


class _ConfigHolder:
    def __init__(self, config):
        self.config = config


def _eud_server(app):
    from raven.eud_handler.EudServerSSL import EudServerSSL

    server = EudServerSSL.__new__(EudServerSSL)
    server.app_context = _ConfigHolder(app.config)
    server.logger = logger
    server._ssl_context = None
    server._crl_key = None
    return server


def _handshake(server_context, ca_folder, username):
    """TLS handshake over a socketpair, client cert certs/<username>; returns the server error."""
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.load_cert_chain(
        os.path.join(ca_folder, "certs", username, username + ".pem"),
        os.path.join(ca_folder, "certs", username, username + ".nopass.key"),
    )
    server_sock, client_sock = socket.socketpair()
    server_sock.settimeout(10)
    client_sock.settimeout(10)
    result = {}

    def serve():
        try:
            tls = server_context.wrap_socket(server_sock, server_side=True)
            result["serial"] = tls.getpeercert()["serialNumber"]
            tls.close()
        except (ssl.SSLError, OSError) as e:
            result["error"] = e

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client_ctx.wrap_socket(client_sock).close()
    except (ssl.SSLError, OSError):
        pass
    thread.join(10)
    server_sock.close()
    client_sock.close()
    return result


def test_streaming_port_rejects_revoked_cert_without_restart(app):
    folder = app.config["RAVEN_CA_FOLDER"]
    _issue_package(app, "alice")
    _issue_package(app, "bob")
    server = _eud_server(app)

    context = server._refresh_ssl_context()
    assert context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert server._refresh_ssl_context() is context  # unchanged CRL, same context
    ok = _handshake(context, folder, "alice")
    assert "error" not in ok, ok
    assert cert_revocation.normalize_serial(ok["serial"]) == _rows(app, username="alice")[0]["serial_number"]

    alice_id = _rows(app, username="alice")[0]["id"]
    assert _client(app, "admin").post(f"/api/certificates/{alice_id}/revoke", json={}).status_code == 200

    reloaded = server._refresh_ssl_context()
    assert reloaded is not context
    failed = _handshake(reloaded, folder, "alice")
    assert "revoked" in str(failed.get("error", "")).lower(), failed
    assert "error" not in _handshake(reloaded, folder, "bob")


def test_streaming_port_without_crl_still_starts(app):
    os.remove(os.path.join(app.config["RAVEN_CA_FOLDER"], "ca.crl"))
    context = _eud_server(app)._refresh_ssl_context()
    assert not context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_streaming_port_regenerates_expired_crl(app, monkeypatch):
    folder = app.config["RAVEN_CA_FOLDER"]
    server = _eud_server(app)
    real = cert_revocation.crl_next_update
    expired = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    calls = []

    def fake_next_update(ca_folder):
        calls.append(ca_folder)
        # The server's check, then ensure_crl's own check, both see the expired CRL
        return expired if len(calls) <= 2 else real(ca_folder)

    monkeypatch.setattr(cert_revocation, "crl_next_update", fake_next_update)
    before = os.stat(os.path.join(folder, "ca.crl")).st_ino
    server._refresh_ssl_context()
    assert os.stat(os.path.join(folder, "ca.crl")).st_ino != before


def test_eud_handler_drops_connection_on_revoke_message():
    from raven.eud_handler.EudHandler import EudHandler

    handler = EudHandler.__new__(EudHandler)
    handler.cert_serial = "186A0"
    handler.uid = "ANDROID-a1"
    handler.callsign = "ALPHA"
    closed = []
    handler.close_connection = lambda: closed.append(True)

    handler.on_control_message(None, None, None, json.dumps({"action": "revoke", "serial": "FFFF"}))
    assert closed == []
    handler.on_control_message(None, None, None, json.dumps({"action": "revoke", "serial": "186A0"}))
    assert closed == [True]
