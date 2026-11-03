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


# The real one, before the kicks fixture stubs it out
_real_kick_revoked_sessions = cert_revocation.kick_revoked_sessions


@pytest.fixture
def kicks(monkeypatch):
    sent = []

    def fake_kick(app, serials, logger=None):
        serials = [cert_revocation.normalize_serial(s) for s in serials]
        sent.extend(serials)
        # As if every one of them had a live streaming connection
        return {"sent": True, "connected": serials}

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
    assert r.json["kick_sent"] is True
    assert r.json["sessions_disconnected"] == [serial]

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
    _client(app, "admin").post(
        "/api/certificates/revoke_user", json={"username": "alice", "reset_password": False}
    )
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


# ---------------------------------------------------------------- review fixes (fix/certs)


def _serial_of(response):
    return format(_signed_cert(response).serial_number, "X")


def _cert_id(app, serial):
    return next(c["id"] for c in _rows(app) if c["serial_number"] == serial)


def test_revoked_device_cant_reenroll_until_an_admin_allows_it(app):
    """A lost phone with the user's saved credentials can't enroll for a fresh cert."""
    r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-lost")
    serial = _serial_of(r1)
    admin = _client(app, "admin")
    assert admin.post(f"/api/certificates/{_cert_id(app, serial)}/revoke", json={}).json[
        "enrollment_blocked"
    ] == ["ANDROID-lost"]

    again, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-lost")
    assert again.status_code == 403
    assert "revoked" in again.json["error"]
    blocked = _audit(app, "enroll_blocked")
    assert len(blocked) == 1 and blocked[0]["success"] is False and "ANDROID-lost" in blocked[0]["details"]
    # Nothing was issued for it
    assert [c["serial_number"] for c in _rows(app, eud_uid="ANDROID-lost")] == [serial]

    # The account is still active: a NEW phone enrolls fine
    new_phone, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-new")
    assert new_phone.status_code == 200

    rows = admin.get("/api/certificates", query_string={"username": "alice"}).json["results"]
    assert {c["eud_uid"]: c["enrollment_blocked"] for c in rows} == {
        "ANDROID-lost": True, "ANDROID-new": False,
    }
    blocks = admin.get("/api/certificates/enrollment_blocks").json["results"]
    assert [(b["eud_uid"], b["serial_number"], b["blocked_by"]) for b in blocks] == [
        ("ANDROID-lost", serial, "admin")
    ]

    # Only an admin can lift it
    assert _client(app, "alice").post(
        "/api/certificates/allow_enrollment", json={"eud_uid": "ANDROID-lost"}
    ).status_code == 403
    assert admin.post(
        "/api/certificates/allow_enrollment", json={"eud_uid": "ANDROID-other"}
    ).status_code == 404
    assert admin.post(
        "/api/certificates/allow_enrollment", json={"eud_uid": "ANDROID-lost"}
    ).status_code == 200
    assert _audit(app, "enrollment_unblocked")[0]["actor"] == "admin"

    found, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-lost")
    assert found.status_code == 200


def test_revoked_device_cant_get_a_certificate_package_either(app):
    r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-lost")
    _client(app, "admin").post(f"/api/certificates/{_cert_id(app, _serial_of(r1))}/revoke", json={})
    r = _client(app, "alice").post(
        "/api/certificate", json={"username": "alice", "uid": "ANDROID-lost"}
    )
    assert r.status_code == 403
    assert _client(app, "alice").post("/api/certificate", json={"username": "alice"}).status_code == 200


def test_revoking_a_replaced_cert_doesnt_block_the_device(app):
    old, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    r = _client(app, "admin").post(
        f"/api/certificates/{_cert_id(app, _serial_of(old))}/revoke", json={"reason": "superseded"}
    )
    assert r.status_code == 200 and r.json["enrollment_blocked"] == []
    assert _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")[0].status_code == 200


def test_revoke_can_reset_the_password(app):
    from raven.blueprints.marti_api.certificate_enrollment_api import basic_auth
    from tests.test_cert_issuance_authz import _basic

    r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    r2, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a2")
    admin = _client(app, "admin")

    # Off by default for a single cert
    r = admin.post(f"/api/certificates/{_cert_id(app, _serial_of(r1))}/revoke", json={})
    assert r.json["password_reset"] is None
    with app.test_request_context("/"):
        assert basic_auth(_basic("alice", "alicepass")) == "alice"
    assert _audit(app, "password_reset") == []

    r = admin.post(
        f"/api/certificates/{_cert_id(app, _serial_of(r2))}/revoke", json={"reset_password": True}
    )
    assert r.status_code == 200 and r.json["password_reset"] is True
    with app.test_request_context("/"):
        assert basic_auth(_basic("alice", "alicepass")) is False
        user = app.security.datastore.find_user(username="alice")
        assert user.active and user.force_password_change
    events = _audit(app, "password_reset")
    assert len(events) == 1 and events[0]["username"] == "alice" and events[0]["actor"] == "admin"
    assert events[0]["category"] == "security"


def test_revoke_all_resets_the_password_by_default(app):
    from raven.blueprints.marti_api.certificate_enrollment_api import basic_auth
    from tests.test_cert_issuance_authz import _basic

    _sign(app, "bob", "bobpass", ["bob"], uid="ANDROID-b1")
    r = _client(app, "admin").post("/api/certificates/revoke_user", json={"username": "bob"})
    assert r.status_code == 200 and r.json["password_reset"] is True
    with app.test_request_context("/"):
        assert basic_auth(_basic("bob", "bobpass")) is False
        assert app.security.datastore.find_user(username="bob").active
    assert len(_audit(app, "password_reset")) == 1


def test_reenrolling_keeps_the_revoked_row(app):
    r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    old = _serial_of(r1)
    admin = _client(app, "admin")
    admin.post(f"/api/certificates/{_cert_id(app, old)}/revoke", json={"reason": "keyCompromise"})
    admin.post("/api/certificates/allow_enrollment", json={"eud_uid": "ANDROID-a1"})
    r2, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    assert r2.status_code == 200

    rows = _rows(app, eud_uid="ANDROID-a1")
    assert [(c["serial_number"], c["status"]) for c in rows] == [
        (old, "revoked"), (_serial_of(r2), "valid"),
    ]
    assert rows[0]["revocation_reason"] == "keyCompromise"


def test_reenrolling_device_causes_no_database_errors(app):
    """The device's EUD row already exists on re-enrollment: INSERT ... ON CONFLICT DO NOTHING
    instead of an insert PostgreSQL rejects (and logs as an error, euds_uid_key)."""
    from sqlalchemy import event

    from raven.models.EUD import EUD

    errors = []
    with app.app_context():
        engine = db.engine

    def on_error(context):
        errors.append(str(context.original_exception))

    event.listen(engine, "handle_error", on_error)
    try:
        r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
        r2, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    finally:
        event.remove(engine, "handle_error", on_error)
    assert r1.status_code == 200 and r2.status_code == 200
    assert errors == []
    with app.app_context():
        eud = db.session.query(EUD).filter_by(uid="ANDROID-a1").one()
        assert eud.user_id is not None
        assert eud.certificate.serial_number == _serial_of(r2)
        assert len(eud.certificates) == 2


def test_reenrolling_never_overwrites_a_revoked_row_even_with_a_unique_eud_uid(app):
    """A database with a unique constraint on certificates.eud_uid (the migration drops it)
    takes the IntegrityError fallback: it may reuse a valid row but never the revoked one."""
    from sqlalchemy import text

    with app.app_context():
        db.session.execute(text("CREATE UNIQUE INDEX uq_cert_eud ON certificates (eud_uid)"))
        db.session.commit()
    r1, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    r2, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    assert r2.status_code == 200
    assert [c["serial_number"] for c in _rows(app, eud_uid="ANDROID-a1")] == [_serial_of(r2)]

    admin = _client(app, "admin")
    admin.post(f"/api/certificates/{_cert_id(app, _serial_of(r2))}/revoke", json={})
    admin.post("/api/certificates/allow_enrollment", json={"eud_uid": "ANDROID-a1"})
    r3, _ = _sign(app, "alice", "alicepass", ["alice"], uid="ANDROID-a1")
    assert r3.status_code == 500
    rows = _rows(app, eud_uid="ANDROID-a1")
    assert [(c["serial_number"], c["status"]) for c in rows] == [(_serial_of(r2), "revoked")]


def _legacy_row(app, username, serial, common_name=None):
    from raven.models.Certificate import Certificate

    with app.app_context():
        cert = Certificate(
            common_name=common_name or username or "unknown",
            username=username,
            expiration_date=datetime.datetime.now() + datetime.timedelta(days=30),
            server_address="localhost",
            server_port=8089,
            truststore_filename="x",
            user_cert_filename="x",
            cert_password="x",
            serial_number=serial,
        )
        db.session.add(cert)
        db.session.commit()
        return cert.id


def test_shared_legacy_serial_needs_confirmation(app, kicks):
    alice_id = _legacy_row(app, "alice", "1869F")
    _legacy_row(app, "bob", "1869F")
    admin = _client(app, "admin")

    for r in (
        admin.post("/api/certificates/revoke", json={"serial": "1869f"}),
        admin.post(f"/api/certificates/{alice_id}/revoke", json={}),
    ):
        assert r.status_code == 409
        assert r.json["shared_serial"] == "1869F"
        assert "alice" in r.json["error"] and "bob" in r.json["error"]
    assert kicks == [] and _crl_serials(app) == set()

    r = admin.post("/api/certificates/revoke", json={"serial": "1869F", "confirm_shared_serial": True})
    assert r.status_code == 200
    assert {c["status"] for c in _rows(app)} == {"revoked"}

    # A unique legacy serial doesn't need it
    carol_id = _legacy_row(app, "alice", "2710")
    assert admin.post(f"/api/certificates/{carol_id}/revoke", json={}).status_code == 200


def test_by_serial_revoke_checks_protected_common_name(app):
    _legacy_row(app, None, "ABCDEF123456", common_name="Admin")
    admin = _client(app, "admin")
    assert admin.post("/api/certificates/revoke", json={"serial": "ABCDEF123456"}).status_code == 403
    assert _crl_serials(app) == set()
    assert _client(app, "Admin").post(
        "/api/certificates/revoke", json={"serial": "ABCDEF123456"}
    ).status_code == 200


def test_ca_password_never_on_the_command_line(app, monkeypatch):
    import subprocess as real_subprocess

    from raven import certificate_authority

    calls = []
    real_call = real_subprocess.call

    def spy(command, *args, **kwargs):
        calls.append((command, kwargs.get("env") or {}))
        return real_call(command, *args, **kwargs)

    monkeypatch.setattr(certificate_authority.subprocess, "call", spy)
    _issue_package(app, "alice")
    openssl = [(c, env) for c, env in calls if "pass" in c]
    assert openssl
    for command, env in openssl:
        assert CA_PASSWORD not in command, command
        assert "pass:" not in command
        assert env.get("RAVEN_CA_PASS") == CA_PASSWORD


# ---------------------------------------------------------------- kick reaches every connection


class _FakeChannel:
    def __init__(self):
        self.is_open = True
        self.binds = []
        self.consumers = []

    def queue_declare(self, queue, **kwargs):
        pass

    def queue_bind(self, exchange, queue, routing_key):
        self.binds.append((exchange, queue, routing_key))

    def basic_consume(self, queue, on_message_callback, auto_ack):
        self.consumers.append((queue, on_message_callback))
        return "tag"


def _handler(app, serial=None):
    from raven.eud_handler.EudHandler import EudHandler

    handler = EudHandler.__new__(EudHandler)
    handler.app = app
    handler.conn_token = "tok"
    handler.cert_serial = serial
    handler.uid = None  # never sent a contact event
    handler.callsign = None
    handler.rabbit_channel = None
    closed = []
    handler.close_connection = lambda: closed.append(True)
    return handler, closed


@pytest.mark.parametrize("channel_first", [True, False])
def test_cert_control_queue_bound_without_a_uid(app, channel_first):
    handler, closed = _handler(app)
    channel = _FakeChannel()
    if channel_first:
        handler.rabbit_channel = channel
        handler.bind_cert_control_queue()  # on_channel_open, serial not known yet
        assert channel.binds == []
        handler.cert_serial = "186A0"
        handler.bind_cert_control_queue()  # after the handshake
    else:
        handler.cert_serial = "186A0"
        handler.bind_cert_control_queue()  # channel not open yet
        handler.rabbit_channel = channel
        handler.bind_cert_control_queue()
    handler.bind_cert_control_queue()  # idempotent
    assert [b[2] for b in channel.binds] == [cert_revocation.CERT_ROUTING_PREFIX + "186A0"]
    queue, callback = channel.consumers[0]
    callback(None, None, None, json.dumps({"action": "revoke", "serial": "186A0"}))
    assert closed == [True]


def test_cert_control_queue_drops_cert_revoked_during_handshake(app):
    pem = _issue_package(app, "alice")
    serial = cert_revocation.serial_from_pem(pem)
    _client(app, "admin").post(f"/api/certificates/{_rows(app, username='alice')[0]['id']}/revoke", json={})
    handler, closed = _handler(app, serial)
    handler.rabbit_channel = _FakeChannel()
    handler.bind_cert_control_queue()
    assert closed == [True]


def test_kick_reports_which_sessions_were_live(app, monkeypatch):
    import pika
    from pika.exceptions import UnroutableError

    published = []

    class FakeChannel:
        def confirm_delivery(self):
            published.append("confirm")

        def exchange_declare(self, *a, **k):
            pass

        def basic_publish(self, exchange, routing_key, body, properties=None, mandatory=False):
            assert mandatory
            published.append(routing_key)
            if routing_key.endswith("DEAD"):
                raise UnroutableError([])

        def close(self):
            pass

    class FakeConnection:
        is_open = True

        def __init__(self, params):
            pass

        def channel(self):
            return FakeChannel()

        def close(self):
            pass

    monkeypatch.setattr(pika, "BlockingConnection", FakeConnection)
    assert _real_kick_revoked_sessions(app, ["beef", "dead"]) == {"sent": True, "connected": ["BEEF"]}
    assert published == ["confirm", "cert.BEEF", "cert.DEAD"]

    def broken(params):
        raise ConnectionError("no broker")

    monkeypatch.setattr(pika, "BlockingConnection", broken)
    assert _real_kick_revoked_sessions(app, ["beef"]) == {"sent": False, "connected": []}


# ---------------------------------------------------------------- CRL expiry checks


def test_streaming_port_checks_crl_expiry_even_when_unchanged(app, monkeypatch):
    import time as time_module

    folder = app.config["RAVEN_CA_FOLDER"]
    server = _eud_server(app)
    context = server._refresh_ssl_context()
    assert server._refresh_ssl_context() is context

    real = cert_revocation.crl_next_update
    soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5)
    calls = []

    def fake_next_update(ca_folder):
        calls.append(ca_folder)
        return soon if len(calls) <= 2 else real(ca_folder)

    monkeypatch.setattr(cert_revocation, "crl_next_update", fake_next_update)
    # Within the interval nothing is checked
    assert server._refresh_ssl_context() is context
    assert calls == []

    before = os.stat(os.path.join(folder, "ca.crl")).st_ino
    server._crl_checked_at = time_module.monotonic() - server.CRL_CHECK_INTERVAL - 1
    reloaded = server._refresh_ssl_context()
    assert os.stat(os.path.join(folder, "ca.crl")).st_ino != before
    assert reloaded is not context


def test_crl_regeneration_failure_is_audited(app, monkeypatch):
    import time as time_module

    server = _eud_server(app)
    server.app_context = app
    server._refresh_ssl_context()
    expired = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    monkeypatch.setattr(cert_revocation, "crl_next_update", lambda folder: expired)

    def broken(*args, **kwargs):
        raise RuntimeError("bad CA password")

    monkeypatch.setattr(cert_revocation, "ensure_crl", broken)
    server._crl_checked_at = time_module.monotonic() - server.CRL_CHECK_INTERVAL - 1
    server._refresh_ssl_context()
    events = _audit(app, "crl_refresh_failed")
    assert len(events) == 1 and events[0]["success"] is False
    assert "bad CA password" in events[0]["details"] and "expired" in events[0]["details"]


def test_refresh_crl_job_failure_is_audited(app, monkeypatch):
    from raven.blueprints import scheduled_jobs
    from raven.extensions import apscheduler

    monkeypatch.setattr(apscheduler, "app", app, raising=False)

    def broken(*args, **kwargs):
        raise RuntimeError("openssl ca -gencrl failed")

    monkeypatch.setattr(cert_revocation, "ensure_crl", broken)
    scheduled_jobs.refresh_crl()
    events = _audit(app, "crl_refresh_failed")
    assert len(events) == 1 and "gencrl failed" in events[0]["details"]
