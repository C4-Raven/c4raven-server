"""
Tests for streaming (SSL CoT port) authentication in EudHandler.handle_auth.

Builds a minimal Flask app on sqlite, the same way tests/test_vpn_onboarding.py does, and drives
handle_auth() on a handler instance that never touches a socket or RabbitMQ.
"""

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import db

# The User model needs Flask-Security's model mixins bound to Raven's db first
try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.defaultconfig import DefaultConfig
from raven.eud_handler.EudHandler import EudHandler, authenticate_eud_credentials
from raven.models.EUD import EUD
from raven.models.Token import Token


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

    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_CA_FOLDER=str(ca),
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

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
        ds.create_user(
            username="mallory", password=hash_password("mallorypass"), roles=["user"], active=False
        )
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


class _Handler(EudHandler):
    """EudHandler without the socket/RabbitMQ setup; records close_connection() calls."""

    is_ssl = True

    def __init__(self, app, common_name=None):
        self.app = app
        self.common_name = common_name
        self.is_authenticated = False
        self.user = None
        self.callsign = None
        self.closed = False

    def close_connection(self):
        self.closed = True


def _auth(username, password, uid="ANDROID-test"):
    return f'<auth><cot username="{username}" password="{password}" uid="{uid}"/></auth>'


def _make_token(username, max_uses=None, total_uses=0) -> str:
    token = Token()
    token.creation = int(time.time())
    token.username = username
    token.max_uses = max_uses
    token.total_uses = total_uses
    token.hash_token()
    db.session.add(token)
    db.session.commit()
    return token.generate_token()


def _accepted_as(handler):
    return handler.user.username if handler.is_authenticated and not handler.closed else None


# ---------------------------------------------------------------- cert only (no <auth>)


def test_cert_only_identifies_by_common_name(app):
    h = _Handler(app, common_name="alice")
    h.handle_auth("")
    assert _accepted_as(h) == "alice"


def test_cert_only_unknown_common_name_rejected(app):
    h = _Handler(app, common_name="nobody")
    h.handle_auth("")
    assert h.closed and not h.is_authenticated


def test_cert_only_deactivated_user_rejected(app):
    h = _Handler(app, common_name="mallory")
    h.handle_auth("")
    assert h.closed and not h.is_authenticated


# ---------------------------------------------------------------- <auth> with a client cert


def test_auth_with_cert_does_not_skip_password_check(app):
    # The reported bug: any CA-signed cert let <auth> claim any username without a valid password
    h = _Handler(app, common_name="alice")
    h.handle_auth(_auth("admin", "wrong"))
    assert h.closed and not h.is_authenticated


def test_auth_username_must_match_cert(app):
    # Even with a valid password, a cert issued to alice can't stream as admin
    h = _Handler(app, common_name="alice")
    h.handle_auth(_auth("admin", "adminpass"))
    assert h.closed and not h.is_authenticated


def test_auth_matching_cert_and_password_accepted(app):
    h = _Handler(app, common_name="alice")
    h.handle_auth(_auth("alice", "alicepass", uid="ANDROID-alice"))
    assert _accepted_as(h) == "alice"
    with app.app_context():
        eud = db.session.query(EUD).filter_by(uid="ANDROID-alice").one()
        assert eud.user_id == h.user.id


def test_auth_after_cert_login_is_ignored(app):
    # ATAK with useAuth sends <auth> after the cert already identified the connection
    h = _Handler(app, common_name="alice")
    h.handle_auth("")
    h.handle_auth(_auth("admin", "wrong"))
    assert _accepted_as(h) == "alice"


# ---------------------------------------------------------------- <auth> without a cert CN


def test_auth_without_cert_cn_checks_password(app):
    good = _Handler(app)
    good.handle_auth(_auth("admin", "adminpass"))
    assert _accepted_as(good) == "admin"

    bad = _Handler(app)
    bad.handle_auth(_auth("admin", "alicepass"))
    assert bad.closed and not bad.is_authenticated

    missing = _Handler(app)
    missing.handle_auth("<auth><cot uid='x'/></auth>")
    assert missing.closed and not missing.is_authenticated


def test_auth_deactivated_user_rejected(app):
    h = _Handler(app)
    h.handle_auth(_auth("mallory", "mallorypass"))
    assert h.closed and not h.is_authenticated


def test_enrollment_token_accepted_without_consuming(app):
    with app.app_context():
        token = _make_token("alice", max_uses=1, total_uses=1)  # already used by enrollment

    for _ in range(2):  # reconnects keep working
        h = _Handler(app, common_name="alice")
        h.handle_auth(_auth("alice", token))
        assert _accepted_as(h) == "alice"

    with app.app_context():
        assert db.session.query(Token).filter_by(username="alice").one().total_uses == 1


def test_enrollment_token_for_another_user_rejected(app):
    with app.app_context():
        token = _make_token("alice")
    h = _Handler(app)
    h.handle_auth(_auth("admin", token))
    assert h.closed and not h.is_authenticated


def test_authenticate_eud_credentials(app):
    with app.app_context():
        assert authenticate_eud_credentials(app, "alice", "alicepass").username == "alice"
        assert authenticate_eud_credentials(app, "alice", "") is None
        assert authenticate_eud_credentials(app, "alice", None) is None
        assert authenticate_eud_credentials(app, "nobody", "x") is None
