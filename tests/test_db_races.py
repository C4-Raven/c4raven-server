"""Rows created on first sight by several processes at once, and the one-to-many relationships
that were mapped as one-to-one.

- EUD.certificate / EUD.data_packages / DataPackage.certificate were uselist=False although a
  device gets a Certificate row per enrollment and uploads any number of packages: SQLAlchemy
  picked an arbitrary row and warned "Multiple rows returned with uselist=False" (hundreds of
  times a day in opentakserver.log).
- Chatrooms, chatroom members, teams and EUDs were created by insert-then-catch-IntegrityError
  (PostgreSQL logged each rejected insert as an ERROR) or check-then-insert (the IntegrityError
  of a lost race escaped). raven.db_upsert.insert_ignore does INSERT ... ON CONFLICT DO NOTHING.
- Token.verify_token logged a mistyped Basic-auth password as "ERROR Invalid token".

Minimal sqlite Flask app, as in tests/test_retention_offline_chat.py. Database errors are
counted with an engine handle_error listener, standing in for PostgreSQL's error log.
"""

import datetime
import logging
import os
import warnings

import pytest
import sqlalchemy
from bs4 import BeautifulSoup
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla
from sqlalchemy import event

from raven.defaultconfig import DefaultConfig
from raven.extensions import db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.db_upsert import insert_ignore  # noqa: E402
from raven.models import import_all_models  # noqa: E402

import_all_models()

from raven.models.Certificate import Certificate  # noqa: E402
from raven.models.Chatrooms import Chatroom  # noqa: E402
from raven.models.ChatroomsUids import ChatroomsUids  # noqa: E402
from raven.models.DataPackage import DataPackage  # noqa: E402
from raven.models.EUD import EUD  # noqa: E402
from raven.models.Team import Team  # noqa: E402

UTC = datetime.timezone.utc


@pytest.fixture
def app(tmp_path):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        UPLOAD_FOLDER=str(tmp_path / "uploads"),
        RAVEN_CA_FOLDER=str(tmp_path / "ca"),
        RAVEN_ENABLE_LDAP=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        WTF_CSRF_ENABLED=False,
        SECURITY_PASSWORD_HASH="plaintext",
    )
    db.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    with app.app_context():
        db.create_all()
        app.security.datastore.create_user(username="alice", password=hash_password("pw"))
        db.session.commit()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def db_errors(app):
    """Statements the database rejected while the test ran."""
    errors = []
    with app.app_context():
        engine = db.engine

    def on_error(context):
        errors.append(str(context.original_exception))

    event.listen(engine, "handle_error", on_error)
    yield errors
    event.remove(engine, "handle_error", on_error)


def cert(eud_uid=None, revoked=False, data_package_id=None, name="alice"):
    return Certificate(
        common_name=name, eud_uid=eud_uid, username="alice", data_package_id=data_package_id,
        expiration_date=datetime.datetime(2030, 1, 1), server_address="x", server_port=8089,
        truststore_filename="t", user_cert_filename="u", cert_password="p",
        revoked_at=datetime.datetime(2026, 1, 1) if revoked else None,
    )


def package(n, eud_uid=None):
    return DataPackage(
        filename=f"p{n}.zip", hash=f"h{n}", creator_uid=eud_uid, mime_type="application/zip",
        size=1, submission_time=datetime.datetime(2026, 1, n),
    )


@pytest.fixture
def no_sa_warnings():
    with warnings.catch_warnings():
        warnings.simplefilter("error", sqlalchemy.exc.SAWarning)
        yield


# Issue: "Multiple rows returned with uselist=False" ------------------------------------------


def test_eud_with_several_certificates_and_packages(app, no_sa_warnings):
    with app.app_context():
        db.session.add(EUD(uid="ANDROID-a", callsign="Alpha"))
        db.session.add_all([package(1, "ANDROID-a"), package(2, "ANDROID-a")])
        db.session.commit()
        first = cert("ANDROID-a")
        current = cert("ANDROID-a", data_package_id=1)
        revoked = cert("ANDROID-a", revoked=True)
        db.session.add_all([first, current, revoked])
        db.session.commit()
        current_id = current.id
        db.session.expire_all()

        eud = db.session.query(EUD).filter_by(uid="ANDROID-a").one()
        assert len(eud.certificates) == 3
        # The newest one is revoked: the current certificate is the newest valid one
        assert eud.certificate.id == current_id
        as_json = eud.to_json()
        assert as_json["config_hash"] == "h1"
        assert as_json["data_packages"]["hash"] == "h2"  # the newest package


def test_eud_whose_certificates_are_all_revoked(app, no_sa_warnings):
    with app.app_context():
        db.session.add(EUD(uid="ANDROID-a"))
        db.session.add_all([cert("ANDROID-a", revoked=True), cert("ANDROID-a", revoked=True)])
        db.session.commit()
        newest = db.session.query(Certificate).order_by(Certificate.id.desc()).first().id
        db.session.expire_all()
        assert db.session.get(EUD, 1).certificate.id == newest
        db.session.add(EUD(uid="ANDROID-b"))
        db.session.commit()
        bare = db.session.query(EUD).filter_by(uid="ANDROID-b").one()
        assert bare.certificate is None
        assert bare.to_json()["data_packages"] is None


def test_data_package_reused_by_two_certificates(app, no_sa_warnings):
    with app.app_context():
        db.session.add(package(1))
        db.session.commit()
        db.session.add_all([cert(data_package_id=1), cert(data_package_id=1, revoked=True)])
        db.session.commit()
        db.session.expire_all()
        dp = db.session.query(DataPackage).one()
        assert len(dp.certificates) == 2
        assert dp.certificate.revoked_at is None
        assert dp.certificate.data_package is dp


def test_deleting_an_eud_deletes_all_its_certificates(app, no_sa_warnings):
    with app.app_context():
        db.session.add(EUD(uid="ANDROID-a"))
        db.session.add_all([cert("ANDROID-a"), cert("ANDROID-a"), cert("ANDROID-b")])
        db.session.commit()
        db.session.delete(db.session.query(EUD).one())
        db.session.commit()
        assert [c.eud_uid for c in db.session.query(Certificate)] == ["ANDROID-b"]


# Issue: duplicate key errors from first-sight inserts ---------------------------------------


def test_insert_ignore(app, db_errors):
    with app.app_context():
        assert insert_ignore(db.session, Team, {"name": "Cyan"}, ["name"]) is True
        assert insert_ignore(db.session, Team, {"name": "Cyan"}, ["name"]) is False
        db.session.commit()
        assert db.session.query(Team).count() == 1
    assert db_errors == []


def test_team_and_eud_get_or_create(app, db_errors):
    from raven.eud_handler.EudHandler import EudHandler

    with app.app_context():
        db.session.add(Chatroom(id="Cyan", name="Cyan"))
        db.session.commit()
        team = EudHandler.get_or_create_team("Cyan")
        again = EudHandler.get_or_create_team("Cyan")
        assert team.id == again.id
        assert again.chatroom_id == "Cyan"
        assert db.session.query(Team).count() == 1

        eud, created = EudHandler.get_or_create_eud("ANDROID-a")
        assert created
        eud.callsign = "Alpha"
        db.session.commit()
        eud, created = EudHandler.get_or_create_eud("ANDROID-a")
        assert not created
        assert eud.callsign == "Alpha"
        assert db.session.query(EUD).count() == 1
    assert db_errors == []


def test_team_created_earlier_gets_its_chatroom_linked(app, db_errors):
    from raven.eud_handler.EudHandler import EudHandler

    with app.app_context():
        EudHandler.get_or_create_team("Red")
        db.session.add(Chatroom(id="Red", name="Red"))
        db.session.commit()
        assert EudHandler.get_or_create_team("Red").chatroom_id == "Red"
    assert db_errors == []


def test_geochat_to_an_existing_room_logs_no_database_error(app, db_errors):
    from raven.cot_parser.cot_parser import CoTController

    class Parser:
        context = None
        logger = logging.getLogger("test")
        db = db

    parser = Parser()
    parser.context = app.app_context()
    now = datetime.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def geochat(message_id):
        return BeautifulSoup(
            f'<event uid="GeoChat.ANDROID-a.All Chat Rooms.{message_id}" type="b-t-f" '
            f'time="{now}" start="{now}" stale="{now}"><point lat="0" lon="0"/>'
            '<detail><__chat parent="RootContactGroup" groupOwner="false" chatroom="All Chat Rooms" '
            'id="All Chat Rooms" senderCallsign="Alpha"><chatgrp uid0="ANDROID-a" '
            'uid1="All Chat Rooms" id="All Chat Rooms"/></__chat>'
            f'<remarks time="{now}">hello {message_id}</remarks></detail></event>',
            "xml",
        ).find("event")

    with app.app_context():
        db.session.add(EUD(uid="ANDROID-a"))
        db.session.commit()
    CoTController.parse_geochat(parser, geochat("m1"), None, None)
    CoTController.parse_geochat(parser, geochat("m2"), None, None)
    with app.app_context():
        assert db.session.query(Chatroom).count() == 1
        assert {(m.chatroom_id, m.uid) for m in db.session.query(ChatroomsUids)} == {
            ("All Chat Rooms", "ANDROID-a"),
            ("All Chat Rooms", "All Chat Rooms"),
        }
    # (The GeoChat rows themselves fail on point_id here: no Point/CoT rows in this test)
    assert [e for e in db_errors if "UNIQUE" in e] == []


# Issue: "Token - verify_token - ERROR - Invalid token: Not enough segments" ------------------


def test_password_that_is_not_a_token_is_not_an_error(app, caplog):
    from raven.models.Token import Token

    os.makedirs(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "raven"))
    with open(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "raven", "raven.pub"), "w"):
        pass
    with app.app_context(), caplog.at_level(logging.DEBUG, logger="Raven"):
        assert Token.verify_token("mistyped password", "alice") is False
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert "neither its password nor a token" in caplog.text


def test_token_with_a_bad_signature_is_still_a_warning(app, caplog):
    # InvalidSignatureError is a DecodeError subclass: it mustn't be taken for a mistyped password
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from raven.models.Token import Token

    def pem_pair():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return key, public

    _, server_public = pem_pair()
    other_key, _ = pem_pair()
    os.makedirs(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "raven"))
    with open(os.path.join(app.config["RAVEN_CA_FOLDER"], "certs", "raven", "raven.pub"), "wb") as f:
        f.write(server_public)
    forged = jwt.encode({"sub": "alice", "aud": "Raven"}, other_key, algorithm="RS256")
    with app.app_context(), caplog.at_level(logging.DEBUG, logger="Raven"):
        assert Token.verify_token(forged, "alice") is False
    assert "neither its password nor a token" not in caplog.text
    assert [r for r in caplog.records if r.levelno == logging.WARNING]
