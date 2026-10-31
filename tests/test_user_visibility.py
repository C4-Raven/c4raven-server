"""Visibility diagram: one-way connections must actually be one-way.

Redrawing a two-way connection as one-way used to leave the reverse grants in
the pairwise group, so it stayed two-way.
"""

import time

import pytest
from flask import Flask
from flask_babel import Babel
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.defaultconfig import DefaultConfig
from raven.extensions import db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.blueprints.raven_api.group_api import group_api  # noqa: E402


@pytest.fixture
def admin(tmp_path):
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
    Babel(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(group_api)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("x"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("x"), roles=["user"])
        ds.create_user(username="bob", password=hash_password("x"), roles=["user"])
        db.session.commit()
        uniquifier = ds.find_user(username="admin").fs_uniquifier

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()
    yield client

    with app.app_context():
        db.session.remove()
        db.drop_all()


def edge(client, a, b):
    r = client.get("/api/users/visibility")
    assert r.status_code == 200, r.json
    matches = [e for e in r.json if {e["source"], e["target"]} == {a, b}]
    return matches[0] if matches else None


def connect(client, source, target, kind):
    r = client.put(
        "/api/users/visibility", json={"source": source, "target": target, "type": kind}
    )
    assert r.status_code == 200, r.json


def test_one_way_connection(admin):
    connect(admin, "alice", "bob", "dotted")
    e = edge(admin, "alice", "bob")
    assert (e["source"], e["target"], e["type"]) == ("alice", "bob", "dotted")


def test_two_way_redrawn_as_one_way(admin):
    connect(admin, "alice", "bob", "solid")
    assert edge(admin, "alice", "bob")["type"] == "solid"
    connect(admin, "bob", "alice", "dotted")
    e = edge(admin, "alice", "bob")
    assert (e["source"], e["target"], e["type"]) == ("bob", "alice", "dotted")


def test_one_way_arrow_flipped(admin):
    connect(admin, "alice", "bob", "dotted")
    connect(admin, "bob", "alice", "dotted")
    e = edge(admin, "alice", "bob")
    assert (e["source"], e["target"], e["type"]) == ("bob", "alice", "dotted")


def _add_named_group(admin, users):
    from raven.extensions import db
    from raven.models.Group import Group
    from raven.models.GroupUser import GroupUser
    from raven.models.user import User

    app = admin.application
    with app.app_context():
        group = Group()
        group.name = "Shared"
        group.type = Group.SYSTEM
        db.session.add(group)
        db.session.commit()
        for name in users:
            user = db.session.execute(db.select(User).filter_by(username=name)).scalar_one()
            for direction in (Group.IN, Group.OUT):
                membership = GroupUser()
                membership.user_id = user.id
                membership.group_id = group.id
                membership.direction = direction
                db.session.add(membership)
        db.session.commit()


def test_one_way_overridden_by_shared_group_is_reported(admin):
    _add_named_group(admin, ["alice", "bob"])
    r = admin.put(
        "/api/users/visibility", json={"source": "alice", "target": "bob", "type": "dotted"}
    )
    assert r.status_code == 200, r.json
    assert r.json["overridden_by"] == ["Shared"]
    e = edge(admin, "alice", "bob")
    assert e["type"] == "solid"
    assert e["source_groups"] == ["Shared"] and e["target_groups"] == ["Shared"]


def test_one_way_not_overridden_reports_nothing(admin):
    r = admin.put(
        "/api/users/visibility", json={"source": "alice", "target": "bob", "type": "dotted"}
    )
    assert r.json["overridden_by"] == []
