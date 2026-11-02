"""Group policies: default access, auto-join, membership expiry, lock, and the
"groups" audit events (raven/group_policy.py, raven/blueprints/raven_api/group_api.py).

Minimal sqlite Flask app, as in tests/test_user_visibility.py: no RabbitMQ,
Postgres or scheduler.
"""

import datetime
import time

import pytest
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven import group_policy  # noqa: E402
from raven.audit import init_audit  # noqa: E402
from raven.blueprints.raven_api.group_api import group_api  # noqa: E402
from raven.blueprints.raven_api.user_api import user_api_blueprint  # noqa: E402
from raven.models.AuditEvent import AuditEvent  # noqa: E402
from raven.models.Group import Group  # noqa: E402
from raven.models.GroupUser import GroupUser  # noqa: E402


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
    )
    db.init_app(app)
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    init_audit(app)
    app.register_blueprint(group_api)
    app.register_blueprint(user_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("x"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("x"), roles=["user"])
        ds.create_user(username="bob", password=hash_password("x"), roles=["user"])
        ds.create_user(username="Server", password=hash_password("x"), roles=["user"])
        ds.create_user(username="gone", password=hash_password("x"), roles=["user"], active=False)
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def admin(app):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username="admin").fs_uniquifier
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()
    return client


def make_group(admin, name="team", **policy):
    r = admin.post("/api/groups", json={"name": name, "description": "d", **policy})
    assert r.status_code == 200, r.json
    return r


def members(admin, group="team"):
    r = admin.get("/api/groups/members", query_string={"name": group})
    assert r.status_code == 200, r.json
    out = {}
    for row in r.json:
        out.setdefault(row["username"], set()).add(row["direction"])
    return out


def rows(app, group="team"):
    with app.app_context():
        g = db.session.query(Group).filter_by(name=group).one()
        return [
            (r.user.username, r.direction, r.expires_at)
            for r in db.session.query(GroupUser).filter_by(group_id=g.id)
        ]


def events(app, action=None):
    with app.app_context():
        q = db.session.query(AuditEvent).filter_by(category="groups")
        if action:
            q = q.filter_by(action=action)
        return [e.to_json() for e in q.order_by(AuditEvent.id)]


def get_group(admin, name="team"):
    r = admin.get("/api/groups", query_string={"name": name})
    assert r.status_code == 200, r.json
    return next(g for g in r.json["results"] if g["name"] == name)


# --- create / policy edit ---


def test_create_with_policies_and_listing(admin, app):
    make_group(admin, default_access="OUT", auto_join=True, default_membership_days=7, locked=False)
    g = get_group(admin)
    assert g["default_access"] == "OUT"
    assert g["auto_join"] is True
    assert g["default_membership_days"] == 7
    assert g["locked"] is False
    assert g["member_count"] == 0
    [ev] = events(app, "group_created")
    assert ev["actor"] == "admin" and "team" in ev["details"]


def test_defaults_when_no_policy_given(admin):
    make_group(admin)
    g = get_group(admin)
    assert g["default_access"] == "both"
    assert g["auto_join"] is False and g["locked"] is False
    assert g["default_membership_days"] is None


@pytest.mark.parametrize(
    "bad",
    [
        {"default_access": "sideways"},
        {"auto_join": "yes"},
        {"locked": 1},
        {"default_membership_days": -1},
        {"default_membership_days": 99999},
        {"default_membership_days": "7"},
    ],
)
def test_policy_validation(admin, bad):
    make_group(admin)
    r = admin.patch("/api/groups/policy", json={"group_name": "team", **bad})
    assert r.status_code == 400
    r = admin.post("/api/groups", json={"name": "other", **bad})
    assert r.status_code == 400


def test_patch_policy_records_only_changes(admin, app):
    make_group(admin)
    r = admin.patch(
        "/api/groups/policy",
        json={"group_name": "team", "default_access": "IN", "auto_join": True, "locked": False},
    )
    assert r.status_code == 200, r.json
    assert r.json["group"]["default_access"] == "IN"
    [ev] = events(app, "group_policy_changed")
    assert "Default access: send only" in ev["details"] and "Auto join: True" in ev["details"]
    assert "Locked" not in ev["details"]  # unchanged
    # No-op patch: no new event
    admin.patch("/api/groups/policy", json={"group_name": "team", "default_access": "IN"})
    assert len(events(app, "group_policy_changed")) == 1
    # Clearing the duration
    admin.patch("/api/groups/policy", json={"group_name": "team", "default_membership_days": 3})
    admin.patch("/api/groups/policy", json={"group_name": "team", "default_membership_days": None})
    assert get_group(admin)["default_membership_days"] is None


def test_policy_requires_admin(app):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username="alice").fs_uniquifier
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_paa"] = time.time()
    r = client.patch("/api/groups/policy", json={"group_name": "__ANON__", "locked": True})
    assert r.status_code in (401, 403)


def test_ldap_refuses_policy_endpoints(admin, app):
    make_group(admin)
    app.config["RAVEN_ENABLE_LDAP"] = True
    assert admin.patch("/api/groups/policy", json={"group_name": "team", "locked": True}).status_code == 400
    assert admin.post("/api/groups/policy/apply", json={"group_name": "team"}).status_code == 400
    assert admin.patch(
        "/api/groups/members", json={"group_name": "team", "username": "alice", "access": "IN"}
    ).status_code == 400


def test_pairwise_groups_refused(admin, app):
    with app.app_context():
        g = Group()
        g.name = "__uv__alice__bob"
        g.type = Group.SYSTEM
        db.session.add(g)
        db.session.commit()
    r = admin.patch("/api/groups/policy", json={"group_name": "__uv__alice__bob", "locked": True})
    assert r.status_code == 400
    r = admin.put("/api/groups", json={"users": ["alice"], "group_name": "__uv__alice__bob", "direction": "IN"})
    assert r.status_code == 400


# --- members: add (BOTH), access change, expiry ---


def test_add_both_in_one_request_and_audit(admin, app):
    make_group(admin)
    r = admin.put("/api/groups", json={"users": ["alice", "bob"], "group_name": "team", "direction": "BOTH"})
    assert r.status_code == 200, r.json
    assert members(admin) == {"alice": {"IN", "OUT"}, "bob": {"IN", "OUT"}}
    evs = events(app, "member_added")
    assert [e["username"] for e in evs] == ["alice", "bob"]
    assert all("send & receive" in e["details"] and e["actor"] == "admin" for e in evs)
    # Re-adding is a no-op, no duplicate event
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "IN"})
    assert len(events(app, "member_added")) == 2


def test_add_uses_group_default_duration_unless_overridden(admin, app):
    make_group(admin, default_membership_days=2)
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "IN"})
    admin.put(
        "/api/groups",
        json={"users": ["bob"], "group_name": "team", "direction": "IN", "expires_at": None},
    )
    by_user = {u: exp for u, _, exp in rows(app)}
    soon = datetime.datetime.utcnow() + datetime.timedelta(days=2)
    assert abs((by_user["alice"] - soon).total_seconds()) < 60
    assert by_user["bob"] is None


def test_add_rejects_past_expiry(admin):
    make_group(admin)
    r = admin.put(
        "/api/groups",
        json={"users": ["alice"], "group_name": "team", "direction": "IN",
              "expires_at": "2000-01-01T00:00:00Z"},
    )
    assert r.status_code == 400


def test_patch_member_access(admin, app):
    make_group(admin)
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "BOTH"})
    r = admin.patch("/api/groups/members", json={"group_name": "team", "username": "alice", "access": "OUT"})
    assert r.status_code == 200, r.json
    assert members(admin) == {"alice": {"OUT"}}
    r = admin.patch("/api/groups/members", json={"group_name": "team", "username": "alice", "access": "IN"})
    assert members(admin) == {"alice": {"IN"}}
    evs = events(app, "member_access_changed")
    assert len(evs) == 2
    assert "send & receive → receive only" in evs[0]["details"]
    assert "receive only → send only" in evs[1]["details"]


def test_patch_member_expiry_set_and_clear(admin, app):
    make_group(admin)
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "BOTH"})
    when = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=5)).replace(microsecond=0)
    r = admin.patch(
        "/api/groups/members",
        json={"group_name": "team", "username": "alice", "expires_at": when.isoformat()},
    )
    assert r.status_code == 200, r.json
    r = admin.get("/api/groups/members", query_string={"name": "team"})
    assert {row["expires_at"] for row in r.json} == {when.isoformat()}
    r = admin.patch("/api/groups/members", json={"group_name": "team", "username": "alice", "expires_at": None})
    assert all(exp is None for _, _, exp in rows(app))
    assert len(events(app, "member_access_changed")) == 2


def test_patch_member_not_member(admin):
    make_group(admin)
    r = admin.patch("/api/groups/members", json={"group_name": "team", "username": "bob", "access": "IN"})
    assert r.status_code == 404


def test_remove_member_audit(admin, app):
    make_group(admin)
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "BOTH"})
    r = admin.delete("/api/groups/members", query_string={"username": "alice", "group_name": "team", "direction": "IN"})
    assert r.status_code == 200, r.json
    assert events(app, "member_access_changed")  # one side of two removed
    r = admin.delete("/api/groups/members", query_string={"username": "alice", "group_name": "team", "direction": "BOTH"})
    assert r.status_code == 200, r.json
    assert members(admin) == {}
    [ev] = events(app, "member_removed")
    assert ev["username"] == "alice" and ev["actor"] == "admin"


# --- auto-join ---


def test_auto_join_on_admin_create_user(admin, app):
    make_group(admin, name="ops", auto_join=True, default_access="OUT", default_membership_days=1)
    make_group(admin, name="quiet")
    r = admin.post(
        "/api/user/add",
        json={"username": "carol", "password": "Passw0rd!Passw0rd", "confirm_password": "Passw0rd!Passw0rd"},
    )
    assert r.status_code == 200, r.json
    assert members(admin, "ops") == {"carol": {"OUT"}}
    assert members(admin, "quiet") == {}
    [(_, _, exp)] = rows(app, "ops")
    assert exp is not None
    [ev] = events(app, "member_added")
    assert ev["username"] == "carol" and "Auto-join" in ev["details"] and ev["actor"] == "admin"


def test_apply_auto_join_helper_skips_ldap(app):
    with app.app_context():
        g = Group()
        g.name = "ops"
        g.type = Group.SYSTEM
        g.auto_join = True
        db.session.add(g)
        db.session.commit()
        user = app.security.datastore.find_user(username="alice")
        app.config["RAVEN_ENABLE_LDAP"] = True
        assert group_policy.apply_auto_join(user) == []
        app.config["RAVEN_ENABLE_LDAP"] = False
        assert group_policy.apply_auto_join(user) == ["ops"]
        assert group_policy.apply_auto_join(user) == []  # idempotent


def test_apply_to_existing_users(admin, app):
    make_group(admin, default_access="IN")
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "OUT"})
    r = admin.post("/api/groups/policy/apply", json={"group_name": "team"})
    assert r.status_code == 200, r.json
    # admin and bob added; alice already a member (keeps her access); Server is
    # protected, "gone" is deactivated
    assert r.json["added"] == ["admin", "bob"]
    assert members(admin) == {"alice": {"OUT"}, "admin": {"IN"}, "bob": {"IN"}}


# --- expiry job ---


def test_expiry_removes_only_expired(admin, app):
    make_group(admin)
    admin.put("/api/groups", json={"users": ["alice", "bob", "admin"], "group_name": "team", "direction": "BOTH"})
    now = group_policy.utcnow()
    with app.app_context():
        g = db.session.query(Group).filter_by(name="team").one()
        for row in db.session.query(GroupUser).filter_by(group_id=g.id):
            if row.user.username == "alice":
                row.expires_at = now - datetime.timedelta(minutes=1)
            elif row.user.username == "bob":
                row.expires_at = now + datetime.timedelta(days=1)
        db.session.commit()
        assert group_policy.expire_memberships() == 2
        assert group_policy.expire_memberships() == 0
    assert members(admin) == {"bob": {"IN", "OUT"}, "admin": {"IN", "OUT"}}
    [ev] = events(app, "membership_expired")
    assert ev["username"] == "alice" and ev["actor"] == "system"
    assert "send & receive" in ev["details"]


def test_expiry_unbinds_connected_euds(admin, app, monkeypatch):
    calls = []
    monkeypatch.setattr(group_policy, "unbind_euds", lambda user, name, dirs: calls.append((user.username, name, sorted(dirs))))
    make_group(admin)
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "BOTH"})
    with app.app_context():
        for row in db.session.query(GroupUser):
            row.expires_at = group_policy.utcnow() - datetime.timedelta(seconds=1)
        db.session.commit()
        group_policy.expire_memberships()
    assert calls == [("alice", "team", ["IN", "OUT"])]


def test_scheduled_job_runs_expiry(admin, app, monkeypatch):
    from raven.blueprints import scheduled_jobs

    class FakeScheduler:
        pass

    fake = FakeScheduler()
    fake.app = app
    monkeypatch.setattr(scheduled_jobs, "apscheduler", fake)
    make_group(admin)
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "IN"})
    with app.app_context():
        for row in db.session.query(GroupUser):
            row.expires_at = group_policy.utcnow() - datetime.timedelta(seconds=1)
        db.session.commit()
    scheduled_jobs.expire_group_memberships()
    assert members(admin) == {}


def test_expiry_job_is_configured_and_described():
    from raven.blueprints.raven_api.scheduler_api import JOB_DESCRIPTIONS

    job = next(j for j in DefaultConfig.JOBS if j["id"] == "expire_group_memberships")
    assert job["func"] == "raven.blueprints.scheduled_jobs:expire_group_memberships"
    assert "next_run_time" not in job  # runs, not paused
    assert JOB_DESCRIPTIONS["expire_group_memberships"]


def test_new_job_added_to_old_config_snapshot():
    from raven.app import add_new_jobs_to_config

    cfg = Flask("cfg")
    cfg.config["JOBS"] = [{"id": "purge_data", "func": "x:y", "trigger": "interval", "minutes": 1}]
    add_new_jobs_to_config(cfg)
    add_new_jobs_to_config(cfg)
    assert [j["id"] for j in cfg.config["JOBS"]] == [
        "purge_data",
        "expire_group_memberships",
        "record_metrics_sample",
        "apply_data_retention",
        "refresh_crl",
    ]


# --- lock ---


def test_locked_group_refuses_changes_and_deletion(admin, app):
    make_group(admin)
    admin.put("/api/groups", json={"users": ["alice"], "group_name": "team", "direction": "BOTH"})
    admin.patch("/api/groups/policy", json={"group_name": "team", "locked": True})

    assert admin.put("/api/groups", json={"users": ["bob"], "group_name": "team", "direction": "IN"}).status_code == 403
    assert admin.delete("/api/groups/members", query_string={"username": "alice", "group_name": "team", "direction": "IN"}).status_code == 403
    assert admin.patch("/api/groups/members", json={"group_name": "team", "username": "alice", "access": "IN"}).status_code == 403
    assert admin.post("/api/groups/policy/apply", json={"group_name": "team"}).status_code == 403
    assert admin.delete("/api/groups", query_string={"group_name": "team"}).status_code == 403
    assert members(admin) == {"alice": {"IN", "OUT"}}

    # Policies (including unlocking) still editable; then changes work again
    assert admin.patch("/api/groups/policy", json={"group_name": "team", "locked": False}).status_code == 200
    assert admin.delete("/api/groups", query_string={"group_name": "team"}).status_code == 200
    [ev] = events(app, "group_deleted")
    assert "team" in ev["details"] and ev["actor"] == "admin"


def test_locked_group_still_auto_joins_and_expires(admin, app):
    make_group(admin, auto_join=True, locked=True)
    with app.app_context():
        user = app.security.datastore.find_user(username="bob")
        assert group_policy.apply_auto_join(user) == ["team"]
        for row in db.session.query(GroupUser):
            row.expires_at = group_policy.utcnow() - datetime.timedelta(seconds=1)
        db.session.commit()
        assert group_policy.expire_memberships() == 2


def test_anon_still_undeletable(admin, app):
    with app.app_context():
        g = Group()
        g.name = "__ANON__"
        g.type = Group.SYSTEM
        db.session.add(g)
        db.session.commit()
    assert admin.delete("/api/groups", query_string={"group_name": "__ANON__"}).status_code == 400
