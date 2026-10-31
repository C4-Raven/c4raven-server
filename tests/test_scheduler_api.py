"""
Tests for the scheduler admin API (raven/blueprints/raven_api/scheduler_api.py) and the
startup handling of config JOBS vs the persistent SQL job store (raven/app.py).

Uses a minimal Flask app with the real global `apscheduler` bound to a sqlite SQLJobStore.
The jobs point at a no-op function in this module so nothing real runs.
"""

import time
from datetime import datetime, timedelta, timezone

import pytest
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import apscheduler, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.app import (
    REMOVED_SCHEDULER_JOB_IDS,
    drop_removed_jobs_from_config,
    remove_obsolete_scheduler_jobs,
)
from raven.blueprints.raven_api.scheduler_api import (
    JOB_DESCRIPTIONS,
    describe_repeat,
    describe_trigger,
    scheduler_api_blueprint,
)
from raven.defaultconfig import DefaultConfig
from raven.sql_jobstore import SQLJobStore

NOOP = "tests.test_scheduler_api:noop"


def noop():
    pass


def test_jobs():
    return [
        {
            "id": "purge_data",
            "func": NOOP,
            "trigger": "cron",
            "day": "*",
            "hour": 0,
            "minute": 0,
            "next_run_time": None,
        },
        {
            "id": "reconcile_eud_status",
            "func": NOOP,
            "trigger": "interval",
            "seconds": 0,
            "minutes": 1,
        },
        {"id": "mystery_job", "func": NOOP, "trigger": "interval", "minutes": 5},
    ]


def start_scheduler(app, jobs_db):
    app.config["SCHEDULER_JOBSTORES"] = {"default": SQLJobStore(url=f"sqlite:///{jobs_db}")}
    drop_removed_jobs_from_config(app)
    apscheduler.init_app(app)
    # Paused: job processing never actually kicks in during the tests.
    apscheduler.start(paused=True)


def stop_scheduler():
    if apscheduler.running:
        apscheduler.shutdown(wait=False)


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
        JOBS=test_jobs(),
    )
    db.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(scheduler_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
        db.session.commit()

    start_scheduler(app, tmp_path / "jobs.db")
    yield app
    stop_scheduler()

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


@pytest.fixture
def admin(app):
    client = app.test_client()
    _login(app, client, "admin")
    return client


def jobs_by_id(client):
    r = client.get("/api/scheduler/jobs")
    assert r.status_code == 200
    return {j["id"]: j for j in r.json}


def future(**delta):
    tz = timezone(timedelta(hours=10))
    t = datetime.now(tz).replace(second=0, microsecond=0) + timedelta(**delta)
    return t


# ---------------------------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------------------------


def test_default_config_has_no_feed_jobs():
    ids = {job["id"] for job in DefaultConfig.JOBS}
    assert "get_adsb_data" not in ids and "ais" not in ids
    assert {"delete_video_recordings", "purge_data", "delete_old_data", "reconcile_eud_status"} <= ids
    for job_id in ids:
        assert JOB_DESCRIPTIONS.get(job_id), job_id


def test_jobs_include_description_and_schedule(admin):
    jobs = jobs_by_id(admin)
    assert set(jobs) == {"purge_data", "reconcile_eud_status", "mystery_job"}
    purge = jobs["purge_data"]
    assert purge["description"] == JOB_DESCRIPTIONS["purge_data"]
    assert purge["schedule"] == "Daily at 00:00"
    assert purge["repeat"] == "daily"
    assert purge["next_run_time"] is None  # paused
    assert purge["trigger"] == "cron"
    assert purge["scheduled_runs"] == []
    for key in ("id", "name", "func", "trigger", "next_run_time"):
        assert key in purge

    rec = jobs["reconcile_eud_status"]
    assert rec["schedule"] == "Every minute"
    assert rec["repeat"] == "minutes" and rec["interval_minutes"] == 1
    assert rec["next_run_time"] is not None

    assert jobs["mystery_job"]["description"] == ""
    assert jobs["mystery_job"]["schedule"] == "Every 5 minutes"


def test_removed_jobs_are_dropped(app, admin, tmp_path):
    # An old install: config.yml still lists the feed jobs and the job store has rows for them.
    cfg_app = Flask("cfg")
    cfg_app.config["JOBS"] = test_jobs() + [
        {"id": "get_adsb_data", "func": "raven.blueprints.scheduled_jobs:get_adsb_data", "trigger": "interval", "minutes": 1},
        {"id": "ais", "func": "raven.blueprints.scheduled_jobs:get_aishub_data", "trigger": "interval", "minutes": 1},
    ]
    drop_removed_jobs_from_config(cfg_app)
    assert {j["id"] for j in cfg_app.config["JOBS"]} == {"purge_data", "reconcile_eud_status", "mystery_job"}

    for job_id in REMOVED_SCHEDULER_JOB_IDS:
        apscheduler.add_job(id=job_id, func=NOOP, trigger="interval", minutes=1)
    assert "get_adsb_data" in jobs_by_id(admin)
    remove_obsolete_scheduler_jobs()
    remove_obsolete_scheduler_jobs()  # idempotent
    jobs = jobs_by_id(admin)
    assert "get_adsb_data" not in jobs and "ais" not in jobs


def test_requires_admin(app):
    client = app.test_client()
    _login(app, client, "alice")
    assert client.get("/api/scheduler/jobs").status_code == 403
    r = client.post("/api/scheduler/job/schedule", json={"job_id": "purge_data"})
    assert r.status_code == 403
    assert client.post("/api/scheduler/job/cancel", json={"job_id": "x__once__1"}).status_code == 403


# ---------------------------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------------------------


def test_schedule_once_adds_separate_job(admin):
    run_at = future(days=1)
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "purge_data", "run_at": run_at.isoformat(), "repeat": "once"},
    )
    assert r.status_code == 200, r.json
    once = r.json["job"]
    assert once["id"] == f"purge_data__once__{int(run_at.timestamp())}"
    assert once["repeat"] == "once"
    assert once["schedule"].startswith("Once at ")
    assert once["description"] == JOB_DESCRIPTIONS["purge_data"]

    job = apscheduler.get_job(once["id"])
    assert isinstance(job.trigger, DateTrigger)
    assert job.func_ref == NOOP
    assert job.next_run_time == run_at

    # The built-in job keeps its own trigger and the one-off is nested under it.
    jobs = jobs_by_id(admin)
    assert once["id"] not in jobs
    purge = jobs["purge_data"]
    assert purge["schedule"] == "Daily at 00:00"
    assert purge["next_run_time"] is None
    assert [run["id"] for run in purge["scheduled_runs"]] == [once["id"]]
    assert datetime.fromisoformat(purge["scheduled_runs"][0]["run_at"]) == run_at


def test_schedule_once_rejects_past(admin):
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "purge_data", "run_at": future(minutes=-5).isoformat(), "repeat": "once"},
    )
    assert r.status_code == 400
    assert "past" in r.json["error"]


def test_schedule_validation(admin):
    ok = {"job_id": "purge_data", "run_at": future(hours=1).isoformat(), "repeat": "daily"}
    assert admin.post("/api/scheduler/job/schedule", json={**ok, "job_id": "nope"}).status_code == 404
    assert admin.post("/api/scheduler/job/schedule", json={**ok, "repeat": "yearly"}).status_code == 400
    assert admin.post("/api/scheduler/job/schedule", json={**ok, "run_at": "tomorrow"}).status_code == 400
    naive = datetime.now().replace(microsecond=0).isoformat()
    assert admin.post("/api/scheduler/job/schedule", json={**ok, "run_at": naive}).status_code == 400
    for bad in (None, 0, 10081, "5", 2.5):
        r = admin.post(
            "/api/scheduler/job/schedule",
            json={**ok, "repeat": "minutes", "interval_minutes": bad},
        )
        assert r.status_code == 400, bad


def test_schedule_minutes(admin):
    run_at = future(hours=2)
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={
            "job_id": "reconcile_eud_status",
            "run_at": run_at.isoformat(),
            "repeat": "minutes",
            "interval_minutes": 15,
        },
    )
    assert r.status_code == 200, r.json
    job = r.json["job"]
    assert job["repeat"] == "minutes" and job["interval_minutes"] == 15
    assert job["schedule"] == f"Every 15 minutes from {run_at.day} {run_at.strftime('%b %H:%M')}"
    trigger = apscheduler.get_job("reconcile_eud_status").trigger
    assert isinstance(trigger, IntervalTrigger)
    assert trigger.interval == timedelta(minutes=15)
    assert datetime.fromisoformat(job["next_run_time"]) == run_at


def test_schedule_hourly(admin):
    run_at = future(minutes=30)
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "reconcile_eud_status", "run_at": run_at.isoformat(), "repeat": "hourly"},
    )
    assert r.status_code == 200, r.json
    job = r.json["job"]
    assert job["repeat"] == "hourly"
    assert job["schedule"].startswith("Every hour from ")
    assert datetime.fromisoformat(job["next_run_time"]) == run_at


def test_schedule_daily_resumes_paused_job(admin):
    run_at = future(days=1).replace(hour=2, minute=0)
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "purge_data", "run_at": run_at.isoformat(), "repeat": "daily"},
    )
    assert r.status_code == 200, r.json
    job = r.json["job"]
    assert job["repeat"] == "daily"
    assert job["schedule"] == "Daily at 02:00"
    assert datetime.fromisoformat(job["next_run_time"]) == run_at
    trigger = apscheduler.get_job("purge_data").trigger
    assert isinstance(trigger, CronTrigger)


def test_schedule_daily_uses_browser_timezone(admin):
    run_at = future(days=1).replace(hour=2, minute=0)
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={
            "job_id": "purge_data",
            "run_at": run_at.isoformat(),
            "repeat": "daily",
            "timezone": "Australia/Sydney",
        },
    )
    assert r.status_code == 200, r.json
    assert str(apscheduler.get_job("purge_data").trigger.timezone) == "Australia/Sydney"


def test_schedule_rejects_unknown_timezone(admin):
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={
            "job_id": "purge_data",
            "run_at": future(days=1).isoformat(),
            "repeat": "daily",
            "timezone": "Mars/Olympus",
        },
    )
    assert r.status_code == 400


def test_schedule_keeps_paused_when_resume_false(admin):
    run_at = future(days=1).replace(hour=2, minute=0)
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={
            "job_id": "purge_data",
            "run_at": run_at.isoformat(),
            "repeat": "weekly",
            "resume": False,
        },
    )
    assert r.status_code == 200, r.json
    job = r.json["job"]
    assert job["next_run_time"] is None
    assert job["repeat"] == "weekly"
    assert job["schedule"] == f"Weekly on {run_at.strftime('%A')} at 02:00"


def test_schedule_weekly(admin):
    run_at = future(days=3).replace(hour=3, minute=0)
    r = admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "reconcile_eud_status", "run_at": run_at.isoformat(), "repeat": "weekly"},
    )
    assert r.status_code == 200, r.json
    job = r.json["job"]
    assert job["schedule"] == f"Weekly on {run_at.strftime('%A')} at 03:00"
    assert datetime.fromisoformat(job["next_run_time"]) == run_at


def test_cancel(admin):
    run_at = future(days=2)
    once_id = admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "purge_data", "run_at": run_at.isoformat(), "repeat": "once"},
    ).json["job"]["id"]

    assert admin.post("/api/scheduler/job/cancel", json={"job_id": "purge_data"}).status_code == 400
    assert admin.post("/api/scheduler/job/cancel", json={}).status_code == 400
    r = admin.post("/api/scheduler/job/cancel", json={"job_id": once_id})
    assert r.status_code == 200 and r.json["success"]
    assert apscheduler.get_job(once_id) is None
    assert apscheduler.get_job("purge_data") is not None
    assert jobs_by_id(admin)["purge_data"]["scheduled_runs"] == []
    assert admin.post("/api/scheduler/job/cancel", json={"job_id": once_id}).status_code == 404


def test_schedule_survives_restart(app, admin, tmp_path):
    run_at = future(days=1).replace(hour=2, minute=0)
    admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "purge_data", "run_at": run_at.isoformat(), "repeat": "daily"},
    )
    once_id = admin.post(
        "/api/scheduler/job/schedule",
        json={"job_id": "purge_data", "run_at": future(days=2).isoformat(), "repeat": "once"},
    ).json["job"]["id"]

    # "Restart": a fresh scheduler over the same job store, loading the original config JOBS
    # (even one asking to replace existing jobs).
    stop_scheduler()
    jobs = test_jobs()
    jobs[0]["replace_existing"] = True
    app.config["JOBS"] = jobs
    start_scheduler(app, tmp_path / "jobs.db")

    listed = jobs_by_id(admin)
    assert listed["purge_data"]["schedule"] == "Daily at 02:00"
    assert datetime.fromisoformat(listed["purge_data"]["next_run_time"]) == run_at
    assert [r["id"] for r in listed["purge_data"]["scheduled_runs"]] == [once_id]
    assert listed["reconcile_eud_status"]["schedule"] == "Every minute"


# ---------------------------------------------------------------------------------------------
# Trigger descriptions
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "trigger,text,repeat",
    [
        (IntervalTrigger(minutes=1), "Every minute", ("minutes", 1)),
        (IntervalTrigger(minutes=5), "Every 5 minutes", ("minutes", 5)),
        (IntervalTrigger(hours=1), "Every hour", ("hourly", None)),
        (IntervalTrigger(hours=2, minutes=30), "Every 2 hours 30 minutes", ("minutes", 150)),
        (IntervalTrigger(seconds=30), "Every 30 seconds", ("custom", None)),
        (CronTrigger(day="*", hour=0, minute=0), "Daily at 00:00", ("daily", None)),
        (CronTrigger(day_of_week="sun", hour=3, minute=0), "Weekly on Sunday at 03:00", ("weekly", None)),
        (CronTrigger(minute=5), "Hourly at :05", ("custom", None)),
        (CronTrigger(day=1, hour=2, minute=0), "Monthly on day 1 at 02:00", ("custom", None)),
    ],
)
def test_describe_trigger(trigger, text, repeat):
    assert describe_trigger(trigger) == text
    assert describe_repeat(trigger) == repeat


def test_describe_interval_with_start():
    tz = timezone(timedelta(hours=10))
    trigger = IntervalTrigger(minutes=15, start_date=datetime(2026, 10, 31, 14, 0, tzinfo=tz))
    assert describe_trigger(trigger) == "Every 15 minutes from 31 Oct 14:00"
