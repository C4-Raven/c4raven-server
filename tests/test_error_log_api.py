"""
Tests for the admin error log viewer (raven/blueprints/raven_api/error_log_api.py).

Builds a minimal Flask app (sqlite, only the blueprint under test) like test_vpn_onboarding.py,
with RAVEN_DATA_FOLDER pointing at a temp dir whose logs/ folder the tests write to.
"""

import os
import time

import pytest
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.blueprints.raven_api import error_log_api
from raven.blueprints.raven_api.error_log_api import error_log_api_blueprint
from raven.defaultconfig import DefaultConfig

FMT = "[{ts}] - {proc}[{pid}] - {module} - {func} - {line} - {level} - {msg}\n"


def rec(ts, level, msg, proc="Raven", pid=1234, module="mod", func="fn", line=42):
    return FMT.format(
        ts=ts, proc=proc, pid=pid, module=module, func=func, line=line, level=level, msg=msg
    )


TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/x/y.py", line 3, in f\n'
    "    boom()\n"
    "ValueError: bad value\n"
)


@pytest.fixture
def app(tmp_path):
    (tmp_path / "logs").mkdir()
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

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(error_log_api_blueprint)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
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


@pytest.fixture
def admin(app):
    client = app.test_client()
    _login(app, client, "admin")
    return client


def logs(app):
    return os.path.join(app.config["RAVEN_DATA_FOLDER"], "logs")


def write(app, name, text, mode="w", mtime=None):
    path = os.path.join(logs(app), name)
    with open(path, mode) as f:
        f.write(text)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def test_parses_multiline_traceback(app, admin):
    write(
        app,
        "raven.log",
        rec("2026-10-30 10:00:00,100", "INFO", "started")
        + rec("2026-10-30 10:00:01,200", "ERROR", "Failed to do thing", module="m", func="f", line=7)
        + TRACEBACK
        + rec("2026-10-30 10:00:02,300", "INFO", "after"),
    )
    r = admin.get("/api/logs/errors")
    assert r.status_code == 200
    body = r.json
    assert body["sources"] == ["raven"]
    assert len(body["entries"]) == 1
    e = body["entries"][0]
    assert e["level"] == "ERROR"
    assert e["source"] == "raven"
    assert e["pid"] == 1234
    assert e["module"] == "m" and e["function"] == "f" and e["line"] == 7
    assert e["message"] == "Failed to do thing"
    assert e["traceback"].startswith("Traceback (most recent call last):")
    assert e["traceback"].endswith("ValueError: bad value")
    assert e["timestamp"].startswith("2026-10-30T10:00:01.200000")
    assert e["id"].startswith("raven:")


def test_level_filtering_and_order(app, admin):
    write(
        app,
        "cot_parser.log",
        rec("2026-10-30 10:00:00,000", "WARNING", "w1", proc="cot_parser")
        + rec("2026-10-30 10:00:01,000", "ERROR", "e1", proc="cot_parser")
        + rec("2026-10-30 10:00:02,000", "CRITICAL", "c1", proc="cot_parser")
        + rec("2026-10-30 10:00:03,000", "INFO", "i1", proc="cot_parser")
        + rec("2026-10-30 10:00:04,000", "DEBUG", "d1", proc="cot_parser"),
    )
    msgs = lambda r: [e["message"] for e in r.json["entries"]]  # noqa: E731
    assert msgs(admin.get("/api/logs/errors")) == ["c1", "e1"]
    assert msgs(admin.get("/api/logs/errors?level=WARNING")) == ["c1", "e1", "w1"]
    assert msgs(admin.get("/api/logs/errors?level=CRITICAL")) == ["c1"]
    assert msgs(admin.get("/api/logs/errors?level=WARNING&limit=2")) == ["c1", "e1"]
    assert msgs(admin.get("/api/logs/errors?level=WARNING&search=E1")) == ["e1"]
    assert admin.get("/api/logs/errors?level=INFO").status_code == 400


def test_source_filter_and_merge(app, admin):
    write(app, "raven.log", rec("2026-10-30 10:00:01,000", "ERROR", "from raven"))
    write(app, "eud_handler_ssl.log", rec("2026-10-30 10:00:02,000", "ERROR", "from eud", proc="eud_handler"))
    r = admin.get("/api/logs/errors")
    assert [e["source"] for e in r.json["entries"]] == ["eud_handler_ssl", "raven"]
    assert r.json["sources"] == ["eud_handler_ssl", "raven"]
    r = admin.get("/api/logs/errors?source=raven")
    assert [e["message"] for e in r.json["entries"]] == ["from raven"]
    assert admin.get("/api/logs/errors?source=../etc").status_code == 400


def test_since_returns_only_new_entries(app, admin):
    path = write(app, "raven.log", rec("2026-10-30 10:00:00,000", "ERROR", "old"))
    first = admin.get("/api/logs/errors").json
    assert [e["message"] for e in first["entries"]] == ["old"]

    r = admin.get("/api/logs/errors", query_string={"since": first["cursor"]})
    assert r.json["entries"] == []

    with open(path, "a") as f:
        f.write(rec("2026-10-30 10:00:05,000", "INFO", "noise"))
        f.write(rec("2026-10-30 10:00:06,000", "ERROR", "new one"))
        f.write(TRACEBACK)
        f.write(rec("2026-10-30 10:00:07,000", "ERROR", "new two"))
        f.write("[2026-10-30 10:00:08,000] - Raven[1] - m - f - 1 - ERROR - half wri")
    r = admin.get("/api/logs/errors", query_string={"since": first["cursor"]}).json
    assert [e["message"] for e in r["entries"]] == ["new two", "new one"]
    assert r["entries"][1]["traceback"].endswith("ValueError: bad value")

    # The half-written last line is picked up once it's complete, and only once.
    with open(path, "a") as f:
        f.write("tten\n")
    r2 = admin.get("/api/logs/errors", query_string={"since": r["cursor"]}).json
    assert [e["message"] for e in r2["entries"]] == ["half written"]
    r3 = admin.get("/api/logs/errors", query_string={"since": r2["cursor"]}).json
    assert r3["entries"] == []

    # Ids are stable between the full view and the incremental view.
    full = admin.get("/api/logs/errors").json["entries"]
    assert {e["id"] for e in r["entries"]} <= {e["id"] for e in full}
    assert len({e["id"] for e in full}) == len(full)


def test_since_across_rotation(app, admin):
    path = write(app, "raven.log", rec("2026-10-30 23:59:58,000", "ERROR", "before rotation"))
    cursor = admin.get("/api/logs/errors").json["cursor"]

    # More lines land in the file, then TimedRotatingFileHandler renames it and starts a new one.
    with open(path, "a") as f:
        f.write(rec("2026-10-30 23:59:59,000", "ERROR", "just before rotation"))
    os.rename(path, os.path.join(logs(app), "raven.log.2026-10-30"))
    write(app, "raven.log", rec("2026-10-31 00:00:01,000", "ERROR", "after rotation"))

    r = admin.get("/api/logs/errors", query_string={"since": cursor}).json
    assert [e["message"] for e in r["entries"]] == ["after rotation", "just before rotation"]
    assert r["sources"] == ["raven"]

    r2 = admin.get("/api/logs/errors", query_string={"since": r["cursor"]}).json
    assert r2["entries"] == []

    # Without since, the history spans the rotated file too, newest first.
    full = admin.get("/api/logs/errors").json["entries"]
    assert [e["message"] for e in full] == [
        "after rotation",
        "just before rotation",
        "before rotation",
    ]


def test_truncated_file_is_reread(app, admin):
    write(app, "raven.log", rec("2026-10-30 10:00:00,000", "ERROR", "a" * 200))
    cursor = admin.get("/api/logs/errors").json["cursor"]
    write(app, "raven.log", rec("2026-10-30 10:00:09,000", "ERROR", "after truncate"))
    r = admin.get("/api/logs/errors", query_string={"since": cursor}).json
    assert [e["message"] for e in r["entries"]] == ["after truncate"]


def test_invalid_cursor(app, admin):
    assert admin.get("/api/logs/errors?since=not-a-cursor").status_code == 400


def test_stderr_capture(app, admin):
    # What systemd's StandardError=append: puts in the same folder: duplicates of the Raven
    # logger in Python's default format (dropped), Flask's own unhandled-exception log, and
    # tracebacks printed for uncaught exceptions.
    write(
        app,
        "raven.log",
        "INFO:Raven:Starting in production mode\n"
        "ERROR:Raven:duplicate of a file record\n"
        "ERROR:raven.app:Exception on /api/foo [GET]\n"
        + TRACEBACK
        + "Exception ignored in: <function f at 0x1>\n"
        + TRACEBACK
        + "----------------------------------------\n"
        "Exception occurred during processing of request from ('1.2.3.4', 5)\n"
        + TRACEBACK
        + "----------------------------------------\n"
        "/x/models/EUD.py:77: SAWarning: Multiple rows returned\n"
        "  if self.certificate:\n"
        "Certificate request self-signature ok\n",
    )
    r = admin.get("/api/logs/errors?level=WARNING").json["entries"]
    messages = [e["message"] for e in r]
    assert messages == [
        "/x/models/EUD.py:77: SAWarning: Multiple rows returned",
        "Exception occurred during processing of request from ('1.2.3.4', 5)",
        "Exception ignored in: <function f at 0x1>",
        "Exception on /api/foo [GET]",
    ]
    by_msg = {e["message"]: e for e in r}
    flask_err = by_msg["Exception on /api/foo [GET]"]
    assert flask_err["level"] == "ERROR"
    assert flask_err["module"] == "raven.app"
    assert flask_err["timestamp"] is None
    assert flask_err["traceback"].endswith("ValueError: bad value")
    assert by_msg["/x/models/EUD.py:77: SAWarning: Multiple rows returned"]["level"] == "WARNING"
    sock = by_msg["Exception occurred during processing of request from ('1.2.3.4', 5)"]
    assert sock["level"] == "ERROR"
    assert "----" not in sock["traceback"]


def test_chunk_boundaries(app, admin, monkeypatch):
    # Force tiny chunks so entries straddle chunk boundaries.
    monkeypatch.setattr(error_log_api, "CHUNK_SIZE", 97)
    text = ""
    for i in range(60):
        text += rec(f"2026-10-30 10:{i // 60:02d}:{i % 60:02d},000", "ERROR", f"err {i}")
        if i % 3 == 0:
            text += TRACEBACK
        text += rec(f"2026-10-30 10:{i // 60:02d}:{i % 60:02d},500", "INFO", "info")
    write(app, "raven.log", text)
    entries = admin.get("/api/logs/errors").json["entries"]
    assert [e["message"] for e in entries] == [f"err {i}" for i in reversed(range(60))]
    for e in entries:
        n = int(e["message"].split()[1])
        assert (e["traceback"] is not None) == (n % 3 == 0)


def test_byte_budget(app, admin):
    app.config["RAVEN_ERROR_LOG_MAX_BYTES"] = 2000
    text = "".join(rec(f"2026-10-30 1{i // 60}:{i % 60:02d}:00,000", "ERROR", f"e{i}") for i in range(200))
    write(app, "raven.log", text)
    entries = admin.get("/api/logs/errors").json["entries"]
    assert 0 < len(entries) < 200
    assert entries[0]["message"] == "e199"


def test_download(app, admin):
    now = time.time()
    recent = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 3600))
    old = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 30 * 86400))
    write(
        app,
        "raven.log.2026-09-01",
        rec(f"{old},000", "ERROR", "ancient"),
        mtime=now - 30 * 86400,
    )
    write(
        app,
        "raven.log",
        rec(f"{recent},000", "ERROR", "recent error")
        + TRACEBACK
        + rec(f"{recent},500", "INFO", "noise")
        + rec(f"{recent},900", "WARNING", "recent warning"),
    )
    r = admin.get("/api/logs/errors/download?days=7")
    assert r.status_code == 200
    assert r.mimetype == "text/plain"
    cd = r.headers["Content-Disposition"]
    assert cd.startswith('attachment; filename="error-log-') and cd.endswith('.txt"')
    text = r.get_data(as_text=True)
    assert text.startswith("# Raven error log export")
    assert "recent error" in text
    assert "ValueError: bad value" in text
    assert "recent warning" not in text
    assert "noise" not in text
    assert "ancient" not in text

    r = admin.get("/api/logs/errors/download?days=60&level=WARNING")
    text = r.get_data(as_text=True)
    assert text.index("ancient") < text.index("recent error") < text.index("recent warning")


def test_requires_admin(app):
    write(app, "raven.log", rec("2026-10-30 10:00:00,000", "ERROR", "secret"))
    client = app.test_client()
    assert client.get("/api/logs/errors").status_code in (401, 403)
    _login(app, client, "alice")
    assert client.get("/api/logs/errors").status_code == 403
    assert client.get("/api/logs/errors/download").status_code == 403


def test_empty_or_missing_folder(app, admin):
    os.rmdir(logs(app))
    r = admin.get("/api/logs/errors").json
    assert r["entries"] == [] and r["sources"] == []
    assert admin.get("/api/logs/errors", query_string={"since": r["cursor"]}).status_code == 200
