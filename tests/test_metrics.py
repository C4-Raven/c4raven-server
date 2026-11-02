"""
Tests for the message counters (raven/metrics.py) and their API
(raven/blueprints/raven_api/metrics_api.py): counting across forked processes, flushing and
aggregating in the DB, and who may read the Prometheus endpoint.

Same minimal sqlite Flask app approach as tests/test_security_audit.py.
"""

import datetime
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

from raven import metrics
from raven.audit import init_audit
from raven.blueprints.raven_api import metrics_api
from raven.blueprints.raven_api.metrics_api import metrics_api_blueprint
from raven.defaultconfig import DefaultConfig
from raven.extensions import babel
from raven.models.AuditEvent import AuditEvent
from raven.models.EUD import EUD
from raven.models.MetricCounter import MetricCounter
from raven.models.MetricSample import MetricSample

TOKEN = "s3cret-scrape-token"


@pytest.fixture
def app(tmp_path, monkeypatch):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_ENABLE_LDAP=False,
        RAVEN_MEDIAMTX_ENABLE=False,
        RAVEN_METRICS_TOKEN=TOKEN,
        RAVEN_METRICS_FLUSH_INTERVAL=10,
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS=True,
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
    app.register_blueprint(metrics_api_blueprint)

    # No RabbitMQ / MediaMTX here
    monkeypatch.setattr(metrics_api, "_queue_stats", lambda: {"cot_parser": (7, 1)})
    monkeypatch.setattr(metrics_api, "_live_cache", {"at": 0.0, "values": None})
    monkeypatch.setattr(metrics_api, "_bad_token_audited", {})

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("password"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("alicepass"), roles=["user"])
        db.session.commit()

    yield app

    metrics.install(None)
    with app.app_context():
        db.session.remove()
        db.drop_all()


def _login_session(app, client, username):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username=username).fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()


def _value(app, name, labels=""):
    with app.app_context():
        row = db.session.get(MetricCounter, (name, labels))
        return row.value if row else None


# --- Categories ---


@pytest.mark.parametrize(
    "cot_type,category",
    [
        ("a-f-G-U-C", "position"),
        ("b-t-f", "chat"),
        ("b-t-f-d", "chat"),
        ("t-x-d-d", "other"),
        ("b-m-p-s-p-i", "other"),
        (None, "other"),
        ("", "other"),
    ],
)
def test_cot_category(cot_type, category):
    assert metrics.cot_category(cot_type) == category


def test_cot_category_from_xml_reads_only_the_event_tag():
    assert metrics.cot_category_from_xml('<event version="2.0" type="b-t-f" uid="x"/>') == "chat"
    assert (
        metrics.cot_category_from_xml("<event uid='x' type='a-f-G'><detail type=\"b-t-f\"/></event>")
        == "position"
    )
    assert metrics.cot_category_from_xml('<event uid="x"><detail type="b-t-f"/></event>') == "other"
    assert metrics.cot_category_from_xml("") == "other"


# --- Counting across processes ---


def test_inc_is_a_noop_without_installed_counters():
    metrics.install(None)
    metrics.inc("raven_cot_received_total", metrics.CATEGORY_LABELS["chat"])


def test_unknown_series_and_bad_amounts_are_ignored():
    counters = metrics.SharedCounters(metrics.COT_PARSER_SERIES)
    counters.inc("nope")
    counters.inc("raven_cot_parse_errors_total", "", -5)
    counters.inc("raven_cot_parse_errors_total", "", 0)
    assert sum(counters.snapshot()) == 0


def test_shared_counters_add_up_across_forked_children():
    counters = metrics.install(metrics.SharedCounters(metrics.EUD_HANDLER_SERIES))
    children = []
    for _ in range(4):
        pid = os.fork()
        if pid == 0:
            try:
                for _ in range(500):
                    metrics.inc("raven_cot_received_total", metrics.CATEGORY_LABELS["position"])
                metrics.inc("raven_bytes_received_total", "", 1000)
            finally:
                os._exit(0)
        children.append(pid)
    metrics.inc("raven_cot_received_total", metrics.CATEGORY_LABELS["chat"])
    for pid in children:
        os.waitpid(pid, 0)

    values = dict(zip(counters.series, counters.snapshot()))
    assert values[("raven_cot_received_total", 'category="position"')] == 2000
    assert values[("raven_cot_received_total", 'category="chat"')] == 1
    assert values[("raven_bytes_received_total", "")] == 4000


def test_flusher_writes_only_the_growth_and_adds_its_labels(app):
    counters = metrics.SharedCounters(metrics.EUD_HANDLER_SERIES)
    gauges = {("raven_eud_connections", 'transport="ssl"'): 3}
    flusher = metrics.MetricsFlusher(
        app, counters, "eud_handler_ssl", 'transport="ssl"', lambda: dict(gauges)
    )

    counters.inc("raven_cot_sent_total", metrics.CATEGORY_LABELS["chat"], 5)
    assert flusher.flush()
    counters.inc("raven_cot_sent_total", metrics.CATEGORY_LABELS["chat"], 2)
    gauges[("raven_eud_connections", 'transport="ssl"')] = 1
    assert flusher.flush()
    assert flusher.flush()  # nothing new, nothing added

    assert _value(app, "raven_cot_sent_total", 'category="chat",transport="ssl"') == 7
    assert _value(app, "raven_eud_connections", 'transport="ssl"') == 1
    # Series that never moved aren't written
    assert _value(app, "raven_cot_sent_total", 'category="other",transport="ssl"') is None
    heartbeat = _value(
        app, "raven_metrics_last_flush_timestamp_seconds", 'source="eud_handler_ssl"'
    )
    assert abs(heartbeat - time.time()) < 60


def test_flushes_from_several_services_aggregate(app):
    # e.g. two cot_parser hosts writing the same series
    first = metrics.SharedCounters(metrics.COT_PARSER_SERIES)
    second = metrics.SharedCounters(metrics.COT_PARSER_SERIES)
    flushers = [
        metrics.MetricsFlusher(app, first, "cot_parser"),
        metrics.MetricsFlusher(app, second, "cot_parser_2"),
    ]
    first.inc("raven_cot_parsed_total", metrics.CATEGORY_LABELS["position"], 10)
    second.inc("raven_cot_parsed_total", metrics.CATEGORY_LABELS["position"], 32)
    second.inc("raven_cot_parse_errors_total")
    for flusher in flushers:
        assert flusher.flush()

    assert _value(app, "raven_cot_parsed_total", 'category="position"') == 42
    assert _value(app, "raven_cot_parse_errors_total") == 1


def test_failed_flush_is_retried(app, monkeypatch):
    counters = metrics.SharedCounters(metrics.COT_PARSER_SERIES)
    flusher = metrics.MetricsFlusher(app, counters, "cot_parser")
    counters.inc("raven_cot_parse_errors_total", "", 3)

    def broken(**kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(metrics, "write", broken)
    assert not flusher.flush()
    monkeypatch.undo()

    counters.inc("raven_cot_parse_errors_total", "", 1)
    assert flusher.flush()
    assert _value(app, "raven_cot_parse_errors_total") == 4


def test_record_adds_straight_to_the_db(app):
    with app.app_context():
        assert metrics.record("raven_data_package_uploads_total")
        assert metrics.record("raven_data_package_uploads_total")
    assert _value(app, "raven_data_package_uploads_total") == 2


def test_record_never_raises(app):
    with app.app_context():
        MetricCounter.__table__.drop(db.engine)
        assert metrics.record("raven_data_package_uploads_total") is False


def test_stale_gauges_read_as_zero(app):
    with app.app_context():
        metrics.write(gauges={("raven_eud_connections", 'transport="tcp"'): 9})
        metrics.write(gauges={("raven_eud_connections", 'transport="ssl"'): 4})
        row = db.session.get(MetricCounter, ("raven_eud_connections", 'transport="tcp"'))
        row.updated_at = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - datetime.timedelta(minutes=5)
        db.session.commit()
        connections = metrics.by_label(metrics.read_rows(db.session), "raven_eud_connections", "transport")
    assert connections == {"tcp": 0, "ssl": 4}


# --- Prometheus endpoint: who may read it ---


def test_metrics_requires_authentication(app):
    response = app.test_client().get("/api/metrics")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_metrics_forbidden_for_non_admin_session(app):
    client = app.test_client()
    _login_session(app, client, "alice")
    assert client.get("/api/metrics").status_code == 403


def test_metrics_allowed_for_admin_session(app):
    client = app.test_client()
    _login_session(app, client, "admin")
    response = client.get("/api/metrics")
    assert response.status_code == 200
    assert response.content_type.startswith("text/plain; version=0.0.4")


def test_metrics_allowed_with_bearer_token(app):
    response = app.test_client().get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200
    assert "raven_euds_connected 0" in response.text


def test_metrics_wrong_token_rejected_and_audited_once(app):
    client = app.test_client()
    for _ in range(3):
        response = client.get("/api/metrics", headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 401
    with app.app_context():
        events = db.session.query(AuditEvent).filter_by(action="metrics_token_failed").all()
        assert len(events) == 1
        assert events[0].success is False


def test_metrics_token_auth_disabled_when_token_empty(app):
    app.config["RAVEN_METRICS_TOKEN"] = ""
    client = app.test_client()
    assert client.get("/api/metrics", headers={"Authorization": "Bearer "}).status_code == 401
    assert client.get("/api/metrics", headers={"Authorization": "Bearer x"}).status_code == 401


def test_wrong_token_is_rejected_even_with_admin_session(app):
    client = app.test_client()
    _login_session(app, client, "admin")
    assert client.get("/api/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401


# --- Exposition format ---


def test_exposition_output(app):
    counters = metrics.SharedCounters(metrics.EUD_HANDLER_SERIES)
    counters.inc("raven_cot_received_total", metrics.CATEGORY_LABELS["position"], 3)
    counters.inc("raven_cot_received_total", metrics.CATEGORY_LABELS["chat"], 2)
    metrics.MetricsFlusher(app, counters, "eud_handler_tcp", 'transport="tcp"').flush()
    with app.app_context():
        db.session.add(EUD(uid="ANDROID-1", callsign="ONE", last_status="Connected"))
        db.session.commit()

    response = app.test_client().get("/api/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    lines = response.text.splitlines()

    assert lines.count("# TYPE raven_cot_received_total counter") == 1
    assert "# HELP raven_cot_received_total " + metrics.METRICS["raven_cot_received_total"][1] in lines
    assert 'raven_cot_received_total{category="chat",transport="tcp"} 2' in lines
    assert 'raven_cot_received_total{category="position",transport="tcp"} 3' in lines
    assert "raven_euds_connected 1" in lines
    assert 'raven_rabbitmq_queue_messages{queue="cot_parser"} 7' in lines
    assert 'raven_rabbitmq_queue_consumers{queue="cot_parser"} 1' in lines
    # MediaMTX disabled, sqlite has no size: left out rather than reported as 0
    assert not any(line.startswith("raven_video_streams_active") for line in lines)
    assert not any(line.startswith("raven_database_size_bytes") for line in lines)
    # Each family's samples follow its own TYPE line
    type_index = lines.index("# TYPE raven_cot_received_total counter")
    assert lines[type_index + 1].startswith("raven_cot_received_total{")
    assert response.text.endswith("\n")


# --- Dashboard summary and samples ---


def test_samples_and_summary(app):
    with app.app_context():
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        for minutes_ago, received, sent in ((3, 100, 50), (2, 160, 80), (1, 160, 200)):
            db.session.add(
                MetricSample(
                    timestamp=now - datetime.timedelta(minutes=minutes_ago),
                    cot_received=received,
                    cot_sent=sent,
                    bytes_received=0,
                    bytes_sent=0,
                    euds_connected=2,
                )
            )
        # Older than the retention, pruned by the next sample
        db.session.add(
            MetricSample(
                timestamp=now - datetime.timedelta(days=2),
                cot_received=0,
                cot_sent=0,
                bytes_received=0,
                bytes_sent=0,
                euds_connected=0,
            )
        )
        db.session.commit()
        metrics.write(
            counters={
                ("raven_cot_received_total", 'category="chat",transport="ssl"'): 4,
                ("raven_cot_received_total", 'category="position",transport="ssl"'): 6,
            },
            gauges={("raven_eud_connections", 'transport="ssl"'): 2},
            source="eud_handler_ssl",
        )
        metrics.take_sample(db.session)
        samples = db.session.query(MetricSample).order_by(MetricSample.timestamp).all()
        assert len(samples) == 4
        assert samples[-1].cot_received == 10

    client = app.test_client()
    assert client.get("/api/metrics/summary").status_code in (302, 401)
    _login_session(app, client, "alice")
    response = client.get("/api/metrics/summary?minutes=30")
    assert response.status_code == 200
    data = response.json

    assert data["totals"]["cot_received"] == 10
    assert data["received_by_category"] == {"chat": 4, "position": 6}
    assert data["connections"] == {"ssl": 2}
    assert data["queue_depth"] == 7
    assert [p["received"] for p in data["history"]][:2] == [60.0, 0.0]
    assert [p["sent"] for p in data["history"]][:2] == [30.0, 120.0]
    # The counters were reset below the older samples' totals: that minute counts as 0
    assert data["history"][-1]["sent"] == 0.0
    assert data["rate"]["received_per_minute"] == data["history"][-1]["received"]
    assert data["sources"][0]["source"] == "eud_handler_ssl"
    assert data["sources"][0]["stale"] is False
