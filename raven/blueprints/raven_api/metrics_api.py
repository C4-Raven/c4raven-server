"""
Message counters (raven.metrics) for Prometheus and the Dashboard.

GET /api/metrics (also /metrics)   -> Prometheus text exposition format. An administrator's web
                                      session, or "Authorization: Bearer <RAVEN_METRICS_TOKEN>"
                                      when that's set. nginx only proxies /api, so scrape
                                      /api/metrics through it.
GET /api/metrics/summary?minutes=60 -> JSON for the Dashboard: totals, connections, the message
                                      rate and its per minute history

Prometheus scrape config:

    scrape_configs:
      - job_name: raven
        scheme: https
        metrics_path: /api/metrics
        authorization:
          type: Bearer
          credentials: <RAVEN_METRICS_TOKEN from config.yml>
        static_configs:
          - targets: ["tak.example.com:443"]

Counters live in the DB, so they keep counting across restarts and every process's counts
are already summed; use rate()/increase() on them as usual.
"""

import hmac
import threading
import time
import traceback
from datetime import timedelta

import pika
import requests
from flask import Blueprint, Response
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_security import auth_required, current_user
from sqlalchemy import text

from raven import metrics
from raven.audit import client_ip, record_audit_event
from raven.extensions import db, logger
from raven.functions import iso8601_string_from_datetime
from raven.models.MetricCounter import MetricCounter  # noqa: F401  (registers the table)
from raven.models.MetricSample import MetricSample

metrics_api_blueprint = Blueprint("metrics_api_blueprint", __name__)

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
# RabbitMQ, MediaMTX and the DB size are asked at most this often, whoever's polling
LIVE_CACHE_SECONDS = 15
# One audit event per IP per this many seconds for a wrong bearer token, so a misconfigured
# scraper doesn't flood the trail every scrape
BAD_TOKEN_AUDIT_SECONDS = 600
QUEUES = ("cot_parser",)

_live_cache = {"at": 0.0, "values": None}
_live_lock = threading.Lock()
_bad_token_audited = {}


def _queue_stats():
    """{queue: (messages, consumers)} by passive declare, or {} if RabbitMQ can't be reached."""
    stats = {}
    connection = None
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS"),
                credentials=pika.PlainCredentials(
                    app.config.get("RAVEN_RABBITMQ_USERNAME"),
                    app.config.get("RAVEN_RABBITMQ_PASSWORD"),
                ),
                connection_attempts=1,
                socket_timeout=2,
                blocked_connection_timeout=2,
            )
        )
        for queue in QUEUES:
            # A passive declare of a missing queue closes the channel, so one per queue
            channel = connection.channel()
            try:
                result = channel.queue_declare(queue=queue, passive=True)
                stats[queue] = (result.method.message_count, result.method.consumer_count)
            except pika.exceptions.ChannelClosed:
                pass
    except Exception as e:
        logger.debug(f"Failed to read RabbitMQ queue depth: {e}")
    finally:
        try:
            if connection and connection.is_open:
                connection.close()
        except Exception:
            pass
    return stats


def _video_streams_active():
    if not app.config.get("RAVEN_MEDIAMTX_ENABLE"):
        return None
    try:
        r = requests.get(
            "{}/v3/paths/list".format(app.config.get("RAVEN_MEDIAMTX_API_ADDRESS")),
            params={"itemsPerPage": 1000},
            timeout=2,
        )
        r.raise_for_status()
        return sum(
            1 for path in r.json().get("items") or [] if path.get("ready") or path.get("online")
        )
    except Exception as e:
        logger.debug(f"Failed to count MediaMTX streams: {e}")
        return None


def _database_size():
    try:
        if db.engine.dialect.name == "postgresql":
            return db.session.execute(
                text("SELECT pg_database_size(current_database())")
            ).scalar_one()
    except Exception as e:
        db.session.rollback()
        logger.debug(f"Failed to read the database size: {e}")
    return None


def _live_values():
    """Values asked of other services, cached for LIVE_CACHE_SECONDS."""
    with _live_lock:
        fresh = time.monotonic() - _live_cache["at"] < LIVE_CACHE_SECONDS
        if _live_cache["values"] is not None and fresh:
            return _live_cache["values"]
        values = {
            "queues": _queue_stats(),
            "video_streams_active": _video_streams_active(),
            "database_size": _database_size(),
        }
        _live_cache.update(at=time.monotonic(), values=values)
        return values


def _format_value(value):
    if isinstance(value, float) and not value.is_integer():
        return repr(value)
    return str(int(value))


def render_prometheus(rows, extra) -> str:
    """Text exposition format: one HELP/TYPE block per metric family, families in METRICS order.

    :param rows: metrics.read_rows()
    :param extra: [(name, labels, value)] computed at scrape time
    """
    families = {}
    for name, labels, kind, value, _updated in rows:
        families.setdefault(name, {"kind": kind, "samples": []})["samples"].append((labels, value))
    for name, labels, value in extra:
        if value is None:
            continue
        kind = metrics.METRICS.get(name, (metrics.GAUGE, ""))[0]
        families.setdefault(name, {"kind": kind, "samples": []})["samples"].append((labels, value))

    order = list(metrics.METRICS) + sorted(n for n in families if n not in metrics.METRICS)
    lines = []
    for name in order:
        family = families.get(name)
        if not family:
            continue
        kind, help_text = metrics.METRICS.get(name, (family["kind"], ""))
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for labels, value in family["samples"]:
            series = f"{name}{{{labels}}}" if labels else name
            lines.append(f"{series} {_format_value(value)}")
    return "\n".join(lines) + "\n"


def _scrape_extra():
    live = _live_values()
    extra = [("raven_euds_connected", "", metrics.connected_euds(db.session))]
    for queue, (messages, consumers) in live["queues"].items():
        extra.append(("raven_rabbitmq_queue_messages", f'queue="{queue}"', messages))
        extra.append(("raven_rabbitmq_queue_consumers", f'queue="{queue}"', consumers))
    extra.append(("raven_video_streams_active", "", live["video_streams_active"]))
    extra.append(("raven_database_size_bytes", "", live["database_size"]))
    return extra


def _audit_bad_token():
    ip = client_ip()
    now = time.monotonic()
    if now - _bad_token_audited.get(ip, -BAD_TOKEN_AUDIT_SECONDS) < BAD_TOKEN_AUDIT_SECONDS:
        return
    _bad_token_audited[ip] = now
    record_audit_event(
        "security",
        "metrics_token_failed",
        success=False,
        details="Wrong bearer token for /api/metrics",
    )


def _unauthorized(message, status):
    response = jsonify({"success": False, "error": message})
    response.status_code = status
    if status == 401:
        response.headers["WWW-Authenticate"] = 'Bearer realm="raven-metrics"'
    return response


def _check_metrics_access():
    """None when the request may read the metrics, otherwise the error response."""
    header = request.headers.get("Authorization", "")
    if header[:7].lower() == "bearer ":
        token = app.config.get("RAVEN_METRICS_TOKEN") or ""
        presented = header[7:].strip()
        if token and presented and hmac.compare_digest(presented.encode(), token.encode()):
            return None
        _audit_bad_token()
        return _unauthorized(gettext("Invalid metrics token"), 401)

    if current_user and current_user.is_authenticated:
        if current_user.has_role("administrator"):
            return None
        return _unauthorized(gettext("Forbidden"), 403)
    return _unauthorized(gettext("Authentication required"), 401)


@metrics_api_blueprint.route("/metrics")
@metrics_api_blueprint.route("/api/metrics")
def prometheus_metrics():
    denied = _check_metrics_access()
    if denied is not None:
        return denied
    try:
        body = render_prometheus(metrics.read_rows(db.session), _scrape_extra())
    except Exception as e:
        logger.error(f"Failed to render metrics: {e}")
        logger.debug(traceback.format_exc())
        return _unauthorized(gettext("Failed to read metrics"), 500)
    return Response(body, mimetype=None, content_type=CONTENT_TYPE)


@metrics_api_blueprint.route("/api/metrics/summary")
@auth_required()
def metrics_summary():
    try:
        minutes = int(request.args.get("minutes", 60))
    except (TypeError, ValueError):
        minutes = 60
    minutes = max(5, min(int(metrics.SAMPLE_RETENTION.total_seconds() // 60), minutes))

    rows = metrics.read_rows(db.session)
    sums = metrics.totals(rows)

    # One sample before the window, so the first minute in it has a rate
    since = metrics._now() - timedelta(minutes=minutes + 1)
    samples = (
        db.session.query(MetricSample)
        .filter(MetricSample.timestamp >= since)
        .order_by(MetricSample.timestamp)
        .all()
    )
    history = [
        dict(point, timestamp=iso8601_string_from_datetime(point["timestamp"]))
        for point in metrics.sample_rates(samples)
    ]
    latest = history[-1] if history else None

    interval = max(1, int(app.config.get("RAVEN_METRICS_FLUSH_INTERVAL") or 10))
    stale_before = metrics._now() - timedelta(seconds=interval * metrics.STALE_INTERVALS)
    sources = []
    for row in rows:
        name, _labels, _kind, _value, updated = row
        if name != "raven_metrics_last_flush_timestamp_seconds":
            continue
        for source in metrics.by_label([row], name, "source"):
            sources.append(
                {
                    "source": source,
                    "last_flush": iso8601_string_from_datetime(updated),
                    "stale": updated < stale_before,
                }
            )

    live = _live_values()
    queue = live["queues"].get("cot_parser")

    return jsonify(
        {
            "totals": {
                "cot_received": sums.get("raven_cot_received_total", 0),
                "cot_sent": sums.get("raven_cot_sent_total", 0),
                "bytes_received": sums.get("raven_bytes_received_total", 0),
                "bytes_sent": sums.get("raven_bytes_sent_total", 0),
                "cot_dropped": sums.get("raven_cot_dropped_total", 0),
                "auth_failures": sums.get("raven_eud_auth_failures_total", 0),
                "connections_accepted": sums.get("raven_eud_connections_accepted_total", 0),
                "cot_parsed": sums.get("raven_cot_parsed_total", 0),
                "cot_parse_errors": sums.get("raven_cot_parse_errors_total", 0),
                "data_package_uploads": sums.get("raven_data_package_uploads_total", 0),
                "data_package_downloads": sums.get("raven_data_package_downloads_total", 0),
            },
            "received_by_category": metrics.by_label(rows, "raven_cot_received_total", "category"),
            "sent_by_category": metrics.by_label(rows, "raven_cot_sent_total", "category"),
            "dropped_by_reason": metrics.by_label(rows, "raven_cot_dropped_total", "reason"),
            "connections": metrics.by_label(rows, "raven_eud_connections", "transport"),
            "euds_connected": metrics.connected_euds(db.session),
            "rate": {
                "received_per_minute": latest["received"] if latest else None,
                "sent_per_minute": latest["sent"] if latest else None,
            },
            "history": history,
            "history_minutes": minutes,
            "queue_depth": queue[0] if queue else None,
            "video_streams_active": live["video_streams_active"],
            "database_size": live["database_size"],
            "sources": sources,
            "flush_interval": interval,
        }
    )
