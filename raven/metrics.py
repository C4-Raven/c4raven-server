"""
Message counters for the Dashboard and the Prometheus endpoint (/api/metrics).

Where the counting happens:
* eud_handler (one service per transport, TCP / SSL / UDP) is a forking socket server: every
  connected device is its own child process.
* cot_parser forks RAVEN_COT_PARSER_PROCESSES parser processes.
* raven (the web app) is a single process.

So no one process can see every count. Each eud_handler / cot_parser service creates one
SharedCounters (a small shared memory array) before it forks, so every child increments the same
slots; the hot path is one dict lookup plus an increment under a process-shared lock, nothing
touches the network. The parent process runs a MetricsFlusher thread that, every
RAVEN_METRICS_FLUSH_INTERVAL seconds, adds the growth since its last flush to the metric_counters
table (``value = value + delta`` in one transaction, so several services can flush at once) and
overwrites its gauges. raven adds its own rare events (data package uploads/downloads) straight
to the table with record(). /api/metrics just reads that table.

Why not prometheus_client: it isn't a dependency (the offline .deb would have to vendor it), and
its multiprocess mode needs a shared directory of per-pid mmap files that has to be wiped on every
restart of every service and keeps a file per dead child forever, one per device connection here.
Why not RabbitMQ: the counts would go through the same queues they're measuring, and be lost
exactly when those back up. The DB is already shared by every process, survives restarts (so the
counters stay monotonic, as Prometheus wants) and costs one small transaction per service every
few seconds.
"""

import ctypes
import multiprocessing
import re
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone

from raven.extensions import db, logger

# name -> (Prometheus type, help). Everything /api/metrics can print, whoever produces it.
METRICS = {
    "raven_cot_received_total": (
        "counter",
        "CoT messages received from devices, by category (pings excluded)",
    ),
    "raven_cot_sent_total": ("counter", "CoT messages sent to devices, by category"),
    "raven_bytes_received_total": ("counter", "Bytes received from devices on streaming ports"),
    "raven_bytes_sent_total": ("counter", "Bytes sent to devices on streaming ports"),
    "raven_cot_dropped_total": (
        "counter",
        "Messages from or to devices that were dropped, by reason",
    ),
    "raven_eud_connections_accepted_total": ("counter", "Device connections accepted"),
    "raven_eud_auth_failures_total": (
        "counter",
        "Device streaming connections refused at authentication",
    ),
    "raven_cot_parsed_total": ("counter", "CoT messages processed by cot_parser, by category"),
    "raven_cot_parse_errors_total": ("counter", "CoT messages cot_parser failed to process"),
    "raven_data_package_uploads_total": ("counter", "Data packages uploaded"),
    "raven_data_package_downloads_total": ("counter", "Data packages downloaded"),
    "raven_eud_connections": ("gauge", "Open device connections, by transport"),
    "raven_euds_connected": ("gauge", "Devices whose status is Connected"),
    "raven_rabbitmq_queue_messages": ("gauge", "Messages waiting in a RabbitMQ queue"),
    "raven_rabbitmq_queue_consumers": ("gauge", "Consumers of a RabbitMQ queue"),
    "raven_video_streams_active": ("gauge", "Video paths in MediaMTX with an active source"),
    "raven_database_size_bytes": ("gauge", "Size of the database"),
    "raven_metrics_last_flush_timestamp_seconds": (
        "gauge",
        "Unix time each counting service last flushed its counters",
    ),
}

GAUGE = "gauge"
COUNTER = "counter"

CATEGORIES = ("position", "chat", "other")
CATEGORY_LABELS = {c: f'category="{c}"' for c in CATEGORIES}

DROP_PARSE_ERROR = 'reason="parse_error"'
DROP_UNAUTHENTICATED = 'reason="unauthenticated"'
DROP_SEND_ERROR = 'reason="send_error"'

# Series each forking service counts, as (name, labels without the service's own labels)
EUD_HANDLER_SERIES = (
    [("raven_cot_received_total", CATEGORY_LABELS[c]) for c in CATEGORIES]
    + [("raven_cot_sent_total", CATEGORY_LABELS[c]) for c in CATEGORIES]
    + [
        ("raven_bytes_received_total", ""),
        ("raven_bytes_sent_total", ""),
        ("raven_cot_dropped_total", DROP_PARSE_ERROR),
        ("raven_cot_dropped_total", DROP_UNAUTHENTICATED),
        ("raven_cot_dropped_total", DROP_SEND_ERROR),
        ("raven_eud_connections_accepted_total", ""),
        ("raven_eud_auth_failures_total", ""),
    ]
)
COT_PARSER_SERIES = [("raven_cot_parsed_total", CATEGORY_LABELS[c]) for c in CATEGORIES] + [
    ("raven_cot_parse_errors_total", "")
]

# A gauge not refreshed for this many flush intervals belongs to a service that stopped
STALE_INTERVALS = 3
# How long record_metrics_sample keeps Dashboard samples
SAMPLE_RETENTION = timedelta(hours=24)

# <event ... type="b-t-f" ...>: only scans the event tag itself
_EVENT_TYPE = re.compile(r"""<event\b[^>]*?\stype=["']([^"']*)""")


def cot_category(cot_type) -> str:
    """position (atoms: SA and points), chat (GeoChat) or other"""
    if not cot_type:
        return "other"
    if cot_type.startswith("b-t-f"):
        return "chat"
    if cot_type.startswith("a-"):
        return "position"
    return "other"


def cot_category_from_xml(cot: str) -> str:
    """cot_category() for a CoT that's still a string, without parsing it."""
    match = _EVENT_TYPE.search(cot) if cot else None
    return cot_category(match.group(1) if match else None)


def join_labels(*labels) -> str:
    return ",".join(label for label in labels if label)


class SharedCounters:
    """Fixed set of counters in shared memory, for a service that forks its workers.

    Create it in the parent before forking. Children inherit the memory and the lock, so their
    increments land in the same slots, and the parent's MetricsFlusher reads them.
    """

    def __init__(self, series):
        self.series = list(series)
        self.index = {key: i for i, key in enumerate(self.series)}
        context = multiprocessing.get_context("fork")
        self.values = context.RawArray(ctypes.c_uint64, len(self.series))
        self.lock = context.Lock()

    def inc(self, name: str, labels: str = "", amount: int = 1):
        i = self.index.get((name, labels))
        if i is None or amount <= 0:
            return
        with self.lock:
            self.values[i] += amount

    def snapshot(self) -> list:
        with self.lock:
            return list(self.values)


# This process's counters, see install()
_counters: SharedCounters | None = None


def install(counters: SharedCounters | None):
    """Makes inc() count into counters, in this process and every child it forks afterwards."""
    global _counters
    _counters = counters
    return counters


def inc(name: str, labels: str = "", amount: int = 1):
    """Hot path counter increment. A no-op in a process that didn't install() counters, and
    never raises: losing a count must never break message handling."""
    counters = _counters
    if counters is None:
        return
    try:
        counters.inc(name, labels, amount)
    except Exception:
        pass


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _upsert(connection, name, labels, kind, value, now, add):
    """Adds value to (add=True) or sets (add=False) one metric_counters row, creating it."""
    from raven.models.MetricCounter import MetricCounter

    table = MetricCounter.__table__
    dialect = connection.dialect.name
    if dialect in ("postgresql", "sqlite"):
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert

        stmt = insert(table).values(
            name=name, labels=labels, kind=kind, value=value, updated_at=now
        )
        new_value = table.c.value + stmt.excluded.value if add else stmt.excluded.value
        connection.execute(
            stmt.on_conflict_do_update(
                index_elements=[table.c.name, table.c.labels],
                set_={"value": new_value, "updated_at": now, "kind": kind},
            )
        )
        return

    where = (table.c.name == name) & (table.c.labels == labels)
    result = connection.execute(
        table.update()
        .where(where)
        .values(value=(table.c.value + value) if add else value, updated_at=now, kind=kind)
    )
    if not result.rowcount:
        connection.execute(
            table.insert().values(name=name, labels=labels, kind=kind, value=value, updated_at=now)
        )


def write(counters=None, gauges=None, source=None):
    """Writes counter deltas and gauge values in one transaction. Needs an app context.

    :param counters: {(name, labels): delta}
    :param gauges: {(name, labels): value}
    :param source: also stamps raven_metrics_last_flush_timestamp_seconds{source=...}
    """
    now = _now()
    with db.engine.begin() as connection:
        for (name, labels), delta in (counters or {}).items():
            if delta > 0:
                _upsert(connection, name, labels, COUNTER, int(delta), now, add=True)
        for (name, labels), value in (gauges or {}).items():
            _upsert(connection, name, labels, GAUGE, int(value), now, add=False)
        if source:
            _upsert(
                connection,
                "raven_metrics_last_flush_timestamp_seconds",
                f'source="{source}"',
                GAUGE,
                int(time.time()),
                now,
                add=False,
            )


def record(name: str, labels: str = "", amount: int = 1) -> bool:
    """Adds to a counter straight away, for rare events in the web app (one small transaction
    of its own, the caller's session is untouched). Never raises; returns False if it couldn't."""
    try:
        write(counters={(name, labels): amount})
        return True
    except BaseException as e:
        logger.warning(f"Failed to record metric {name}: {e}")
        logger.debug(traceback.format_exc())
        return False


class MetricsFlusher(threading.Thread):
    """Periodically writes a SharedCounters' growth (and this service's gauges) to the DB.

    :param labels: added to every series this service writes, e.g. ``transport="ssl"``
    :param source: names this service in raven_metrics_last_flush_timestamp_seconds
    :param gauges: callable returning {(name, labels): value}, labels used as given
    """

    def __init__(self, app, counters: SharedCounters, source: str, labels: str = "", gauges=None):
        super().__init__(name=f"metrics-{source}", daemon=True)
        self.app = app
        self.counters = counters
        self.source = source
        self.labels = labels
        self.gauges = gauges
        self.interval = max(1, int(app.config.get("RAVEN_METRICS_FLUSH_INTERVAL") or 10))
        # What the DB already has. Starts at zero: SharedCounters start at zero with the process.
        self.flushed = [0] * len(counters.series)
        self.stopped = threading.Event()

    def run(self):
        while not self.stopped.wait(self.interval):
            self.flush()

    def stop(self):
        self.stopped.set()
        self.flush()

    def flush(self) -> bool:
        values = self.counters.snapshot()
        deltas = {}
        for i, (name, labels) in enumerate(self.counters.series):
            delta = values[i] - self.flushed[i]
            if delta > 0:
                deltas[(name, join_labels(labels, self.labels))] = delta
        try:
            gauges = self.gauges() if self.gauges else {}
            with self.app.app_context():
                write(counters=deltas, gauges=gauges, source=self.source)
            # Only now: if the write failed, the next flush retries the same growth
            self.flushed = values
            return True
        except BaseException as e:
            logger.warning(f"Failed to flush {self.source} metrics: {e}")
            logger.debug(traceback.format_exc())
            return False


# --- Reading (raven web app) ---


def read_rows(session):
    """Every metric_counters row as (name, labels, kind, value, updated_at), gauges whose service
    has stopped flushing reported as 0 (their last value would otherwise linger forever)."""
    from flask import current_app
    from raven.models.MetricCounter import MetricCounter

    interval = max(1, int(current_app.config.get("RAVEN_METRICS_FLUSH_INTERVAL") or 10))
    stale_before = _now() - timedelta(seconds=interval * STALE_INTERVALS)
    rows = []
    for row in session.query(MetricCounter).order_by(MetricCounter.name, MetricCounter.labels):
        value = row.value
        if (
            row.kind == GAUGE
            and row.name != "raven_metrics_last_flush_timestamp_seconds"
            and row.updated_at < stale_before
        ):
            value = 0
        rows.append((row.name, row.labels, row.kind, value, row.updated_at))
    return rows


def totals(rows) -> dict:
    """{name: sum over every label set}"""
    result = {}
    for name, _labels, _kind, value, _updated in rows:
        result[name] = result.get(name, 0) + value
    return result


def by_label(rows, name: str, label: str) -> dict:
    """{label value: sum} for one metric.

    e.g. by_label(rows, "raven_cot_received_total", "category") -> {"chat": 4, "position": 6}
    """
    pattern = re.compile(rf'(?:^|,){re.escape(label)}="([^"]*)"')
    result = {}
    for row_name, labels, _kind, value, _updated in rows:
        if row_name != name:
            continue
        match = pattern.search(labels or "")
        key = match.group(1) if match else ""
        result[key] = result.get(key, 0) + value
    return result


def connected_euds(session) -> int:
    from sqlalchemy import func, select
    from raven.models.EUD import EUD

    return session.execute(
        select(func.count()).select_from(EUD).where(EUD.last_status == "Connected")
    ).scalar_one()


def take_sample(session):
    """Stores one MetricSample of the current totals and prunes old ones. Needs an app context."""
    from raven.models.MetricSample import MetricSample

    sums = totals(read_rows(session))
    now = _now()
    session.add(
        MetricSample(
            timestamp=now,
            cot_received=sums.get("raven_cot_received_total", 0),
            cot_sent=sums.get("raven_cot_sent_total", 0),
            bytes_received=sums.get("raven_bytes_received_total", 0),
            bytes_sent=sums.get("raven_bytes_sent_total", 0),
            euds_connected=connected_euds(session),
        )
    )
    session.query(MetricSample).filter(MetricSample.timestamp < now - SAMPLE_RETENTION).delete()
    session.commit()


def sample_rates(samples) -> list:
    """Per minute rates between consecutive MetricSamples (oldest first).

    A counter going down means its rows were reset, that interval counts as 0.
    """
    points = []
    for previous, sample in zip(samples, samples[1:]):
        minutes = (sample.timestamp - previous.timestamp).total_seconds() / 60
        if minutes <= 0:
            continue

        def rate(field):
            delta = getattr(sample, field) - getattr(previous, field)
            return round(max(0, delta) / minutes, 1)

        points.append(
            {
                "timestamp": sample.timestamp,
                "received": rate("cot_received"),
                "sent": rate("cot_sent"),
                "bytes_received": rate("bytes_received"),
                "bytes_sent": rate("bytes_sent"),
                "euds_connected": sample.euds_connected,
            }
        )
    return points
