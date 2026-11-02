from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db


@dataclass
class MetricCounter(db.Model):
    """One Prometheus series (a metric name plus its rendered label set) for /api/metrics.

    eud_handler, cot_parser and raven are separate processes (eud_handler and cot_parser fork
    more of their own), so each one counts in memory and raven.metrics flushes the deltas here
    every few seconds with an atomic ``value = value + delta``. Counter rows only ever go up and
    survive restarts, which is what Prometheus expects of a counter. Gauge rows are overwritten
    by their one owning process; updated_at lets readers ignore a gauge whose process died.

    labels is the already rendered label set, e.g. ``category="chat",transport="ssl"``.
    updated_at is naive UTC, like audit_events.timestamp.
    """

    __tablename__ = "metric_counters"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    labels: Mapped[str] = mapped_column(String(255), primary_key=True, default="")
    # counter or gauge
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="counter")
    value: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
