from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db


@dataclass
class RetentionSetting(db.Model):
    """How long one type of data is kept (see raven/retention.py).

    One row per data type, written the first time an admin changes that type
    or the purge job runs for it. A type with no row uses the default from
    raven.retention.DATA_TYPES. keep_seconds NULL means keep forever.
    Timestamps are naive UTC.
    """

    __tablename__ = "retention_settings"

    data_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    keep_seconds: Mapped[int] = mapped_column(Integer, nullable=True)
    # Explicitly saved by an admin (as opposed to a row the purge job created
    # only to record its last run). Lets a later change to a type's default
    # still reach installs where nobody ever touched that type.
    customized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(255), nullable=True)
    last_purge_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_purge_count: Mapped[int] = mapped_column(Integer, nullable=True)
    last_purge_error: Mapped[str] = mapped_column(Text, nullable=True)
