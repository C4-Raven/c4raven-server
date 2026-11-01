from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, false, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db
from raven.models.DeviceProfileSetting import DeviceProfileSetting  # noqa: F401
from raven.models.DeviceProfileTarget import DeviceProfileTarget  # noqa: F401


def utcnow() -> datetime:
    """Naive UTC, like the other timestamp columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class DeviceProfileSet(db.Model):
    """A named bundle of ATAK settings sent to an audience (targets) at enrollment and/or on
    connection. Resolution lives in raven/device_profiles.py."""

    __tablename__ = "device_profile_sets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    apply_on_enrollment: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    apply_on_connection: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    target_everyone: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    targets = relationship(
        "DeviceProfileTarget",
        back_populates="profile",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DeviceProfileTarget.id",
    )
    settings = relationship(
        "DeviceProfileSetting",
        back_populates="profile",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DeviceProfileSetting.id",
    )
