from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, false, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db
from raven.models.DeviceProfileFile import DeviceProfileFile  # noqa: F401
from raven.models.DeviceProfileSetting import DeviceProfileSetting  # noqa: F401
from raven.models.DeviceProfileTarget import DeviceProfileTarget  # noqa: F401


def utcnow() -> datetime:
    """Naive UTC, like the other timestamp columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class DeviceProfileSet(db.Model):
    """A named bundle of ATAK settings and files sent to an audience (targets) at enrollment
    and/or on connection, or, with a tool name, only when a device asks for that tool's profile
    (/Marti/api/device/profile/tool/<tool>). Resolution lives in raven/device_profiles.py."""

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
    # Set: a tool profile, served only by the tool endpoint (the enrollment/connection flags are
    # ignored). Matched case-insensitively.
    tool: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
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
    files = relationship(
        "DeviceProfileFile",
        back_populates="profile",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DeviceProfileFile.id",
    )
