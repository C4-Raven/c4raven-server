from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db


@dataclass
class DeviceProfileFile(db.Model):
    """A file shipped inside a DeviceProfileSet's data package (a .pref, map source, imagery,
    plugin APK, certificate...). The bytes live under RAVEN_DATA_FOLDER/device_profile_files as
    stored_name; zip_path is where it goes in the zip, which ATAK's import sorters key off."""

    __tablename__ = "device_profile_files"
    __table_args__ = (
        UniqueConstraint("profile_id", "zip_path", name="uq_device_profile_files_profile_path"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    profile_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("device_profile_sets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    zip_path: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=True)
    uploaded_by: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    profile = relationship("DeviceProfileSet", back_populates="files")
