import os
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime


@dataclass
class DataPackage(db.Model):
    __tablename__ = "data_packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Not unique: clients routinely reuse a generic filename for distinct
    # content -- TAKX's chat/quick-file-share feature names every package
    # "chat-transfer.zip" regardless of what's inside. hash is the real
    # content identity and is already unique on its own.
    filename: Mapped[str] = mapped_column(String(255))
    hash: Mapped[str] = mapped_column(String(255), unique=True)
    creator_uid: Mapped[str] = mapped_column(
        String(255), ForeignKey("euds.uid", ondelete="CASCADE"), nullable=True
    )
    submission_time: Mapped[datetime] = mapped_column(DateTime)
    submission_user: Mapped[int] = mapped_column(Integer, ForeignKey("user.id"), nullable=True)
    keywords: Mapped[str] = mapped_column(String(255), nullable=True)
    mime_type: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    tool: Mapped[str] = mapped_column(String(255), nullable=True)
    expiration: Mapped[str] = mapped_column(String(255), nullable=True)
    install_on_enrollment: Mapped[bool] = mapped_column(Boolean, default=False, nullable=True)
    install_on_connection: Mapped[bool] = mapped_column(Boolean, default=False, nullable=True)
    eud: Mapped["EUD"] = relationship(back_populates="data_packages")
    certificate = relationship("Certificate", back_populates="data_package", uselist=False)
    user = relationship("User", back_populates="data_packages")
    recipients = relationship(
        "DataPackageRecipient",
        back_populates="data_package",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @property
    def is_private(self) -> bool:
        """tool=private is what ATAK sets on user-to-user file transfers; anything else
        (including the NULL legacy rows predate the tool column being honoured) is
        public, matching TAK Server."""
        return (self.tool or "").strip().lower() == "private"

    def serialize(self):
        return {
            "filename": self.filename,
            "hash": self.hash,
            "creator_uid": self.creator_uid,
            "submission_time": self.submission_time,
            "submission_user": self.submission_user,
            "keywords": self.keywords,
            "mime_type": self.mime_type,
            "size": self.size,
            "tool": self.tool,
            "expiration": self.expiration,
            "install_on_enrollment": self.install_on_enrollment,
            "install_on_connection": self.install_on_connection,
            "private": self.is_private,
        }

    def to_json(self, include_eud=True):
        return {
            "filename": self.filename,
            "hash": self.hash,
            "creator_uid": self.creator_uid,
            "submission_time": iso8601_string_from_datetime(self.submission_time),
            "submission_user": self.user.username if self.user else None,
            "keywords": self.keywords,
            "mime_type": self.mime_type,
            "size": self.size,
            "tool": self.tool,
            "expiration": self.expiration,
            "eud": self.eud.to_json(False) if include_eud and self.eud else None,
            "install_on_enrollment": self.install_on_enrollment,
            "install_on_connection": self.install_on_connection,
            "private": self.is_private,
        }
