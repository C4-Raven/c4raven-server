from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime


@dataclass
class SupportingDocument(db.Model):
    __tablename__ = "supporting_documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    # Random on-disk name, decoupled from the (user-controlled) original
    # filename to avoid path traversal / collisions.
    stored_filename: Mapped[str] = mapped_column(String(255), unique=True)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=True)
    size: Mapped[int] = mapped_column(Integer)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime)
    # SET NULL so deleting the uploading user (user_api.delete_user) does not fail on
    # the FK; the document itself stays available.
    uploaded_by_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    uploaded_by = relationship("User", back_populates="supporting_documents")

    def to_json(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "mime_type": self.mime_type,
            "size": self.size,
            "uploaded_at": iso8601_string_from_datetime(self.uploaded_at),
            "uploaded_by": self.uploaded_by.username if self.uploaded_by else None,
        }
