from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime


@dataclass
class AuditEvent(db.Model):
    """One security-relevant event (web login, device enrollment, cert issue,
    admin change to an account...) for the admin Security Audit page.

    Written only through raven.audit.record_audit_event(). username/actor are
    plain strings, not foreign keys, so the trail survives a user being deleted
    and inserting a row never has to wait on a lock on the user table.
    timestamp is naive UTC, like Flask-Security's trackable columns.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    # auth, enrollment, certificate, user_admin, security
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # The account the event is about
    username: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    # The admin who did it, when that's someone other than username
    actor: Mapped[str] = mapped_column(String(255), nullable=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    details: Mapped[str] = mapped_column(Text, nullable=True)

    def to_json(self):
        return {
            "id": self.id,
            "timestamp": iso8601_string_from_datetime(self.timestamp) if self.timestamp else None,
            "category": self.category,
            "action": self.action,
            "username": self.username,
            "actor": self.actor,
            "ip": self.ip,
            "user_agent": self.user_agent,
            "success": bool(self.success),
            "details": self.details,
        }
