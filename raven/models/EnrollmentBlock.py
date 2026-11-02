from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime


@dataclass
class EnrollmentBlock(db.Model):
    """A device (EUD uid, ATAK's clientUid) that may not enroll for a new certificate.

    Written when an admin revokes a certificate that was issued to a device
    (raven_api/certificate_api), so a lost or stolen phone can't simply enroll again with the
    user's saved credentials and get a fresh, valid cert. certificate_enrollment_api and
    /api/certificate refuse that uid with a 403 until an admin clears the block ("Allow this
    device to enroll again" on the user's certificates dialog).

    eud_uid is deliberately not a foreign key to euds: purging or deleting the EUD row (which
    cascades to its certificates) must not lift the block.
    """

    __tablename__ = "enrollment_blocks"

    eud_uid: Mapped[str] = mapped_column(String(255), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    # The revoked cert that put the block in place (normalized hex)
    serial_number: Mapped[str] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(String(64), nullable=True)
    # Naive UTC
    blocked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    blocked_by: Mapped[str] = mapped_column(String(255), nullable=True)

    def to_json(self):
        return {
            "eud_uid": self.eud_uid,
            "username": self.username,
            "serial_number": self.serial_number,
            "reason": self.reason,
            "blocked_at": iso8601_string_from_datetime(self.blocked_at) if self.blocked_at else None,
            "blocked_by": self.blocked_by,
        }
