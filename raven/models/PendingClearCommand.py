from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime


@dataclass
class PendingClearCommand(db.Model):
    """A remote clear-content command queued for a device that was offline when
    an admin issued it.

    The web UI's "Remote clear content" prompt lets the admin choose to queue
    the command for offline devices instead of only reaching whoever is online
    right now. When that option is set, one row is written per offline device.
    On the device's next connection, EudHandler delivers every undelivered row
    for that uid and stamps ``delivered_at``.

    The command is deliberately NOT pre-serialized here: the signed CoT carries
    an ``issued`` timestamp and nonce, and the plugin rejects anything outside a
    +/-15 minute freshness window, so a command stored for hours would be stale.
    Only the intent (target uid + whether to clear maps) is stored; the signed
    CoT is built fresh by raven.remote_clear at delivery time.
    """

    __tablename__ = "pending_clear_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # The target device uid. Indexed because the reconnect path looks rows up
    # by uid on every device connection.
    eud_uid: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    clearmaps: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # NULL until the command has been published to the reconnected device. Rows
    # are kept after delivery for audit; the reconnect query filters on NULL so
    # a delivered command is never sent twice (which would wipe-loop a device).
    delivered_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    node_id: Mapped[str] = mapped_column(String(255), nullable=True)

    def serialize(self):
        return {
            "id": self.id,
            "eud_uid": self.eud_uid,
            "clearmaps": self.clearmaps,
            "requested_by": self.requested_by,
            "requested_at": iso8601_string_from_datetime(self.requested_at)
            if self.requested_at
            else None,
            "delivered_at": iso8601_string_from_datetime(self.delivered_at)
            if self.delivered_at
            else None,
            "node_id": self.node_id,
        }

    def to_json(self):
        return self.serialize()
