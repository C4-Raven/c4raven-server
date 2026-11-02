from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db


@dataclass
class OfflineChatMessage(db.Model):
    """A GeoChat message held for a device that was offline when it was sent.

    cot_parser writes one row per offline recipient (raven/offline_chat.py);
    EudHandler writes the stored CoT straight to the device's socket when it
    next connects and stamps delivered_at. Rows older than the "offline_chat"
    retention setting (48 hours by default) are no longer delivered and are
    removed by the data retention job. Timestamps are naive UTC.
    """

    __tablename__ = "offline_chat_messages"
    __table_args__ = (
        UniqueConstraint("recipient_uid", "message_uid", name="uq_offline_chat_recipient_message"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Device uid, not a foreign key: the message should outlive the euds row
    # being recreated, and inserting here must never wait on a lock on euds.
    recipient_uid: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sender_uid: Mapped[str] = mapped_column(String(255), nullable=True)
    chatroom_id: Mapped[str] = mapped_column(String(255), nullable=True)
    # The GeoChat event uid, so the same message is only queued once per device
    message_uid: Mapped[str] = mapped_column(String(255), nullable=False)
    xml: Mapped[str] = mapped_column(Text, nullable=False)
    # The user the recipient device belonged to when the message was queued. When set, only a
    # connection authenticated as this user gets the message.
    recipient_user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    # Team chat only: JSON list of the group ids that may read it ([] for __ANON__), re-checked
    # against the connecting user at delivery. NULL for messages addressed with <dest>.
    read_groups: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    delivered_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
