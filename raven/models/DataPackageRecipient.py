from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db


@dataclass
class DataPackageRecipient(db.Model):
    """Who a private (user-to-user) data package was addressed to.

    ATAK's "send file to contact" uploads the file as a data package, marks it
    tool=private, then sends the contact a b-f-t-r (fileshare) CoT with the
    package hash and a <marti><dest callsign=.../> (or uid) for each recipient.
    cot_parser records those destinations here so the download endpoints can
    limit a private package to its sender and the people it was actually sent
    to. Either eud_uid or callsign may be NULL: ATAK/WinTAK address by
    callsign, iTAK by uid, and the callsign may not resolve to a known EUD
    yet at the time the CoT passes through.
    """

    __tablename__ = "data_package_recipients"
    __table_args__ = (
        UniqueConstraint(
            "data_package_hash", "eud_uid", "callsign", name="uq_data_package_recipient"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data_package_hash: Mapped[str] = mapped_column(
        String(255), ForeignKey("data_packages.hash", ondelete="CASCADE"), nullable=False
    )
    eud_uid: Mapped[str] = mapped_column(String(255), nullable=True)
    callsign: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    data_package = relationship("DataPackage", back_populates="recipients")

    def serialize(self):
        return {
            "data_package_hash": self.data_package_hash,
            "eud_uid": self.eud_uid,
            "callsign": self.callsign,
            "created_at": self.created_at,
        }

    def to_json(self):
        return self.serialize()
