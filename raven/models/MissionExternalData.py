import datetime
from dataclasses import dataclass

from sqlalchemy import TEXT, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db


@dataclass
class MissionExternalData(db.Model):
    """A link to data that lives outside the server (TAK Server's ExternalMissionData)"""

    __tablename__ = "mission_external_data"
    __table_args__ = (UniqueConstraint("mission_name", "uid"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[str] = mapped_column(String(255), nullable=False)
    mission_name: Mapped[str] = mapped_column(
        String(255), ForeignKey("missions.name", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    tool: Mapped[str] = mapped_column(String(255), nullable=True)
    url_data: Mapped[str] = mapped_column(TEXT, nullable=True)
    url_view: Mapped[str] = mapped_column(TEXT, nullable=True)
    notes: Mapped[str] = mapped_column(TEXT, nullable=True)
    creator_uid: Mapped[str] = mapped_column(String(255), nullable=True)
    create_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    mission = relationship("Mission", back_populates="external_data_items")

    def serialize(self):
        return {
            "uid": self.uid,
            "mission_name": self.mission_name,
            "name": self.name,
            "tool": self.tool,
            "url_data": self.url_data,
            "url_view": self.url_view,
            "notes": self.notes,
            "creator_uid": self.creator_uid,
            "create_time": self.create_time,
        }

    def to_json(self):
        # Exactly TAK Server's ExternalMissionData fields: Jackson-based clients reject unknown ones
        return {
            "id": self.uid,
            "name": self.name or "",
            "tool": self.tool or "",
            "urlData": self.url_data or "",
            "urlView": self.url_view or "",
            "notes": self.notes or "",
        }
