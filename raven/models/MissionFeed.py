import datetime
from dataclasses import dataclass

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db


@dataclass
class MissionFeed(db.Model):
    """A data feed subscribed to a mission (TAK Server's MissionFeed). data_feed_uid names the
    feed; the filters narrow what of it belongs to the mission."""

    __tablename__ = "mission_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    mission_name: Mapped[str] = mapped_column(
        String(255), ForeignKey("missions.name", ondelete="CASCADE"), nullable=False
    )
    data_feed_uid: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    filter_bbox: Mapped[str] = mapped_column(String(1024), nullable=True)
    filter_type: Mapped[str] = mapped_column(String(1024), nullable=True)
    filter_callsign: Mapped[str] = mapped_column(String(255), nullable=True)
    creator_uid: Mapped[str] = mapped_column(String(255), nullable=True)
    create_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    mission = relationship("Mission", back_populates="feed_items")

    def serialize(self):
        return {
            "uid": self.uid,
            "mission_name": self.mission_name,
            "data_feed_uid": self.data_feed_uid,
            "name": self.name,
            "filter_bbox": self.filter_bbox,
            "filter_type": self.filter_type,
            "filter_callsign": self.filter_callsign,
            "creator_uid": self.creator_uid,
            "create_time": self.create_time,
        }

    def to_json(self):
        return {
            "uid": self.uid,
            "dataFeedUid": self.data_feed_uid,
            "name": self.name or "",
            "filterBbox": self.filter_bbox or "",
            "filterType": self.filter_type or "",
            "filterCallsign": self.filter_callsign or "",
        }
