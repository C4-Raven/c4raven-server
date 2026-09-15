import datetime
from dataclasses import dataclass

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime


@dataclass
class MissionUID(db.Model):
    __tablename__ = "mission_uids"

    uid: Mapped[str] = mapped_column(String(255), primary_key=True)  # Equals the original CoT's UID
    mission_name: Mapped[str] = mapped_column(
        String(255), ForeignKey("missions.name"), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    creator_uid: Mapped[str] = mapped_column(String(255), nullable=True)
    cot_type: Mapped[str] = mapped_column(String(255), nullable=True)
    callsign: Mapped[str] = mapped_column(String(255), nullable=True)
    iconset_path: Mapped[str] = mapped_column(String(255), nullable=True)
    color: Mapped[str] = mapped_column(String(255), nullable=True)
    latitude: Mapped[float] = mapped_column(Float, nullable=True)
    longitude: Mapped[float] = mapped_column(Float, nullable=True)
    mission = relationship("Mission", back_populates="uids")
    mission_change = relationship("MissionChange", back_populates="uid", uselist=False)

    def serialize(self):
        return {
            "timestamp": self.timestamp,
            "creator_uid": self.creator_uid,
            "cot_type": self.cot_type,
            "callsign": self.callsign,
            "iconset_path": self.iconset_path,
            "color": self.color,
            "latitude": self.latitude,
            "longitude": self.longitude,
        }

    def color_as_int(self) -> int:
        # WinTAK deserializes details.color into a non-nullable C# Int32 --
        # a null or non-numeric string throws a JsonSerializationException
        # and aborts the whole GetMissionsAsync call. -1 (0xFFFFFFFF, opaque
        # white) is the standard CoT/ATAK default for "no color override".
        try:
            return int(self.color)
        except (TypeError, ValueError):
            return -1

    def to_json(self):
        return {
            "data": self.uid,
            "timestamp": iso8601_string_from_datetime(self.timestamp),
            "creatorUid": self.creator_uid if self.creator_uid else "",
            "details": {
                "type": self.cot_type,
                "callsign": self.callsign,
                "iconsetPath": self.iconset_path,
                "color": self.color_as_int(),
                "location": {
                    "lat": self.latitude if self.latitude is not None else 0.0,
                    "lon": self.longitude if self.longitude is not None else 0.0,
                },
            },
        }

    def to_details_json(self):
        return {
            "type": self.cot_type,
            "callsign": self.callsign,
            "iconsetPath": self.iconset_path,
            "color": self.color_as_int(),
            "location": {
                "lat": self.latitude if self.latitude is not None else 0.0,
                "lon": self.longitude if self.longitude is not None else 0.0,
            },
        }
