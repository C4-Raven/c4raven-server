from dataclasses import dataclass

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db


@dataclass
class DeviceProfileSetting(db.Model):
    """One ATAK preference (key/value/class) in a DeviceProfileSet."""

    __tablename__ = "device_profile_settings"
    __table_args__ = (
        UniqueConstraint("profile_id", "key", name="uq_device_profile_settings_profile_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    profile_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("device_profile_sets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Full ATAK form, e.g. "class java.lang.Boolean"
    value_class: Mapped[str] = mapped_column(
        String(64), nullable=False, default="class java.lang.String"
    )

    profile = relationship("DeviceProfileSet", back_populates="settings")

    def to_json(self):
        return {"key": self.key, "value": self.value, "value_class": self.value_class}
