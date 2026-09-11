from dataclasses import dataclass

from sqlalchemy import ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db


@dataclass
class UserFilterMember(db.Model):
    __tablename__ = "user_filters_members"

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("user.id"), primary_key=True)
    filter_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("user_filters.id"), primary_key=True
    )
    user = relationship("User", cascade="all, delete", viewonly=True)
    filter = relationship("UserFilter", cascade="all, delete", viewonly=True)

    def serialize(self):
        return {
            "user_id": self.user_id,
            "filter_id": self.filter_id,
        }
