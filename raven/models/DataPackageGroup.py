from dataclasses import dataclass

from sqlalchemy import ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from raven.extensions import db


@dataclass
class DataPackageGroup(db.Model):
    """Which groups may see a data package (see raven/group_isolation.py).

    A package with no rows here is visible to everyone, which is what every
    package uploaded before group isolation existed looks like.
    """

    __tablename__ = "data_packages_groups"

    data_package_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("data_packages.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
