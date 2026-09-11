from dataclasses import dataclass

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db

# secondary="user_filters_members" below is resolved by table name against
# db.metadata at mapper-configuration time, not by class name -- that table
# only exists in metadata once UserFilterMember's own module has actually
# run. Every call site that touches UserFilter happened to import it lazily
# inside a function body, and whichever endpoint got hit first (usually
# GET /api/users/filters, which only imports UserFilter) triggered mapper
# configuration before UserFilterMember was ever imported, raising
# InvalidRequestError -- and once mapper configuration fails once, it's
# poisoned for every query for the rest of that process's life, not just
# the one that failed. Importing it here, unconditionally, closes the gap
# for every caller at once.
from raven.models.UserFilterMember import UserFilterMember  # noqa: F401


@dataclass
class UserFilter(db.Model):
    """A named, admin-managed subset of users -- lets the Users page and the
    Groups tab's member picker be scoped down to e.g. "My Team" instead of
    showing every user on the server. Membership is many-to-many (a user can
    be in more than one filter); see UserFilterMember.
    """

    __tablename__ = "user_filters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    users = relationship("User", secondary="user_filters_members", viewonly=True)

    def serialize(self):
        return {
            "id": self.id,
            "name": self.name,
            "usernames": [u.username for u in self.users],
        }
