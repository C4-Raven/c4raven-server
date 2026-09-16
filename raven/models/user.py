from dataclasses import dataclass

from flask_security.models import fsqla_v3 as fsqla
from sqlalchemy import String
from sqlalchemy.orm import relationship

from raven.extensions import db
from raven.models.Group import Group

# Leave these imports here: they are the relationship targets User names as
# strings below, and SQLAlchemy can only resolve those once the classes have
# been imported into the registry. Importing them here (rather than relying
# on whichever blueprint happens to import them) is what lets the standalone
# processes -- eud_handler, cot_parser, fedhub_bridge -- configure the User
# mapper at all.
from raven.models.SupportingDocument import SupportingDocument  # noqa: F401
from raven.models.DataPackageRecipient import DataPackageRecipient  # noqa: F401
from raven.models.Token import Token
from raven.models.WebAuthn import WebAuthn


@dataclass
class User(db.Model, fsqla.FsUserMixin):
    email = db.Column(String(255), nullable=True)
    site_access = db.Column(db.Boolean, nullable=False, default=True, server_default="true")
    # CUSTOM: force_password_change patch -- when true, user is blocked from all
    # API access except changing their password, until they do so.
    force_password_change = db.Column(db.Boolean, nullable=False, default=False, server_default="false")
    video_streams = relationship("VideoStream", back_populates="user")
    euds = relationship("EUD", back_populates="user")
    data_packages = relationship("DataPackage", back_populates="user")
    certificate = relationship("Certificate", back_populates="user")
    mission_invitations = relationship("MissionInvitation", back_populates="user")
    tokens = relationship("Token", back_populates="user")
    supporting_documents = relationship("SupportingDocument", back_populates="uploaded_by")
    groups = relationship(
        "Group",
        secondary="groups_users",
        viewonly=True,
        back_populates="users",
        cascade="all, delete",
    )
    group_memberships = relationship("GroupUser", back_populates="user", cascade="all, delete")

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "active": self.active,
            "site_access": self.site_access,
            "last_login_at": self.last_login_at,
            "last_login_ip": self.last_login_ip,
            "current_login_at": self.current_login_at,
            "current_login_ip": self.current_login_ip,
            "email": self.email,
            "login_count": self.login_count,
            "euds": [eud.serialize() for eud in self.euds],
            "video_streams": [v.serialize() for v in self.video_streams],
            "roles": [role.serialize() for role in self.roles],
            "groups": [group.serialize() for group in self.groups],
            "group_memberships": [membership.to_json() for membership in self.group_memberships],
        }

    def to_json(self):
        response = self.serialize()
        response["token"] = self.get_auth_token()
        return response
