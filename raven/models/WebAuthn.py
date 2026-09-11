from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import db


class WebAuthn(db.Model, fsqla.FsWebAuthnMixin):
    pass
