"""Added cert_validity_days column to user table

How many days certificates issued for this user are valid for, set by an admin
on the Users page. NULL means the server default (RAVEN_CA_EXPIRATION_TIME).
Applies to every issuance path: the certificate data package, QR/token
enrollment and username/password enrollment.

Revision ID: c4e8a1d7b2f9
Revises: e1f2a3b4c5d6
Create Date: 2026-10-29 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c4e8a1d7b2f9"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.add_column(sa.Column("cert_validity_days", sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_column("cert_validity_days")
