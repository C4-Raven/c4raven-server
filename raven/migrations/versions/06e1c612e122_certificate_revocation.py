"""Track certificate serials and revocation

Adds serial_number, revoked_at and revocation_reason to certificates so an admin
can revoke a client certificate from the Users page (certificate_api). The CA's
crl_index.txt / ca.crl stay the source of truth for enforcement; these columns
are what the web UI shows. serial_number is NULL for certs issued before this
revision, certificate_api fills it in from the PEM on disk where it still can.

Revision ID: 06e1c612e122
Revises: d3f1a7c95b20
Create Date: 2026-11-02 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "06e1c612e122"
down_revision = "d3f1a7c95b20"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.add_column(sa.Column("serial_number", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("revoked_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("revocation_reason", sa.String(length=64), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_certificates_serial_number"), ["serial_number"], unique=False
        )


def downgrade():
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_certificates_serial_number"))
        batch_op.drop_column("revocation_reason")
        batch_op.drop_column("revoked_at")
        batch_op.drop_column("serial_number")
