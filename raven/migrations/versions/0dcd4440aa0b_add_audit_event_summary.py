"""Added a summary column to audit_events for the admin action audit log

Revision ID: 0dcd4440aa0b
Revises: de935064c551
Create Date: 2026-11-02 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0dcd4440aa0b"
down_revision = "de935064c551"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("summary", sa.String(length=255), nullable=True))


def downgrade():
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_column("summary")
