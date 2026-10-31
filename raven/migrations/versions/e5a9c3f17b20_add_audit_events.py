"""Added audit_events table for the Security Audit page

Revision ID: e5a9c3f17b20
Revises: a7d3e9f2c418
Create Date: 2026-10-31 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e5a9c3f17b20"
down_revision = "a7d3e9f2c418"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_audit_events_timestamp"), ["timestamp"], unique=False)
        batch_op.create_index(batch_op.f("ix_audit_events_category"), ["category"], unique=False)
        batch_op.create_index(batch_op.f("ix_audit_events_action"), ["action"], unique=False)
        batch_op.create_index(batch_op.f("ix_audit_events_username"), ["username"], unique=False)


def downgrade():
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_audit_events_username"))
        batch_op.drop_index(batch_op.f("ix_audit_events_action"))
        batch_op.drop_index(batch_op.f("ix_audit_events_category"))
        batch_op.drop_index(batch_op.f("ix_audit_events_timestamp"))

    op.drop_table("audit_events")
