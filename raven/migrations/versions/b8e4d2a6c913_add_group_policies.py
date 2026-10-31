"""Added group policies (default access, auto-join, membership expiry, lock)

Revision ID: b8e4d2a6c913
Revises: e5a9c3f17b20
Create Date: 2026-10-31 16:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b8e4d2a6c913"
down_revision = "e5a9c3f17b20"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("groups", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("default_access", sa.String(length=8), nullable=True, server_default="both")
        )
        batch_op.add_column(
            sa.Column("auto_join", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch_op.add_column(sa.Column("default_membership_days", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("locked", sa.Boolean(), nullable=False, server_default=sa.false())
        )

    with op.batch_alter_table("groups_users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_groups_users_expires_at"), ["expires_at"], unique=False
        )


def downgrade():
    with op.batch_alter_table("groups_users", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_groups_users_expires_at"))
        batch_op.drop_column("expires_at")

    with op.batch_alter_table("groups", schema=None) as batch_op:
        batch_op.drop_column("locked")
        batch_op.drop_column("default_membership_days")
        batch_op.drop_column("auto_join")
        batch_op.drop_column("default_access")
