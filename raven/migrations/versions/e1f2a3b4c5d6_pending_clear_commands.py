"""Queue remote clear-content commands for offline devices

The web UI's "Remote clear content" prompt can now queue a wipe for a device
that is offline when the admin issues it, instead of only reaching devices that
are online right now. Each queued command is one row here; EudHandler delivers
every undelivered row for a uid on that device's next connection and stamps
delivered_at. Only the intent (target uid + clearmaps) is stored, since the
signed CoT is rebuilt fresh at delivery to stay inside the plugin's freshness
window.

Revision ID: e1f2a3b4c5d6
Revises: d9a3b4c5e6f7
Create Date: 2026-09-18 15:20:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e1f2a3b4c5d6"
down_revision = "d9a3b4c5e6f7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pending_clear_commands",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("eud_uid", sa.String(length=255), nullable=False),
        sa.Column("clearmaps", sa.Boolean(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("node_id", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("pending_clear_commands", schema=None) as batch_op:
        batch_op.create_index(
            "ix_pending_clear_commands_eud_uid", ["eud_uid"], unique=False
        )


def downgrade():
    with op.batch_alter_table("pending_clear_commands", schema=None) as batch_op:
        batch_op.drop_index("ix_pending_clear_commands_eud_uid")
    op.drop_table("pending_clear_commands")
