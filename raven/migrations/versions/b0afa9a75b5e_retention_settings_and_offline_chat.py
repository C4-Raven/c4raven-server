"""Per data type retention settings and the offline chat queue

Adds retention_settings (raven/retention.py; no rows are seeded, a type without a row uses its
default) and offline_chat_messages (raven/offline_chat.py).

Revision ID: b0afa9a75b5e
Revises: bb6e15297a77
Create Date: 2026-11-02 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b0afa9a75b5e"
down_revision = "bb6e15297a77"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "retention_settings",
        sa.Column("data_type", sa.String(length=64), nullable=False),
        sa.Column("keep_seconds", sa.Integer(), nullable=True),
        sa.Column("customized", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.Column("last_purge_at", sa.DateTime(), nullable=True),
        sa.Column("last_purge_count", sa.Integer(), nullable=True),
        sa.Column("last_purge_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("data_type"),
    )

    op.create_table(
        "offline_chat_messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("recipient_uid", sa.String(length=255), nullable=False),
        sa.Column("sender_uid", sa.String(length=255), nullable=True),
        sa.Column("chatroom_id", sa.String(length=255), nullable=True),
        sa.Column("message_uid", sa.String(length=255), nullable=False),
        sa.Column("xml", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "recipient_uid", "message_uid", name="uq_offline_chat_recipient_message"
        ),
    )
    op.create_index(
        "ix_offline_chat_messages_recipient_uid",
        "offline_chat_messages",
        ["recipient_uid"],
        unique=False,
    )
    op.create_index(
        "ix_offline_chat_messages_created_at",
        "offline_chat_messages",
        ["created_at"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_offline_chat_messages_created_at", table_name="offline_chat_messages")
    op.drop_index("ix_offline_chat_messages_recipient_uid", table_name="offline_chat_messages")
    op.drop_table("offline_chat_messages")
    op.drop_table("retention_settings")
