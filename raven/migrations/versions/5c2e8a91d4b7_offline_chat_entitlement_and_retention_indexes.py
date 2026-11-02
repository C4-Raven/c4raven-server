"""Offline chat entitlement and receive tracking, indexes for the retention job

offline_chat_messages gets recipient_user_id (the user the recipient device belonged to when the
message was queued; only a connection authenticated as that user gets it) and read_groups
(for team chat, the JSON list of group ids that may read it, re-checked at delivery).
euds gets last_rx_at, when the server last received data from the device (naive UTC, written at
most every 30 seconds per connection), used to tell which queued chat a still-connected device
got live (raven/offline_chat.py).

Plain (non-concurrent) indexes on the time and point_id columns the retention purge filters on;
on a server with large points/geochat/eud_stats tables the upgrade can take a while and blocks
inserts into each table while its index builds.

Revision ID: 5c2e8a91d4b7
Revises: b7e3c1d9a4f2
Create Date: 2026-11-03 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "5c2e8a91d4b7"
down_revision = "b7e3c1d9a4f2"
branch_labels = None
depends_on = None

INDEXES = (
    ("points", "ix_points_timestamp", ["timestamp"]),
    ("geochat", "ix_geochat_timestamp", ["timestamp"]),
    ("eud_stats", "ix_eud_stats_timestamp", ["timestamp"]),
    ("alerts", "ix_alerts_start_time", ["start_time"]),
    ("markers", "ix_markers_point_id", ["point_id"]),
    ("geochat", "ix_geochat_point_id", ["point_id"]),
    ("rb_lines", "ix_rb_lines_point_id", ["point_id"]),
    ("casevac", "ix_casevac_point_id", ["point_id"]),
    ("alerts", "ix_alerts_point_id", ["point_id"]),
    ("citrap", "ix_citrap_point_id", ["point_id"]),
)


def upgrade():
    with op.batch_alter_table("offline_chat_messages", schema=None) as batch_op:
        batch_op.add_column(sa.Column("recipient_user_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("read_groups", sa.Text(), nullable=True))

    with op.batch_alter_table("euds", schema=None) as batch_op:
        batch_op.add_column(sa.Column("last_rx_at", sa.DateTime(), nullable=True))

    for table, name, columns in INDEXES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.create_index(name, columns, unique=False)


def downgrade():
    for table, name, columns in reversed(INDEXES):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_index(name)

    with op.batch_alter_table("euds", schema=None) as batch_op:
        batch_op.drop_column("last_rx_at")

    with op.batch_alter_table("offline_chat_messages", schema=None) as batch_op:
        batch_op.drop_column("read_groups")
        batch_op.drop_column("recipient_user_id")
