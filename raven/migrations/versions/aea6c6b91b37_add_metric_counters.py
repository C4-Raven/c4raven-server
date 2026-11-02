"""Added metric_counters and metric_samples tables for message metrics

metric_counters holds the message counters every eud_handler / cot_parser service flushes
(see raven/metrics.py), metric_samples the once a minute snapshots behind the Dashboard's
message rate chart.

Revision ID: aea6c6b91b37
Revises: d3f1a7c95b20
Create Date: 2026-11-02 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "aea6c6b91b37"
down_revision = "d3f1a7c95b20"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "metric_counters",
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("labels", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("name", "labels"),
    )
    op.create_table(
        "metric_samples",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("cot_received", sa.BigInteger(), nullable=False),
        sa.Column("cot_sent", sa.BigInteger(), nullable=False),
        sa.Column("bytes_received", sa.BigInteger(), nullable=False),
        sa.Column("bytes_sent", sa.BigInteger(), nullable=False),
        sa.Column("euds_connected", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("metric_samples", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_metric_samples_timestamp"), ["timestamp"], unique=False
        )


def downgrade():
    with op.batch_alter_table("metric_samples", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_metric_samples_timestamp"))

    op.drop_table("metric_samples")
    op.drop_table("metric_counters")
