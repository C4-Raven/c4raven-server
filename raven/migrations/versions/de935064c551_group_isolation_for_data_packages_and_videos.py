"""Group isolation for data packages and video streams

Adds data_packages_groups and video_streams_groups (see raven/group_isolation.py). Existing
packages and streams get no rows, which keeps them visible to everyone.

Revision ID: de935064c551
Revises: d3f1a7c95b20
Create Date: 2026-11-02 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "de935064c551"
down_revision = "d3f1a7c95b20"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "data_packages_groups",
        sa.Column("data_package_id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["data_package_id"], ["data_packages.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("data_package_id", "group_id"),
    )
    op.create_table(
        "video_streams_groups",
        sa.Column("video_stream_path", sa.String(length=255), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["video_stream_path"],
            ["video_streams.path"],
            ondelete="CASCADE",
            onupdate="CASCADE",
        ),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("video_stream_path", "group_id"),
    )


def downgrade():
    op.drop_table("video_streams_groups")
    op.drop_table("data_packages_groups")
