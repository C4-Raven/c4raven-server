"""Mission layers (folders), external data and feeds

Adds mission_layers, mission_external_data and mission_feeds, and snapshot columns on
mission_changes (external_data, mission_feed, mission_layer) so a change still describes what was
removed after the row itself is gone. The old missions.external_data / missions.feeds JSON columns
are left alone (the mission JSON falls back to them when a mission has no rows in the new tables).

Revision ID: 30dad796cc32
Revises: b0afa9a75b5e
Create Date: 2026-11-02 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "30dad796cc32"
down_revision = "b0afa9a75b5e"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mission_layers",
        sa.Column("uid", sa.String(length=255), nullable=False),
        sa.Column("mission_name", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("parent_uid", sa.String(length=255), nullable=True),
        sa.Column("after", sa.String(length=255), nullable=True),
        sa.Column("uids", sa.JSON(), nullable=True),
        sa.Column("hashes", sa.JSON(), nullable=True),
        sa.Column("creator_uid", sa.String(length=255), nullable=True),
        sa.Column("create_time", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["mission_name"], ["missions.name"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_uid"], ["mission_layers.uid"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("uid"),
    )
    op.create_index(
        op.f("ix_mission_layers_mission_name"), "mission_layers", ["mission_name"], unique=False
    )

    op.create_table(
        "mission_external_data",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("uid", sa.String(length=255), nullable=False),
        sa.Column("mission_name", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("tool", sa.String(length=255), nullable=True),
        sa.Column("url_data", sa.TEXT(), nullable=True),
        sa.Column("url_view", sa.TEXT(), nullable=True),
        sa.Column("notes", sa.TEXT(), nullable=True),
        sa.Column("creator_uid", sa.String(length=255), nullable=True),
        sa.Column("create_time", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["mission_name"], ["missions.name"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("mission_name", "uid"),
    )

    op.create_table(
        "mission_feeds",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("uid", sa.String(length=255), nullable=False),
        sa.Column("mission_name", sa.String(length=255), nullable=False),
        sa.Column("data_feed_uid", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("filter_bbox", sa.String(length=1024), nullable=True),
        sa.Column("filter_type", sa.String(length=1024), nullable=True),
        sa.Column("filter_callsign", sa.String(length=255), nullable=True),
        sa.Column("creator_uid", sa.String(length=255), nullable=True),
        sa.Column("create_time", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["mission_name"], ["missions.name"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uid"),
    )

    with op.batch_alter_table("mission_changes", schema=None) as batch_op:
        batch_op.add_column(sa.Column("external_data", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("mission_feed", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("mission_layer", sa.JSON(), nullable=True))


def downgrade():
    # Layer changes are a C4 RAVEN addition older code doesn't know how to show
    op.execute(
        "DELETE FROM mission_changes WHERE change_type IN "
        "('ADD_MISSION_LAYER', 'UPDATE_MISSION_LAYER', 'REMOVE_MISSION_LAYER')"
    )
    with op.batch_alter_table("mission_changes", schema=None) as batch_op:
        batch_op.drop_column("mission_layer")
        batch_op.drop_column("mission_feed")
        batch_op.drop_column("external_data")

    op.drop_table("mission_feeds")
    op.drop_table("mission_external_data")
    op.drop_index(op.f("ix_mission_layers_mission_name"), table_name="mission_layers")
    op.drop_table("mission_layers")
