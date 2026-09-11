"""Added citrap table

Backs the Reports and Returns / CITRAP report submission endpoints
(raven/blueprints/marti_api/citrap_api.py). Ported from the upstream
project's in-progress "reports" branch, minus the geoalchemy2
Geography column on points (not a dependency this fork carries) --
reports are stored with plain lat/lon like everything else, and most
columns are nullable since not every report XML sets every attribute.

Revision ID: 8a43097881d7
Revises: b7f0c2a189de
Create Date: 2026-08-30 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "8a43097881d7"
down_revision = "b7f0c2a189de"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "citrap",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("visible", sa.Boolean(), nullable=True),
        sa.Column("delimiter", sa.String(length=255), nullable=True),
        sa.Column("user_callsign", sa.String(length=255), nullable=True),
        sa.Column("user_description", sa.String(length=255), nullable=True),
        sa.Column("date_time", sa.DateTime(), nullable=True),
        sa.Column("date_time_description", sa.String(length=255), nullable=True),
        sa.Column("point_id", sa.Integer(), nullable=False),
        sa.Column("location_description", sa.String(length=255), nullable=True),
        sa.Column("event_scale", sa.String(length=255), nullable=True),
        sa.Column("importance", sa.String(length=255), nullable=True),
        sa.Column("tags", sa.String(length=255), nullable=True),
        sa.Column("scale_description", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=255), nullable=True),
        sa.Column("file_name", sa.String(length=255), nullable=True),
        sa.Column("hash", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["point_id"], ["points.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hash"),
    )


def downgrade():
    op.drop_table("citrap")
