"""Add user_filters and user_filters_members

Admin-managed, named subsets of users so the Users page and the Groups tab's
member picker can be scoped down instead of always listing every user.

Revision ID: f7a2c8e91b3d
Revises: e3dd10e564a6
Create Date: 2026-09-04 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "f7a2c8e91b3d"
down_revision = "e3dd10e564a6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_filters",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "user_filters_members",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("filter_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["filter_id"], ["user_filters.id"]),
        sa.PrimaryKeyConstraint("user_id", "filter_id"),
    )


def downgrade():
    op.drop_table("user_filters_members")
    op.drop_table("user_filters")
