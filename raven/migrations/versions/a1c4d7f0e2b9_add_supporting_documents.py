"""Add supporting_documents

Admin-uploaded reference documents that any signed-in user can download
from the new Supporting Documents admin tab.

Revision ID: a1c4d7f0e2b9
Revises: f7a2c8e91b3d
Create Date: 2026-09-14 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "a1c4d7f0e2b9"
down_revision = "f7a2c8e91b3d"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "supporting_documents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("stored_filename", sa.String(length=255), nullable=False),
        sa.Column("mime_type", sa.String(length=255), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.Column("uploaded_by_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["uploaded_by_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("stored_filename"),
    )


def downgrade():
    op.drop_table("supporting_documents")
