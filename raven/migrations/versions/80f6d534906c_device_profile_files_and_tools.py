"""Device profile files and tool profiles

Adds device_profile_sets.tool (a profile served only by /Marti/api/device/profile/tool/<tool>)
and device_profile_files (files shipped in a profile's data package; the bytes live under
RAVEN_DATA_FOLDER/device_profile_files). The downgrade drops both; stored files are left on disk.

Revision ID: 80f6d534906c
Revises: d3f1a7c95b20
Create Date: 2026-11-02 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "80f6d534906c"
down_revision = "d3f1a7c95b20"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("device_profile_sets", schema=None) as batch_op:
        batch_op.add_column(sa.Column("tool", sa.String(length=255), nullable=True))
        batch_op.create_index(batch_op.f("ix_device_profile_sets_tool"), ["tool"], unique=False)

    op.create_table(
        "device_profile_files",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("zip_path", sa.String(length=512), nullable=False),
        sa.Column("stored_name", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("uploaded_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["profile_id"], ["device_profile_sets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("stored_name"),
        sa.UniqueConstraint("profile_id", "zip_path", name="uq_device_profile_files_profile_path"),
    )
    with op.batch_alter_table("device_profile_files", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_device_profile_files_profile_id"), ["profile_id"], unique=False
        )


def downgrade():
    with op.batch_alter_table("device_profile_files", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_device_profile_files_profile_id"))
    op.drop_table("device_profile_files")

    with op.batch_alter_table("device_profile_sets", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_device_profile_sets_tool"))
        batch_op.drop_column("tool")
