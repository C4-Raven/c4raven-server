"""Honour tool=private on data packages; track fileshare recipients

ATAK's user-to-user file transfer uploads a data package and then PUTs
"private" to /Marti/api/sync/metadata/<hash>/tool. That body was being
stored in `keywords` and never read, so every listing and download treated
the file as public. Move those markers into `tool` (where TAK Server keeps
them) and add the table cot_parser uses to record who a private package was
sent to, so downloads can be limited to sender + recipients.

Revision ID: d9a3b4c5e6f7
Revises: c8f2a3b4d5e6
Create Date: 2026-09-16 10:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d9a3b4c5e6f7"
down_revision = "c8f2a3b4d5e6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "data_package_recipients",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("data_package_hash", sa.String(length=255), nullable=False),
        sa.Column("eud_uid", sa.String(length=255), nullable=True),
        sa.Column("callsign", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["data_package_hash"], ["data_packages.hash"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "data_package_hash", "eud_uid", "callsign", name="uq_data_package_recipient"
        ),
    )
    with op.batch_alter_table("data_package_recipients", schema=None) as batch_op:
        batch_op.create_index(
            "ix_data_package_recipients_hash", ["data_package_hash"], unique=False
        )

    # Markers the old tool handler mis-filed under keywords.
    op.execute(
        sa.text(
            "UPDATE data_packages SET tool = lower(keywords), keywords = NULL "
            "WHERE tool IS NULL AND lower(keywords) IN ('private', 'public')"
        )
    )


def downgrade():
    with op.batch_alter_table("data_package_recipients", schema=None) as batch_op:
        batch_op.drop_index("ix_data_package_recipients_hash")
    op.drop_table("data_package_recipients")
    # The keywords -> tool backfill is not reversed: tool is the right column
    # under the old schema too.
