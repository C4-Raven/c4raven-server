"""Added web_path column to video_streams table

Revision ID: a7d3e9f2c418
Revises: c4e8a1d7b2f9
Create Date: 2026-10-29 14:15:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a7d3e9f2c418"
down_revision = "c4e8a1d7b2f9"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("video_streams", schema=None) as batch_op:
        batch_op.add_column(sa.Column("web_path", sa.String(length=255), nullable=True))


def downgrade():
    with op.batch_alter_table("video_streams", schema=None) as batch_op:
        batch_op.drop_column("web_path")
