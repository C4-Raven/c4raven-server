"""Added force_password_change column to user table

CUSTOM: force_password_change patch. This column was originally added by
hand directly against the database (never through a migration), so on the
server this was written for it already exists and this migration is a
no-op there. It's written defensively (checked via SQLAlchemy inspection
rather than an unconditional ADD COLUMN) so it's also safe to run against:

  - the server it was reverse-engineered from (column already present)
  - any other existing C4 Raven install that also hand-patched this in
  - a genuinely fresh install/database (column is actually missing)

Revision ID: b7f0c2a189de
Revises: a1b2c3d4e5f6
Create Date: 2026-08-30 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b7f0c2a189de"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def _has_column(table_name, column_name):
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column_name in {c["name"] for c in inspector.get_columns(table_name)}


def upgrade():
    if _has_column("user", "force_password_change"):
        return
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "force_password_change",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade():
    if not _has_column("user", "force_password_change"):
        return
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_column("force_password_change")
