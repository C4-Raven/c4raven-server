"""Added federated_from to euds

Federated CoT arrives for uids that were never locally enrolled, but the
`cot` table's cot_eud foreign key requires the sender_uid to already exist
in `euds` -- without this, cot_parser rejects every federated event with a
ForeignKeyViolation before it ever reaches the groups exchange or the map.
federated_from records which peer server (its Federation Hub provenance id)
a device came from so the frontend can tell a federated contact apart from
a locally-enrolled one; NULL means local.

Revision ID: e3dd10e564a6
Revises: 8a43097881d7
Create Date: 2026-09-03 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "e3dd10e564a6"
down_revision = "8a43097881d7"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("euds", sa.Column("federated_from", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("euds", "federated_from")
