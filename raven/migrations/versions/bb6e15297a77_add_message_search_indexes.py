"""Added indexes for message search (CoT time/type/uid, point location, join columns)

Plain (non-concurrent) indexes: on a server with a large cot table the upgrade can take a while
and blocks CoT inserts while each index builds.

Revision ID: bb6e15297a77
Revises: d3f1a7c95b20
Create Date: 2026-11-02 12:00:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "bb6e15297a77"
down_revision = "d3f1a7c95b20"
branch_labels = None
depends_on = None

INDEXES = (
    ("cot", "ix_cot_timestamp", ["timestamp"]),
    ("cot", "ix_cot_type", ["type"]),
    ("cot", "ix_cot_uid", ["uid"]),
    ("cot", "ix_cot_sender_uid", ["sender_uid"]),
    ("points", "ix_points_cot_id", ["cot_id"]),
    ("points", "ix_points_latitude_longitude", ["latitude", "longitude"]),
    ("geochat", "ix_geochat_cot_id", ["cot_id"]),
    ("markers", "ix_markers_cot_id", ["cot_id"]),
)


def upgrade():
    for table, name, columns in INDEXES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.create_index(name, columns, unique=False)


def downgrade():
    for table, name, columns in reversed(INDEXES):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_index(name)
