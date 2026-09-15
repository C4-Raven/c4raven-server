"""Drop data_packages.filename uniqueness

Clients routinely reuse a generic filename for distinct content -- TAKX's
chat/quick-file-share feature names every package "chat-transfer.zip"
regardless of what's inside, so the second file or picture anyone sent
this way failed to save (IntegrityError on the filename unique
constraint) and could never be retrieved by any recipient. hash is the
real content identity and is already unique on its own.

Revision ID: 32404899fc58
Revises: a1c4d7f0e2b9
Create Date: 2026-09-15 00:00:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "32404899fc58"
down_revision = "a1c4d7f0e2b9"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("data_packages", schema=None) as batch_op:
        batch_op.drop_constraint("data_packages_filename_key", type_="unique")


def downgrade():
    with op.batch_alter_table("data_packages", schema=None) as batch_op:
        batch_op.create_unique_constraint("data_packages_filename_key", ["filename"])
