"""supporting_documents.uploaded_by_id ON DELETE SET NULL

The uploaded_by_id -> user.id foreign key was created without an ON DELETE
action, so deleting a user who had uploaded a supporting document failed
with an FK violation in user_api.delete_user. Recreate the constraint with
ON DELETE SET NULL: the document stays, its uploader just becomes unknown.

Revision ID: b7e1f2a3c4d5
Revises: 32404899fc58
Create Date: 2026-09-16 00:00:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "b7e1f2a3c4d5"
down_revision = "32404899fc58"
branch_labels = None
depends_on = None

# Postgres' auto-generated name for the unnamed ForeignKeyConstraint in a1c4d7f0e2b9.
FK_NAME = "supporting_documents_uploaded_by_id_fkey"


def upgrade():
    with op.batch_alter_table("supporting_documents", schema=None) as batch_op:
        batch_op.drop_constraint(FK_NAME, type_="foreignkey")
        batch_op.create_foreign_key(
            FK_NAME, "user", ["uploaded_by_id"], ["id"], ondelete="SET NULL"
        )


def downgrade():
    with op.batch_alter_table("supporting_documents", schema=None) as batch_op:
        batch_op.drop_constraint(FK_NAME, type_="foreignkey")
        batch_op.create_foreign_key(FK_NAME, "user", ["uploaded_by_id"], ["id"])
