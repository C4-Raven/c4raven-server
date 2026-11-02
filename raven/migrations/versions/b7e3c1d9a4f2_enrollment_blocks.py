"""Block re-enrollment of devices whose certificate was revoked

Adds enrollment_blocks: one row per device (EUD uid) that may not enroll for a new
certificate until an admin clears it. Revoking a device's cert (certificate_api) adds
the row, so a lost phone can't enroll again with the user's saved credentials.
Devices whose newest certificate is already revoked are blocked here as well.

Revision ID: b7e3c1d9a4f2
Revises: 06e1c612e122
Create Date: 2026-11-03 12:00:00.000000

"""

import datetime

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b7e3c1d9a4f2"
down_revision = "06e1c612e122"
branch_labels = None
depends_on = None


def _drop_unique_eud_uid():
    """Every enrollment now gets its own certificates row so a revoked one is kept as history
    (certificate_enrollment_api). No revision ever made certificates.eud_uid unique, but drop
    such a constraint/index if a hand-made or create_all() schema has one."""
    inspector = sa.inspect(op.get_bind())
    names = [
        ("constraint", c["name"])
        for c in inspector.get_unique_constraints("certificates")
        if c.get("column_names") == ["eud_uid"] and c.get("name")
    ]
    names += [
        ("index", i["name"])
        for i in inspector.get_indexes("certificates")
        if i.get("unique")
        and i.get("column_names") == ["eud_uid"]
        and i.get("name")
        # postgres lists a unique constraint's own index here too
        and not i.get("duplicates_constraint")
    ]
    if not names:
        return
    with op.batch_alter_table("certificates", schema=None) as batch_op:
        for kind, name in names:
            if kind == "constraint":
                batch_op.drop_constraint(name, type_="unique")
            else:
                batch_op.drop_index(name)


def upgrade():
    _drop_unique_eud_uid()

    blocks = op.create_table(
        "enrollment_blocks",
        sa.Column("eud_uid", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("serial_number", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.String(length=64), nullable=True),
        sa.Column("blocked_at", sa.DateTime(), nullable=False),
        sa.Column("blocked_by", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("eud_uid"),
    )
    with op.batch_alter_table("enrollment_blocks", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_enrollment_blocks_username"), ["username"], unique=False
        )

    # Devices whose newest certificate was revoked before this revision
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT c.eud_uid, c.username, c.common_name, c.serial_number, "
            "c.revocation_reason, c.revoked_at FROM certificates c "
            "WHERE c.eud_uid IS NOT NULL AND c.id = "
            "(SELECT MAX(c2.id) FROM certificates c2 WHERE c2.eud_uid = c.eud_uid) "
            "AND c.revoked_at IS NOT NULL"
        )
    ).fetchall()
    if rows:
        op.bulk_insert(
            blocks,
            [
                {
                    "eud_uid": row[0],
                    "username": row[1] or row[2],
                    "serial_number": row[3],
                    "reason": row[4],
                    "blocked_at": row[5] or datetime.datetime.utcnow(),
                    "blocked_by": None,
                }
                for row in rows
            ],
        )


def downgrade():
    with op.batch_alter_table("enrollment_blocks", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_enrollment_blocks_username"))
    op.drop_table("enrollment_blocks")
