"""Give every video stream a distinct uid

VideoStream.uid's column default used to be str(uuid.uuid4()) evaluated
once at import, so every stream created through the web UI (which never
set uid) shared the same uid within a server process, or had NULL. TAK
clients key their synced feed list on this uid and fetch/delete via
/Marti/api/video/<uid>, so duplicates made every such lookup resolve to
the wrong (first) stream. Keep the first row of each uid, and give every
later duplicate and every NULL a fresh uuid4.

Revision ID: c8f2a3b4d5e6
Revises: b7e1f2a3c4d5
Create Date: 2026-09-16 00:00:00.000000

"""

import uuid

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c8f2a3b4d5e6"
down_revision = "b7e1f2a3c4d5"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT path, uid FROM video_streams ORDER BY path")
    ).fetchall()

    seen = set()
    for path, uid in rows:
        if uid is None or uid in seen:
            new_uid = str(uuid.uuid4())
            while new_uid in seen:
                new_uid = str(uuid.uuid4())
            bind.execute(
                sa.text("UPDATE video_streams SET uid = :uid WHERE path = :path"),
                {"uid": new_uid, "path": path},
            )
            seen.add(new_uid)
        else:
            seen.add(uid)


def downgrade():
    # Data-only migration: the original (shared/NULL) uids are not
    # recoverable and distinct uids are valid under the old schema too.
    pass
