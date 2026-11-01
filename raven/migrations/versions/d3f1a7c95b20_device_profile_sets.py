"""Device profiles as named, targeted sets of settings

Adds device_profile_sets / device_profile_targets / device_profile_settings and copies the old
per-key device_profiles rows into them (build_profiles() below):
* rows with an empty key are skipped
* rows without an eud_uid -> one profile "Default settings" for everyone
* rows with an eud_uid -> one profile per device, "Settings for <callsign or uid>"
A profile applies on enrollment / connection if any of its rows did. Inactive rows go into a
separate disabled profile ("... (inactive)") so nothing that wasn't being sent starts being sent.
device_profiles itself is left in place (no longer used), so the downgrade just drops the new
tables.

Revision ID: d3f1a7c95b20
Revises: b8e4d2a6c913
Create Date: 2026-10-31 20:00:00.000000

"""

import datetime

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d3f1a7c95b20"
down_revision = "b8e4d2a6c913"
branch_labels = None
depends_on = None

VALUE_CLASSES = (
    "class java.lang.String",
    "class java.lang.Boolean",
    "class java.lang.Integer",
    "class java.lang.Long",
    "class java.lang.Float",
)
DEFAULT_NAME = "Default settings"


def _value_class(value_class):
    if isinstance(value_class, str) and value_class.strip():
        short = value_class.strip().split(".")[-1].split(" ")[-1].lower()
        for allowed in VALUE_CLASSES:
            if allowed.rsplit(".", 1)[-1].lower() == short:
                return allowed
    return "class java.lang.String"


def build_profiles(rows, callsigns, now=None):
    """Maps old device_profiles rows to new profiles. Pure, so it's unit-tested on its own
    (tests/test_device_profiles.py).

    :param rows: dicts with the device_profiles columns (id, preference_key, preference_value,
        value_class, enrollment, connection, active, publish_time, eud_uid)
    :param callsigns: {eud uid: callsign}
    :return: [{name, description, enabled, apply_on_enrollment, apply_on_connection,
        target_everyone, targets:[{kind, value}], settings:[{key, value, value_class}],
        created_at, updated_at}]
    """
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    groups = {}  # (eud_uid, active) -> rows, in first-seen order
    for row in rows:
        key = (row.get("preference_key") or "").strip()
        if not key:
            continue
        eud_uid = (row.get("eud_uid") or "").strip() or None
        active = row.get("active") is not False  # NULL counted as active, as the column defaults
        groups.setdefault((eud_uid, active), []).append(row)

    def sort_key(group_key):
        eud_uid, active = group_key
        return (eud_uid is not None, eud_uid or "", not active)

    profiles, names = [], set()
    for eud_uid, active in sorted(groups, key=sort_key):
        group_rows = groups[(eud_uid, active)]
        # Newest row per key wins (the old API upserted per (key, eud_uid), but nothing in the
        # schema stopped duplicates)
        def row_order(r):
            return (r.get("publish_time") or datetime.datetime.min, r.get("id") or 0)

        by_key = {}
        for row in sorted(group_rows, key=row_order):
            by_key[row["preference_key"].strip()] = row
        settings = [
            {
                "key": key,
                "value": row.get("preference_value") if row.get("preference_value") is not None else "",
                "value_class": _value_class(row.get("value_class")),
            }
            for key, row in sorted(by_key.items())
        ]

        if eud_uid is None:
            name = DEFAULT_NAME
            description = "Settings every device got before profiles could be targeted (migrated)."
            targets = []
        else:
            name = f"Settings for {callsigns.get(eud_uid) or eud_uid}"
            description = f"Settings for device {eud_uid} (migrated)."
            targets = [{"kind": "device", "value": eud_uid}]
        if not active:
            name += " (inactive)"
        name = name[:240]
        base, n = name, 2
        while name.lower() in names:
            name = f"{base} ({n})"
            n += 1
        names.add(name.lower())

        times = [r.get("publish_time") for r in group_rows if r.get("publish_time")]
        profiles.append(
            {
                "name": name,
                "description": description,
                "enabled": active,
                "apply_on_enrollment": any(bool(r.get("enrollment")) for r in group_rows),
                "apply_on_connection": any(bool(r.get("connection")) for r in group_rows),
                "target_everyone": eud_uid is None,
                "targets": targets,
                "settings": settings,
                "created_at": min(times) if times else now,
                "updated_at": max(times) if times else now,
            }
        )
    return profiles


def upgrade():
    sets = op.create_table(
        "device_profile_sets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("apply_on_enrollment", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("apply_on_connection", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("target_everyone", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    targets = op.create_table(
        "device_profile_targets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["profile_id"], ["device_profile_sets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_device_profile_targets_profile_id"),
        "device_profile_targets",
        ["profile_id"],
        unique=False,
    )
    settings = op.create_table(
        "device_profile_settings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("value_class", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["profile_id"], ["device_profile_sets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("profile_id", "key", name="uq_device_profile_settings_profile_key"),
    )
    op.create_index(
        op.f("ix_device_profile_settings_profile_id"),
        "device_profile_settings",
        ["profile_id"],
        unique=False,
    )

    if op.get_context().as_sql:
        # The data copy needs to read device_profiles, which --sql can't do
        op.execute(
            "-- device_profiles rows are copied by build_profiles() when run online, not in --sql mode"
        )
        return

    bind = op.get_bind()
    old = sa.table(
        "device_profiles",
        sa.column("id", sa.Integer),
        sa.column("preference_key", sa.String),
        sa.column("preference_value", sa.String),
        sa.column("value_class", sa.String),
        sa.column("enrollment", sa.Boolean),
        sa.column("connection", sa.Boolean),
        sa.column("active", sa.Boolean),
        sa.column("publish_time", sa.DateTime),
        sa.column("eud_uid", sa.String),
    )
    euds = sa.table("euds", sa.column("uid", sa.String), sa.column("callsign", sa.String))
    rows = [dict(r._mapping) for r in bind.execute(sa.select(old))]
    if not rows:
        return
    callsigns = {
        uid: callsign for uid, callsign in bind.execute(sa.select(euds.c.uid, euds.c.callsign))
        if callsign
    }

    for profile in build_profiles(rows, callsigns):
        result = bind.execute(
            sets.insert().values(
                name=profile["name"],
                description=profile["description"],
                enabled=profile["enabled"],
                apply_on_enrollment=profile["apply_on_enrollment"],
                apply_on_connection=profile["apply_on_connection"],
                target_everyone=profile["target_everyone"],
                created_at=profile["created_at"],
                updated_at=profile["updated_at"],
            )
        )
        profile_id = result.inserted_primary_key[0]
        for target in profile["targets"]:
            bind.execute(targets.insert().values(profile_id=profile_id, **target))
        for setting in profile["settings"]:
            bind.execute(settings.insert().values(profile_id=profile_id, **setting))


def downgrade():
    # device_profiles was never touched, so dropping the new tables restores the old state.
    # Anything created or edited in the new tables is lost.
    op.drop_index(op.f("ix_device_profile_settings_profile_id"), table_name="device_profile_settings")
    op.drop_table("device_profile_settings")
    op.drop_index(op.f("ix_device_profile_targets_profile_id"), table_name="device_profile_targets")
    op.drop_table("device_profile_targets")
    op.drop_table("device_profile_sets")
