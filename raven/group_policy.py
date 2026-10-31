"""
Group policies: default access, auto-join, membership expiry and lock.

The policy settings live on Group (default_access, auto_join,
default_membership_days, locked) and GroupUser.expires_at. This module holds
the logic that more than one place needs: the group API, user creation
(admin-created and self-registered users), and the expire_group_memberships
scheduled job.

Lock only freezes *manual* changes made through the group API (adding,
removing or changing members, applying auto-join to existing users, deleting
the group). The policies an admin configured on purpose still run on a locked
group: new users still auto-join it and memberships that were given an
expiry still expire.
"""

import datetime
import traceback

import pika
import sqlalchemy.exc
from flask import current_app as app

from raven.audit import record_audit_event
from raven.extensions import db, logger
from raven.models.Group import ACCESS_DIRECTIONS, Group
from raven.models.GroupUser import GroupUser

AUDIT_CATEGORY = "groups"
SYSTEM_ACTOR = "system"

# Groups auto-managed by the user visibility diagram (see group_api). Kept
# here too so this module doesn't import the blueprint.
PAIRWISE_PREFIX = "__uv__"

ACCESS_LABELS = {"both": "send & receive", "IN": "send only", "OUT": "receive only"}

MAX_MEMBERSHIP_DAYS = 3650


def utcnow() -> datetime.datetime:
    """Naive UTC now -- the form GroupUser.expires_at is stored in."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def to_naive_utc(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is not None:
        value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return value


def parse_expires_at(value):
    """Parses an ISO 8601 string (with or without offset; no offset means UTC).
    Returns a naive UTC datetime or None for an empty value. Raises ValueError."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError("expires_at must be an ISO 8601 date/time string")
    return to_naive_utc(datetime.datetime.fromisoformat(value.strip()))


def default_expiry(group: Group):
    if group.default_membership_days:
        return utcnow() + datetime.timedelta(days=group.default_membership_days)
    return None


def access_of(directions) -> str | None:
    directions = set(directions)
    if {"IN", "OUT"} <= directions:
        return "both"
    if "IN" in directions:
        return "IN"
    if "OUT" in directions:
        return "OUT"
    return None


def access_label(access: str | None) -> str:
    return ACCESS_LABELS.get(access, access or "none")


def unbind_euds(user, group_name: str, directions) -> bool:
    """Applies a membership removal to the user's connected EUDs the same way
    removing a member on the Groups page always has: unbind each EUD's queue
    from the group's routing key. Best effort -- the database change has
    already happened, and EUDs re-read their memberships when they reconnect.
    Returns False if RabbitMQ couldn't be reached."""
    euds = list(getattr(user, "euds", None) or [])
    if not euds or not directions:
        return True
    try:
        credentials = pika.PlainCredentials(
            app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
        )
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS"), credentials=credentials
            )
        )
        channel = connection.channel()
        for eud in euds:
            for direction in directions:
                channel.queue_unbind(
                    exchange="groups", queue=eud.uid, routing_key=f"{group_name}.{direction}"
                )
        channel.close()
        connection.close()
        return True
    except BaseException as e:
        logger.warning(f"Failed to unbind {user.username}'s EUDs from {group_name}: {e}")
        logger.debug(traceback.format_exc())
        return False


def add_membership(user, group: Group, access: str, expires_at=None) -> list[str]:
    """Adds whichever of the access's directions the user doesn't already
    have. Doesn't commit. Returns the directions added."""
    existing = {
        row.direction
        for row in db.session.execute(
            db.session.query(GroupUser).filter_by(user_id=user.id, group_id=group.id)
        ).scalars()
    }
    added = []
    for direction in ACCESS_DIRECTIONS[access]:
        if direction in existing:
            continue
        membership = GroupUser()
        membership.user_id = user.id
        membership.group_id = group.id
        membership.direction = direction
        membership.enabled = True
        membership.expires_at = expires_at
        db.session.add(membership)
        added.append(direction)
    return added


def _auto_join_groups():
    return (
        db.session.execute(
            db.session.query(Group).filter(
                Group.auto_join.is_(True), ~Group.name.startswith(PAIRWISE_PREFIX)
            )
        )
        .scalars()
        .all()
    )


def apply_auto_join(user, actor: str | None = None) -> list[str]:
    """Adds a newly created user to every auto-join group with that group's
    default access and default membership duration. Never raises. Returns the
    names of the groups the user was added to."""
    if app.config.get("RAVEN_ENABLE_LDAP"):
        # Group membership comes from the LDAP server
        return []
    joined = []
    try:
        for group in _auto_join_groups():
            access = group.default_access or "both"
            added = add_membership(user, group, access, default_expiry(group))
            if not added:
                continue
            try:
                db.session.commit()
            except sqlalchemy.exc.IntegrityError:
                db.session.rollback()
                continue
            joined.append(group.name)
            record_audit_event(
                AUDIT_CATEGORY,
                "member_added",
                username=user.username,
                actor=actor or SYSTEM_ACTOR,
                details=f"Group: {group.name} · Access: {access_label(access)} · Auto-join",
            )
    except BaseException as e:
        db.session.rollback()
        logger.error(f"Failed to auto-join {getattr(user, 'username', user)} to groups: {e}")
        logger.debug(traceback.format_exc())
    return joined


def expire_memberships(now: datetime.datetime | None = None) -> int:
    """Deletes every membership whose expires_at has passed, unbinds the
    user's connected EUDs and records a membership_expired audit event per
    user and group. Returns the number of membership rows removed."""
    now = now or utcnow()
    rows = (
        db.session.execute(
            db.session.query(GroupUser).filter(
                GroupUser.expires_at.isnot(None), GroupUser.expires_at <= now
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return 0

    # (user id, group id) -> (user, group, directions removed). Keyed by id:
    # the models are dataclasses, so not hashable.
    expired: dict[tuple, tuple] = {}
    for row in rows:
        entry = expired.setdefault((row.user_id, row.group_id), (row.user, row.group, []))
        entry[2].append(row.direction)
        db.session.delete(row)
    db.session.commit()

    for user, group, directions in expired.values():
        logger.info(f"Membership of {user.username} in {group.name} expired")
        unbind_euds(user, group.name, directions)
        record_audit_event(
            AUDIT_CATEGORY,
            "membership_expired",
            username=user.username,
            actor=SYSTEM_ACTOR,
            details=f"Group: {group.name} · Access: {access_label(access_of(directions))}",
        )
    return len(rows)
