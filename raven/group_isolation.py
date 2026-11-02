"""
Group isolation for data packages and video streams, as in TAK Server.

An item (DataPackage, VideoStream) is tagged with groups through its `groups`
relationship (data_packages_groups / video_streams_groups):

* On upload/create it gets the uploader's IN (write) groups -- the groups that
  user's data flows *into* the server through, the same direction CoT is
  routed on.
* A requester sees an item if they share one of its groups through an OUT
  (read) membership. Only enabled, unexpired memberships count.
* Administrators see everything.
* An item with no groups is visible to everyone. Every item that existed
  before group isolation looks like that, and so does anything uploaded by a
  user with no groups or by an unidentified client.

The requester is whoever the endpoint already identifies: the web session
user, or for Marti requests the user named by the client certificate's CN.
"""

import datetime

from sqlalchemy import or_, select

from raven.extensions import db
from raven.models.Group import Group
from raven.models.GroupUser import GroupUser

AUDIT_CATEGORY = "groups"


def _now():
    # GroupUser.expires_at is naive UTC
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def is_admin(user) -> bool:
    return user is not None and bool(getattr(user, "is_authenticated", True)) and user.has_role(
        "administrator"
    )


def _membership_group_ids(user, direction: str):
    """A select of the group ids `user` has an active `direction` membership of."""
    return select(GroupUser.group_id).where(
        GroupUser.user_id == user.id,
        GroupUser.direction == direction,
        or_(GroupUser.enabled.is_(None), GroupUser.enabled.is_(True)),
        or_(GroupUser.expires_at.is_(None), GroupUser.expires_at > _now()),
    )


def uploader_groups(user) -> list[Group]:
    """The groups a new item uploaded by `user` is tagged with: their IN groups."""
    if user is None or getattr(user, "id", None) is None:
        return []
    return list(
        db.session.execute(
            select(Group)
            .where(Group.id.in_(_membership_group_ids(user, Group.IN)))
            .order_by(Group.name)
        ).scalars()
    )


def assign_uploader_groups(item, user) -> None:
    """Tags a newly created item with the uploader's groups. Doesn't commit."""
    groups = uploader_groups(user)
    if groups:
        item.groups = groups


def group_visibility_clause(model, user):
    """A filter clause that's true for the `model` rows `user` may see by group, or None
    when `user` sees everything (administrators)."""
    if is_admin(user):
        return None
    ungrouped = ~model.groups.any()
    if user is None or getattr(user, "id", None) is None:
        return ungrouped
    return or_(ungrouped, model.groups.any(Group.id.in_(_membership_group_ids(user, Group.OUT))))


def filter_by_groups(query, model, user):
    """Restricts a query/select of `model` to the rows `user` may see by group."""
    clause = group_visibility_clause(model, user)
    return query if clause is None else query.filter(clause)


def can_see(item, user) -> bool:
    """Whether `user` may see `item` by group."""
    if item is None:
        return False
    if is_admin(user) or not item.groups:
        return True
    if user is None or getattr(user, "id", None) is None:
        return False
    readable = set(db.session.execute(_membership_group_ids(user, Group.OUT)).scalars())
    return any(group.id in readable for group in item.groups)


def can_publish(item, user) -> bool:
    """Whether `user` may publish (replace the video of) the existing stream `item`.

    Administrators and the stream's owner may. Otherwise it takes an IN (write) membership
    of one of the stream's groups -- the direction the stream's data flows into the server
    through -- and a stream with neither an owner nor groups is open to any user.
    """
    if item is None or user is None or getattr(user, "id", None) is None:
        return False
    if is_admin(user):
        return True
    owner = getattr(item, "username", None)
    if owner and owner == user.username:
        return True
    if not item.groups:
        return not owner
    writable = set(db.session.execute(_membership_group_ids(user, Group.IN)).scalars())
    return any(group.id in writable for group in item.groups)


def resolve_group_names(names) -> tuple[list[Group], list[str]]:
    """Looks up groups by name. Returns (groups, names that don't exist)."""
    groups, missing = [], []
    for name in dict.fromkeys(n.strip() for n in names if isinstance(n, str) and n.strip()):
        group = db.session.execute(select(Group).filter_by(name=name)).scalar_one_or_none()
        if group:
            groups.append(group)
        else:
            missing.append(name)
    return groups, missing
