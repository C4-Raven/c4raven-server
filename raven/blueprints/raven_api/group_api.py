import traceback

import bleach
import sqlalchemy.exc
from flask import Blueprint, Response
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_login import current_user
from flask_security import auth_required, roles_required

from raven import group_policy
from raven.audit import record_audit_event
from raven.blueprints.raven_api.api import paginate, search
from raven.extensions import db, ldap_manager, logger
from raven.models.Group import ACCESS_DIRECTIONS, Group
from raven.models.GroupUser import GroupUser
from raven.models.user import User

group_api = Blueprint("group_api", __name__)

# Prefix for groups auto-managed by the user visibility diagram (one per
# connected pair of users). These are an implementation detail -- never
# shown in the regular groups list or editable/deletable directly.
PAIRWISE_PREFIX = group_policy.PAIRWISE_PREFIX


@group_api.route("/api/groups")
@roles_required("administrator")
def get_groups():
    """Search groups with filters and pagination

    :parameter: name
    :parameter: type
    :parameter: bitpos
    :parameter: active
    :parameter: page
    :parameter: per_page

    :return: JSON array of groups
    """

    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled. Please view and edit groups on your LDAP server"
                    ),
                }
            ),
            400,
        )

    query = db.session.query(Group).filter(~Group.name.startswith(PAIRWISE_PREFIX))
    query = search(query, Group, "name")
    query = search(query, Group, "type")
    query = search(query, Group, "bitpos")
    query = search(query, Group, "active")

    return paginate(query, Group)


@group_api.route("/api/groups/all", methods=["GET"])
@auth_required()
def get_all_groups():
    """Get a list of all groups

    :return: JSON array of groups
    :rtype: Response
    """
    return_value = []

    if app.config.get("RAVEN_ENABLE_LDAP"):

        groups = ldap_manager.get_user_groups(current_user.username)
        for group in groups:
            if group["cn"].lower().startswith(
                app.config.get("RAVEN_LDAP_GROUP_PREFIX").lower()
            ) and not (
                group["cn"].lower().endswith("_read") or group["cn"].lower().endswith("_write")
            ):

                g = Group()
                g.id = group["entryuuid"]
                g.name = group["cn"]
                g.distinguishedName = group["dn"]
                g.type = Group.LDAP

                return_value.append(g.to_json())

        return jsonify(return_value)

    if not current_user.has_role("administrator"):
        groups = db.session.execute(
            db.session.query(GroupUser).filter_by(user_id=current_user.id, direction=Group.OUT)
        ).scalars()
        # Make sure a group is only added once, not twice for both IN and OUT
        group_names = []
        for group in groups:
            if group.group.name.startswith(PAIRWISE_PREFIX):
                continue
            if group.group.name not in group_names:
                group_names.append(group.group.name)
            else:
                continue
            return_value.append(group.group.to_json())

    else:
        groups = db.session.execute(
            db.session.query(Group).filter(~Group.name.startswith(PAIRWISE_PREFIX))
        ).scalars()
        for group in groups:
            return_value.append(group.to_json())

    return jsonify(return_value)


def _ldap_enabled_response(message=None):
    return (
        jsonify(
            {
                "success": False,
                "error": message
                or gettext("LDAP is enabled. Please view and edit groups on your LDAP server"),
            }
        ),
        400,
    )


def _error(message, status=400):
    return jsonify({"success": False, "error": message}), status


def _actor():
    return getattr(current_user, "username", None)


def _items_only_in_group(group: Group) -> dict[str, int]:
    """Data packages and video streams tagged with `group` and no other group. Deleting the
    group would leave them with no groups, which raven/group_isolation.py treats as visible to
    everyone, so a group with any of these can't be deleted until they're retagged."""
    from raven.models.DataPackage import DataPackage
    from raven.models.VideoStream import VideoStream

    counts = {}
    for label, model in (("data packages", DataPackage), ("video streams", VideoStream)):
        counts[label] = db.session.execute(
            sqlalchemy.select(sqlalchemy.func.count())
            .select_from(model)
            .where(
                model.groups.any(Group.id == group.id),
                ~model.groups.any(Group.id != group.id),
            )
        ).scalar_one()
    return counts


def _orphaned_items_response(group: Group):
    """An error response if deleting `group` would make items public, else None"""
    counts = _items_only_in_group(group)
    if not any(counts.values()):
        return None
    summary = ", ".join(f"{count} {label}" for label, count in counts.items() if count)
    return (
        jsonify(
            {
                "success": False,
                "error": gettext(
                    "%(group_name)s is the only group of %(summary)s. Deleting it would make them "
                    "visible to everyone -- give them another group first",
                    group_name=group.name,
                    summary=summary,
                ),
                "orphaned_items": counts,
            }
        ),
        409,
    )


def _find_group(group_name):
    if not group_name:
        return None
    return db.session.execute(
        db.session.query(Group).filter_by(name=bleach.clean(group_name))
    ).scalar_one_or_none()


def _pairwise_response(action):
    return _error(
        gettext(
            "This group is managed by the user visibility diagram -- disconnect the users there "
            "instead of %(action)s here",
            action=action,
        )
    )


def _locked_response(group):
    return _error(
        gettext(
            "%(group_name)s is locked. Unlock it in the group's policies before changing its "
            "members or deleting it",
            group_name=group.name,
        ),
        403,
    )


def _protected_username_response(username):
    if username in app.config.get("RAVEN_PROTECTED_USERNAMES", []):
        return _error(
            gettext(
                "%(username)s is a protected system account and can't be modified",
                username=username,
            ),
            403,
        )
    return None


def _parse_access(value):
    """Accepts both|IN|OUT (any case, BOTH too). Returns the canonical access or None."""
    if not isinstance(value, str):
        return None
    if value.lower() == "both":
        return "both"
    if value.upper() in ("IN", "OUT"):
        return value.upper()
    return None


def _parse_policy(data):
    """Validates the policy keys present in data. Returns {column: value}.
    Raises ValueError with a user-facing message."""
    policy = {}
    if "default_access" in data:
        access = _parse_access(data.get("default_access"))
        if not access:
            raise ValueError(gettext("default_access must be both, IN or OUT"))
        policy["default_access"] = access
    for key in ("auto_join", "locked"):
        if key in data:
            if not isinstance(data.get(key), bool):
                raise ValueError(gettext("%(key)s must be true or false", key=key))
            policy[key] = data.get(key)
    if "default_membership_days" in data:
        days = data.get("default_membership_days")
        if days in (None, "", 0):
            policy["default_membership_days"] = None
        elif (
            isinstance(days, bool)
            or not isinstance(days, int)
            or not 1 <= days <= group_policy.MAX_MEMBERSHIP_DAYS
        ):
            raise ValueError(
                gettext(
                    "default_membership_days must be a whole number of days from 1 to %(max)s, "
                    "or empty for no expiry",
                    max=group_policy.MAX_MEMBERSHIP_DAYS,
                )
            )
        else:
            policy["default_membership_days"] = days
    return policy


def _parse_future_expiry(value):
    """Parses an expires_at value from a request. Raises ValueError."""
    try:
        expires_at = group_policy.parse_expires_at(value)
    except ValueError:
        raise ValueError(gettext("expires_at must be an ISO 8601 date and time"))
    if expires_at is not None and expires_at <= group_policy.utcnow():
        raise ValueError(gettext("The expiry must be in the future"))
    return expires_at


def _describe_policy(policy):
    parts = []
    for key, value in policy.items():
        if key == "default_access":
            value = group_policy.access_label(value)
        elif key == "default_membership_days":
            value = f"{value} days" if value else "never expire"
        elif key == "description":
            value = value or "(none)"
        parts.append(f"{key.replace('_', ' ').capitalize()}: {value}")
    return " · ".join(parts)


def _expiry_label(expires_at):
    return expires_at.strftime("%Y-%m-%d %H:%M UTC") if expires_at else "never"


@group_api.route("/api/groups/members")
@roles_required("administrator")
def get_group_members():
    """Get a list of members of a group

    :parameter: name

    :return: JSON array of {username, direction, active, expires_at}, one per membership row
    :rtype: Response
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response()

    group_name = request.args.get("name")
    if not group_name:
        return jsonify({"success": False, "error": "Please specify a group name"}), 400

    group_name = bleach.clean(group_name)
    group = _find_group(group_name)
    if not group:
        return jsonify({"success": False, "error": f"Group {group_name} not found"}), 404

    members = db.session.execute(
        db.session.query(GroupUser).filter_by(group_id=group.id)
    ).scalars()
    return_value = []
    for member in members:
        return_value.append(
            {
                "username": member.user.username,
                "direction": member.direction,
                "active": member.enabled,
                "expires_at": member.expires_at_iso(),
            }
        )

    return jsonify(return_value)


@group_api.route("/api/groups/members", methods=["DELETE"])
@roles_required("administrator")
def remove_user_from_group():
    """Removes a user's membership of a group.

    :parameter: username
    :parameter: group_name
    :parameter: direction - IN, OUT or BOTH
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response()

    username = request.args.get("username")
    group_name = request.args.get("group_name")
    direction = request.args.get("direction")

    if not username or not group_name or not direction:
        return _error(gettext("Please provide the username, group name, and direction"))

    username = bleach.clean(username)
    group_name = bleach.clean(group_name)
    direction = bleach.clean(direction)

    if group_name.startswith(PAIRWISE_PREFIX):
        return _error(
            gettext(
                "This group is managed by the user visibility diagram -- disconnect the "
                "users there instead of removing one side of it here"
            )
        )

    protected = _protected_username_response(username)
    if protected:
        return protected

    access = _parse_access(direction)
    if not access:
        return _error(gettext("Invalid direction: %(direction)s", direction=direction))

    user = app.security.datastore.find_user(username=username)
    if not user:
        return _error(gettext("User %(username)s not found", username=username), 404)

    group = _find_group(group_name)
    if not group:
        return _error(gettext("Group %(group_name)s not found", group_name=group_name), 404)
    if group.locked:
        return _locked_response(group)

    try:
        rows = (
            db.session.execute(
                db.session.query(GroupUser).filter(
                    GroupUser.group_id == group.id,
                    GroupUser.user_id == user.id,
                    GroupUser.direction.in_(ACCESS_DIRECTIONS[access]),
                )
            )
            .scalars()
            .all()
        )
        removed = [row.direction for row in rows]
        remaining = (
            db.session.query(GroupUser)
            .filter_by(group_id=group.id, user_id=user.id)
            .count()
            - len(rows)
        )
        for row in rows:
            db.session.delete(row)
        db.session.commit()
    except BaseException as e:
        db.session.rollback()
        logger.error(f"Failed to remove {username} from {group_name}: {e}")
        logger.debug(traceback.format_exc())
        return _error(
            gettext(
                "Failed to remove %(username)s from %(group_name)s: %(e)s",
                username=username,
                group_name=group_name,
                e=str(e),
            ),
            500,
        )

    if removed:
        group_policy.unbind_euds(user, group.name, removed)
        if remaining:
            # One direction of a two-way membership went: an access change
            record_audit_event(
                group_policy.AUDIT_CATEGORY,
                "member_access_changed",
                username=username,
                actor=_actor(),
                details=f"Group: {group.name} · Removed: "
                f"{group_policy.access_label(group_policy.access_of(removed))}",
            )
        else:
            record_audit_event(
                group_policy.AUDIT_CATEGORY,
                "member_removed",
                username=username,
                actor=_actor(),
                details=f"Group: {group.name}",
            )

    return jsonify({"success": True})


@group_api.route("/api/groups/members", methods=["PATCH"])
@roles_required("administrator")
def update_group_member():
    """Changes one member's access and/or membership expiry in one go.

    :parameter: username
    :parameter: group_name
    :parameter: access - optional, both, IN (send only) or OUT (receive only)
    :parameter: expires_at - optional, ISO 8601 date/time in the future, or null to
        remove the expiry. Applies to all of the member's rows in the group.

    :return: 403 if the group is locked, 404 if the user isn't a member
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response()

    data = request.get_json(silent=True) or {}
    username = bleach.clean(str(data.get("username") or ""))
    group_name = bleach.clean(str(data.get("group_name") or ""))
    if not username or not group_name:
        return _error(gettext("Please provide the username and group name"))
    if "access" not in data and "expires_at" not in data:
        return _error(gettext("Nothing to change: provide access and/or expires_at"))

    if group_name.startswith(PAIRWISE_PREFIX):
        return _pairwise_response(gettext("changing it"))

    protected = _protected_username_response(username)
    if protected:
        return protected

    access = None
    if "access" in data:
        access = _parse_access(data.get("access"))
        if not access:
            return _error(gettext("access must be both, IN or OUT"))

    expiry_given = "expires_at" in data
    try:
        expires_at = _parse_future_expiry(data.get("expires_at")) if expiry_given else None
    except ValueError as e:
        return _error(str(e))

    user = app.security.datastore.find_user(username=username)
    if not user:
        return _error(gettext("User %(username)s not found", username=username), 404)
    group = _find_group(group_name)
    if not group:
        return _error(gettext("Group %(group_name)s not found", group_name=group_name), 404)
    if group.locked:
        return _locked_response(group)

    rows = (
        db.session.execute(
            db.session.query(GroupUser).filter_by(group_id=group.id, user_id=user.id)
        )
        .scalars()
        .all()
    )
    if not rows:
        return _error(
            gettext(
                "%(username)s is not a member of %(group_name)s",
                username=username,
                group_name=group_name,
            ),
            404,
        )

    old_access = group_policy.access_of(r.direction for r in rows)
    old_expiry = min((r.expires_at for r in rows if r.expires_at), default=None)
    if not expiry_given:
        # Keep the member's current expiry on any direction being added
        expires_at = old_expiry

    removed = []
    try:
        if access and access != old_access:
            wanted = ACCESS_DIRECTIONS[access]
            # Grant the new directions before revoking the old ones
            group_policy.add_membership(user, group, access, expires_at)
            for row in rows:
                if row.direction not in wanted:
                    removed.append(row.direction)
                    db.session.delete(row)
        if expiry_given:
            for row in rows:
                if row.direction not in removed:
                    row.expires_at = expires_at
        db.session.commit()
    except BaseException as e:
        db.session.rollback()
        logger.error(f"Failed to update {username} in {group_name}: {e}")
        logger.debug(traceback.format_exc())
        return _error(
            gettext(
                "Failed to update %(username)s in %(group_name)s: %(e)s",
                username=username,
                group_name=group_name,
                e=str(e),
            ),
            500,
        )

    if removed:
        group_policy.unbind_euds(user, group.name, removed)

    changes = []
    if access and access != old_access:
        changes.append(
            f"Access: {group_policy.access_label(old_access)} → {group_policy.access_label(access)}"
        )
    if expiry_given and expires_at != old_expiry:
        changes.append(f"Expires: {_expiry_label(old_expiry)} → {_expiry_label(expires_at)}")
    if changes:
        record_audit_event(
            group_policy.AUDIT_CATEGORY,
            "member_access_changed",
            username=username,
            actor=_actor(),
            details=f"Group: {group.name} · " + " · ".join(changes),
        )

    return jsonify({"success": True})


@group_api.route("/api/groups", methods=["POST"])
@roles_required("administrator")
def add_group():
    """Creates a new group

    :parameter: name
    :parameter: description - optional
    :parameter: default_access, auto_join, default_membership_days, locked - optional
        policies, see PATCH /api/groups/policy

    :return: 400 if LDAP is enabled, the request is missing the name key or the group exists. 500 on server errors.
    :rtype: Response
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response(
            gettext("LDAP is enabled, please use your LDAP server to add groups")
        )

    data = request.get_json(silent=True) or {}
    if not data.get("name"):
        return _error(gettext("Missing name"))

    name = bleach.clean(str(data.get("name"))).strip()
    if not name:
        return _error(gettext("Missing name"))
    if name.startswith(PAIRWISE_PREFIX):
        return _error(
            gettext("Group names starting with %(prefix)s are reserved", prefix=PAIRWISE_PREFIX)
        )
    description = bleach.clean(data.get("description")) if data.get("description") else None

    try:
        policy = _parse_policy(data)
    except ValueError as e:
        return _error(str(e))

    if _find_group(name):
        return _error(gettext("%(name)s group already exists", name=name))

    try:
        group = Group()
        group.name = name
        group.type = Group.SYSTEM
        group.description = description
        for key, value in policy.items():
            setattr(group, key, value)
        db.session.add(group)
        db.session.commit()
    except BaseException as e:
        db.session.rollback()
        logger.error(f"Failed to add {name} group: {e}")
        logger.debug(traceback.format_exc())
        return _error(
            gettext("Failed to add %(name)s group: %(e)s", name=name, e=str(e)), 500
        )

    record_audit_event(
        group_policy.AUDIT_CATEGORY,
        "group_created",
        actor=_actor(),
        details=" · ".join(
            filter(None, [f"Group: {name}", _describe_policy(policy) if policy else None])
        ),
    )
    return jsonify({"success": True})


@group_api.route("/api/groups/policy", methods=["PATCH"])
@roles_required("administrator")
def update_group_policy():
    """Changes a group's description and/or policies. Only the keys present change.

    :parameter: group_name
    :parameter: description - optional
    :parameter: default_access - optional, both, IN (send only) or OUT (receive only).
        Preselected when adding members and used for auto-join.
    :parameter: auto_join - optional bool, add new users to this group automatically
    :parameter: default_membership_days - optional int 1..3650, or null for no expiry.
        New memberships expire after this many days.
    :parameter: locked - optional bool. A locked group can't be deleted and its members
        can't be changed (policies, including unlocking, still can be).

    :return: the updated group
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response()

    data = request.get_json(silent=True) or {}
    group_name = bleach.clean(str(data.get("group_name") or ""))
    if not group_name:
        return _error(gettext("Missing group name"))
    if group_name.startswith(PAIRWISE_PREFIX):
        return _pairwise_response(gettext("changing it"))

    group = _find_group(group_name)
    if not group:
        return _error(gettext("No such group: %(group_name)s", group_name=group_name), 404)

    try:
        policy = _parse_policy(data)
    except ValueError as e:
        return _error(str(e))
    if "description" in data:
        description = data.get("description")
        policy["description"] = bleach.clean(str(description)) if description else None

    changed = {key: value for key, value in policy.items() if getattr(group, key) != value}
    if changed:
        for key, value in changed.items():
            setattr(group, key, value)
        db.session.commit()
        record_audit_event(
            group_policy.AUDIT_CATEGORY,
            "group_policy_changed",
            actor=_actor(),
            details=f"Group: {group.name} · {_describe_policy(changed)}",
        )

    result = group.to_json()
    return jsonify({"success": True, "group": result})


@group_api.route("/api/groups/policy/apply", methods=["POST"])
@roles_required("administrator")
def apply_group_auto_join():
    """Adds every current user who isn't in the group yet, with the group's
    default access and default membership duration. Protected system accounts
    and deactivated users are skipped.

    :parameter: group_name

    :return: {"success": true, "added": [usernames]}
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response()

    data = request.get_json(silent=True) or {}
    group_name = bleach.clean(str(data.get("group_name") or ""))
    if not group_name:
        return _error(gettext("Missing group name"))
    if group_name.startswith(PAIRWISE_PREFIX):
        return _pairwise_response(gettext("changing it"))
    group = _find_group(group_name)
    if not group:
        return _error(gettext("No such group: %(group_name)s", group_name=group_name), 404)
    if group.locked:
        return _locked_response(group)

    member_ids = {
        row.user_id
        for row in db.session.execute(
            db.session.query(GroupUser).filter_by(group_id=group.id)
        ).scalars()
    }
    protected = set(app.config.get("RAVEN_PROTECTED_USERNAMES", []))
    access = group.default_access or "both"
    expires_at = group_policy.default_expiry(group)
    added = []
    for user in db.session.execute(db.session.query(User).order_by(User.username)).scalars():
        if user.id in member_ids or user.username in protected or not user.active:
            continue
        if group_policy.add_membership(user, group, access, expires_at):
            added.append(user.username)
    try:
        db.session.commit()
    except BaseException as e:
        db.session.rollback()
        logger.error(f"Failed to add existing users to {group_name}: {e}")
        logger.debug(traceback.format_exc())
        return _error(
            gettext("Failed to add users to %(group_name)s: %(e)s", group_name=group_name, e=str(e)),
            500,
        )

    for username in added:
        record_audit_event(
            group_policy.AUDIT_CATEGORY,
            "member_added",
            username=username,
            actor=_actor(),
            details=f"Group: {group.name} · Access: {group_policy.access_label(access)} · "
            f"Expires: {_expiry_label(expires_at)} · Applied to existing users",
        )

    return jsonify({"success": True, "added": added})


@group_api.route("/api/groups", methods=["PUT"])
@roles_required("administrator")
def add_user_to_group():
    """Adds users to a group. This will allow all the user's EUDs to subscribe and unsubscribe from the channels/groups they're allowed to see.
    :parameter: users - A list of users to add to a group
    :parameter: group_name - Name of the group to add users to
    :parameter: direction - IN, OUT or BOTH (both rows in one request)
    :parameter: expires_at - optional ISO 8601 date/time in the future, or null for no
        expiry. When the key is missing, the group's default membership duration applies.

    :return: 400 if LDAP is enabled, no group or username is specified, or if the specified group or user doesn't exist. 403 if the group is locked. 200 on success.
    :rtype: Response
    """

    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response(
            gettext("LDAP is enabled, please use your LDAP server to add users to groups")
        )

    data = request.get_json(silent=True) or {}
    users = data.get("users")
    group_name = data.get("group_name")
    direction = data.get("direction")

    if users is None or group_name is None or direction is None:
        return _error(gettext("Please provide a list of users, group name, and direction"))
    if not isinstance(users, list):
        return _error(gettext("users must be a list of usernames"))

    access = _parse_access(direction)
    if not access:
        return _error(gettext("Direction must be IN, OUT or BOTH"))

    group = _find_group(group_name)
    if not group:
        return _error(gettext("Group %(group_name)s does not exist", group_name=group_name))
    if group.name.startswith(PAIRWISE_PREFIX):
        return _pairwise_response(gettext("changing it"))
    if group.locked:
        return _locked_response(group)

    try:
        if "expires_at" in data:
            expires_at = _parse_future_expiry(data.get("expires_at"))
        else:
            expires_at = group_policy.default_expiry(group)
    except ValueError as e:
        return _error(str(e))

    for username in users:
        user = app.security.datastore.find_user(username=username)
        if not user:
            return _error(gettext("User %(username)s does not exist", username=username))

        added = group_policy.add_membership(user, group, access, expires_at)
        if not added:
            continue
        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            db.session.rollback()
            continue

        record_audit_event(
            group_policy.AUDIT_CATEGORY,
            "member_added",
            username=user.username,
            actor=_actor(),
            details=f"Group: {group.name} · Access: "
            f"{group_policy.access_label(group_policy.access_of(added))} · "
            f"Expires: {_expiry_label(expires_at)}",
        )

    return jsonify({"success": True})


@group_api.route("/api/groups", methods=["DELETE"])
@roles_required("administrator")
def delete_group():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return _ldap_enabled_response(
            gettext("LDAP is enabled, please use your LDAP server to delete groups")
        )

    if "group_name" not in request.args.keys() or not request.args.get("group_name"):
        return _error(gettext("Missing group name"))

    group_name = bleach.clean(request.args.get("group_name"))
    if group_name == "__ANON__":
        return _error(gettext("The __ANON__ group cannot be deleted"))
    if group_name.startswith(PAIRWISE_PREFIX):
        return _error(
            gettext(
                "This group is managed by the user visibility diagram -- disconnect the "
                "users there instead of deleting it directly"
            )
        )

    group = _find_group(group_name)
    if not group:
        return _error(gettext("No such group: %(group_name)s", group_name=group_name), 404)
    if group.locked:
        return _locked_response(group)
    orphaned = _orphaned_items_response(group)
    if orphaned:
        return orphaned

    try:
        memberships: dict = {}
        for row in db.session.execute(
            db.session.query(GroupUser).filter_by(group_id=group.id)
        ).scalars():
            memberships.setdefault(row.user_id, (row.user, []))[1].append(row.direction)

        GroupUser.query.filter_by(group_id=group.id).delete()
        db.session.delete(group)
        db.session.commit()
    except BaseException as e:
        db.session.rollback()
        logger.error(f"Failed to delete {group_name}: {e}")
        logger.debug(traceback.format_exc())
        return _error(
            gettext("Failed to delete %(group_name)s: %(e)s", group_name=group_name, e=str(e)),
            500,
        )

    # Members' connected EUDs stop receiving from the group straight away
    for user, directions in memberships.values():
        group_policy.unbind_euds(user, group_name, directions)

    record_audit_event(
        group_policy.AUDIT_CATEGORY,
        "group_deleted",
        actor=_actor(),
        details=f"Group: {group_name} · Members: {len(memberships)}",
    )
    return jsonify({"success": True})


def _pairwise_group_name(username_a, username_b):
    a, b = sorted([username_a, username_b])
    return f"{PAIRWISE_PREFIX}{a}__{b}"


def _get_or_create_pairwise_group(username_a, username_b):
    name = _pairwise_group_name(username_a, username_b)
    group = db.session.execute(db.session.query(Group).filter_by(name=name)).first()
    if group:
        return group[0]

    group = Group()
    group.name = name
    group.type = Group.SYSTEM
    group.description = "Auto-managed by the user visibility diagram. Do not edit directly."
    db.session.add(group)
    db.session.commit()
    return group


def _set_membership(user_id, group_id, direction, present):
    existing = db.session.execute(
        db.session.query(GroupUser).filter_by(user_id=user_id, group_id=group_id, direction=direction)
    ).first()
    if present and not existing:
        membership = GroupUser()
        membership.user_id = user_id
        membership.group_id = group_id
        membership.direction = direction
        try:
            db.session.add(membership)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            db.session.rollback()
    elif not present and existing:
        db.session.delete(existing[0])
        db.session.commit()


def _named_groups_granting(sender_id, receiver_id):
    """Names of the named (non-pairwise) groups through which sender's data reaches receiver.

    A pairwise connection can only add access: if a shared group already carries data
    the other way, a one-way line drawn on the diagram stays two-way in practice.
    """
    sender_groups = {
        r.group_id
        for r in db.session.execute(
            db.session.query(GroupUser).filter_by(user_id=sender_id, direction=Group.IN, enabled=True)
        ).scalars()
    }
    receiver_groups = {
        r.group_id
        for r in db.session.execute(
            db.session.query(GroupUser).filter_by(user_id=receiver_id, direction=Group.OUT, enabled=True)
        ).scalars()
    }
    shared = sender_groups & receiver_groups
    if not shared:
        return []
    names = db.session.execute(db.session.query(Group.name).filter(Group.id.in_(shared))).scalars()
    return sorted(n for n in names if not n.startswith(PAIRWISE_PREFIX))


@group_api.route("/api/users/visibility", methods=["GET"])
@roles_required("administrator")
def get_user_visibility():
    """Computes the current user-to-user visibility diagram.

    Per this project's group semantics, IN lets a user send CoT to a group
    and OUT lets them receive CoT from it. Two users are connected here if
    that holds true via ANY group they share -- a real named group (e.g. one
    they were both added to on the Groups page) just as much as one of the
    auto-managed pairwise groups this diagram itself creates (see
    PAIRWISE_PREFIX). Without this, adding someone to a group's Access list
    wouldn't show up here at all, and the two views would visibly disagree
    about who can actually see whom.

      - user A has IN and user B has OUT (on some shared group) -> A's data
        reaches B
      - true in both directions -> solid, mutual "see + message"
      - only one direction holds -> dotted, pointing at the receiver

    Each edge is also flagged "manual": true if a pairwise group
    contributes to it, meaning it can be created/removed directly on this
    diagram. An edge that's only true because of a shared *named* group
    (manual: false) can't be removed here -- it has to be changed on that
    group's own Access list, since it isn't a property of just this one
    pair.

    :return: JSON array of {source, target, type, manual} edges,
        source/target are usernames
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled. Please view and edit groups on your LDAP server"
                    ),
                }
            ),
            400,
        )

    groups = db.session.execute(db.session.query(Group)).scalars().all()

    # (sender_id, receiver_id) -> list of group names that grant it
    send_pairs: dict[tuple[int, int], list[str]] = {}
    for group in groups:
        rows = db.session.execute(
            db.session.query(GroupUser).filter_by(group_id=group.id, enabled=True)
        ).scalars().all()
        senders = {r.user_id for r in rows if r.direction == Group.IN}
        receivers = {r.user_id for r in rows if r.direction == Group.OUT}
        for sender_id in senders:
            for receiver_id in receivers:
                if sender_id == receiver_id:
                    continue
                send_pairs.setdefault((sender_id, receiver_id), []).append(group.name)

    users_by_id = {u.id: u for u in db.session.execute(db.session.query(User)).scalars().all()}

    edges = []
    seen = set()
    for (a_id, b_id) in send_pairs:
        pair_key = frozenset((a_id, b_id))
        if pair_key in seen:
            continue
        seen.add(pair_key)

        a_to_b_groups = send_pairs.get((a_id, b_id), [])
        b_to_a_groups = send_pairs.get((b_id, a_id), [])
        if not a_to_b_groups and not b_to_a_groups:
            continue

        user_a = users_by_id.get(a_id)
        user_b = users_by_id.get(b_id)
        if not user_a or not user_b:
            continue

        manual = any(
            name.startswith(PAIRWISE_PREFIX) for name in a_to_b_groups + b_to_a_groups
        )

        def named(names):
            return sorted({n for n in names if not n.startswith(PAIRWISE_PREFIX)})

        # source_groups / target_groups: the named groups carrying source -> target and
        # target -> source, so the diagram can say *why* a pair is connected.
        if a_to_b_groups and b_to_a_groups:
            edges.append(
                {
                    "source": user_a.username,
                    "target": user_b.username,
                    "type": "solid",
                    "manual": manual,
                    "source_groups": named(a_to_b_groups),
                    "target_groups": named(b_to_a_groups),
                }
            )
        elif a_to_b_groups:
            edges.append(
                {
                    "source": user_a.username,
                    "target": user_b.username,
                    "type": "dotted",
                    "manual": manual,
                    "source_groups": named(a_to_b_groups),
                    "target_groups": [],
                }
            )
        else:
            edges.append(
                {
                    "source": user_b.username,
                    "target": user_a.username,
                    "type": "dotted",
                    "manual": manual,
                    "source_groups": named(b_to_a_groups),
                    "target_groups": [],
                }
            )

    return jsonify(edges)


@group_api.route("/api/users/visibility", methods=["PUT"])
@roles_required("administrator")
def set_user_visibility():
    """Connects two users on the visibility diagram.

    :parameter: source - username (the sender, for a dotted connection)
    :parameter: target - username (the receiver, for a dotted connection)
    :parameter: type - "solid" (mutual) or "dotted" (one-way, source -> target)
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled. Please view and edit groups on your LDAP server"
                    ),
                }
            ),
            400,
        )

    source_name = bleach.clean(request.json.get("source", ""))
    target_name = bleach.clean(request.json.get("target", ""))
    rel_type = bleach.clean(request.json.get("type", ""))

    if not source_name or not target_name or rel_type not in ("solid", "dotted"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "source, target, and a valid type (solid or dotted) are required"
                    ),
                }
            ),
            400,
        )
    if source_name == target_name:
        return jsonify({"success": False, "error": gettext("A user can't connect to themselves")}), 400

    source = app.security.datastore.find_user(username=source_name)
    target = app.security.datastore.find_user(username=target_name)
    if not source or not target:
        return jsonify({"success": False, "error": gettext("User not found")}), 404

    group = _get_or_create_pairwise_group(source_name, target_name)

    # dotted source -> target: source sends (IN), target receives (OUT).
    # The reverse grants are set explicitly either way, so redrawing a two-way
    # connection as one-way (or flipping its arrow) actually takes effect.
    _set_membership(source.id, group.id, Group.IN, True)
    _set_membership(target.id, group.id, Group.OUT, True)
    _set_membership(target.id, group.id, Group.IN, rel_type == "solid")
    _set_membership(source.id, group.id, Group.OUT, rel_type == "solid")

    # A one-way line can't take away what a shared group already grants; tell the
    # admin which groups still carry target -> source so they can change those.
    overridden_by = (
        _named_groups_granting(target.id, source.id) if rel_type == "dotted" else []
    )
    return jsonify({"success": True, "overridden_by": overridden_by})


@group_api.route("/api/users/visibility", methods=["DELETE"])
@roles_required("administrator")
def remove_user_visibility():
    """Disconnects two users, removing their auto-managed pairwise group entirely.

    If the two aren't connected through a pairwise group at all -- the
    connection is only coming from a shared named group's own Access list
    (see get_user_visibility's "manual" flag) -- there's nothing here to
    remove, and this returns an error explaining that rather than silently
    doing nothing.

    :parameter: source - username
    :parameter: target - username
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled. Please view and edit groups on your LDAP server"
                    ),
                }
            ),
            400,
        )

    source_name = bleach.clean(request.args.get("source", ""))
    target_name = bleach.clean(request.args.get("target", ""))

    if not source_name or not target_name:
        return jsonify({"success": False, "error": gettext("source and target are required")}), 400

    name = _pairwise_group_name(source_name, target_name)
    group = db.session.execute(db.session.query(Group).filter_by(name=name)).first()
    if not group:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "This connection comes from a shared group's Access list, not a direct "
                        "connection -- remove one of them from that group instead"
                    ),
                }
            ),
            400,
        )

    group = group[0]
    orphaned = _orphaned_items_response(group)
    if orphaned:
        return orphaned
    GroupUser.query.filter_by(group_id=group.id).delete()
    db.session.delete(group)
    db.session.commit()

    return jsonify({"success": True})
