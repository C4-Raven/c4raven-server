import traceback

import bleach
import pika
import sqlalchemy.exc
from flask import Blueprint, Response
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_login import current_user
from flask_security import auth_required, roles_required

from raven.blueprints.raven_api.api import paginate, search
from raven.extensions import db, ldap_manager, logger
from raven.models.Group import Group
from raven.models.GroupUser import GroupUser
from raven.models.user import User

group_api = Blueprint("group_api", __name__)

# Prefix for groups auto-managed by the user visibility diagram (one per
# connected pair of users). These are an implementation detail -- never
# shown in the regular groups list or editable/deletable directly.
PAIRWISE_PREFIX = "__uv__"


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


@group_api.route("/api/groups/members")
@roles_required("administrator")
def get_group_members():
    """Get a list of members of a group

    :parameter: name

    :return: JSON array of group members
    :rtype: Response
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

    group_name = request.args.get("name")
    if not group_name:
        return jsonify({"success": False, "error": "Please specify a group name"}), 400

    group_name = bleach.clean(group_name)
    group = db.session.execute(db.session.query(Group).filter_by(name=group_name)).first()
    if not group:
        return jsonify({"success": False, "error": f"Group {group_name} not found"}), 404

    group = group[0]
    members = db.session.execute(db.session.query(GroupUser).filter_by(group_id=group.id)).all()
    return_value = []
    for member in members:
        member = member[0]
        return_value.append(
            {
                "username": member.user.username,
                "direction": member.direction,
                "active": member.enabled,
            }
        )

    return return_value


@group_api.route("/api/groups/members", methods=["DELETE"])
@roles_required("administrator")
def remove_user_from_group():
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

    username = request.args.get("username")
    group_name = request.args.get("group_name")
    direction = request.args.get("direction")

    if not username or not group_name or not direction:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Please provide the username, group name, and direction"),
                }
            ),
            400,
        )

    username = bleach.clean(username)
    group_name = bleach.clean(group_name)
    direction = bleach.clean(direction)

    if group_name.startswith(PAIRWISE_PREFIX):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "This group is managed by the user visibility diagram -- disconnect the "
                        "users there instead of removing one side of it here"
                    ),
                }
            ),
            400,
        )

    if username in app.config.get("RAVEN_PROTECTED_USERNAMES", []):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "%(username)s is a protected system account and can't be modified",
                        username=username,
                    ),
                }
            ),
            403,
        )

    if direction != Group.IN and direction != Group.OUT:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Invalid direction: %(direction)s", direction=direction),
                }
            ),
            400,
        )

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s not found", username=username),
                }
            ),
            404,
        )

    group = db.session.execute(db.session.query(Group).filter_by(name=group_name)).first()
    if not group:
        return jsonify({"success": False, "error": gettext("Group %(group_name)s not found")}), 404

    try:
        GroupUser.query.filter_by(
            group_id=group[0].id, user_id=user.id, direction=direction
        ).delete()
        db.session.commit()

        rabbit_credentials = pika.PlainCredentials(
            app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
        )
        rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
        rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
        )
        channel = rabbit_connection.channel()
        for eud in user.euds:
            channel.queue_unbind(
                exchange="groups", queue=eud.uid, routing_key=f"{group_name}.{direction}"
            )

        channel.close()
        rabbit_connection.close()

        return jsonify({"success": True})
    except BaseException as e:
        logger.error(f"Failed to remove {username} from {group_name}: {e}")
        logger.debug(traceback.format_exc())
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Failed to remove %(username)s from %(group_name)s: %(e)s",
                        username=username,
                        group_name=group_name,
                        e=str(e),
                    ),
                }
            ),
            500,
        )


@group_api.route("/api/groups", methods=["POST"])
@roles_required("administrator")
def add_group():
    """Creates a new group

    :return: 400 if LDAP is enabled, the request is missing the name key or the group exists. 500 on server errors.
    :rtype: Response
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("LDAP is enabled, please use your LDAP server to add groups"),
                }
            ),
            400,
        )

    if "name" not in request.json.keys():
        return jsonify({"success": False, "error": gettext("Missing name")}), 400

    name = bleach.clean(request.json.get("name"))
    if name.startswith(PAIRWISE_PREFIX):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Group names starting with %(prefix)s are reserved", prefix=PAIRWISE_PREFIX),
                }
            ),
            400,
        )
    description = (
        bleach.clean(request.json.get("description"))
        if "description" in request.json.keys()
        else None
    )

    group = db.session.execute(db.session.query(Group).filter_by(name=name)).first()

    try:
        if not group:
            group = Group()
            group.name = name
            group.type = Group.SYSTEM
            group.description = description
            db.session.add(group)
            db.session.commit()
        else:
            return (
                jsonify(
                    {"success": False, "error": gettext("%(name)s group already exists", name=name)}
                ),
                400,
            )

    except BaseException as e:
        logger.error(f"Failed to add {name} group: {e}")
        logger.debug(traceback.format_exc())
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Failed to add %(name)s group: %(e)s", name=name, e=str(e)),
                }
            ),
            500,
        )

    return jsonify({"success": True})


@group_api.route("/api/groups", methods=["PUT"])
@roles_required("administrator")
def add_user_to_group():
    """Adds a users to a group. This will allow all the user's EUDs to subscribe and unsubscribe from the channels/groups they're allowed to see.
    :parameter: users - A list of users to add to a group
    :parameter: group_name - Name of the group to add users to
    :parameter: direction - Group direction, can only be IN or OUT

    :return: 400 if LDAP is enabled, no group or username is specified, or if the specified group or user doesn't exist or the user is already in the group. 200 on success.
    :rtype: Response
    """

    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to add users to groups"
                    ),
                }
            ),
            400,
        )

    users = request.json.get("users")
    group_name = request.json.get("group_name")
    direction = request.json.get("direction")

    if users is None or group_name is None or direction is None:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Please provide a list of users, group name, and direction"),
                }
            ),
            400,
        )

    if direction != "IN" and direction != "OUT":
        return jsonify({"success": False, "error": gettext("Direction must be IN or OUT")}), 400

    for username in users:
        user = app.security.datastore.find_user(username=username)
        if not user:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("User %(username)s does not exist", username=username),
                    }
                ),
                400,
            )

        group = db.session.execute(db.session.query(Group).filter_by(name=group_name)).first()
        if not group:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "Group %(group_name)s does not exist", group_name=group_name
                        ),
                    }
                ),
                400,
            )

        membership = GroupUser()
        membership.user_id = user.id
        membership.group_id = group[0].id
        membership.direction = direction

        try:
            db.session.add(membership)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            db.session.rollback()

    return jsonify({"success": True})


@group_api.route("/api/groups", methods=["DELETE"])
@roles_required("administrator")
def delete_group():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to delete groups"
                    ),
                }
            ),
            400,
        )

    if "group_name" not in request.args.keys() or not request.args.get("group_name"):
        return jsonify({"success": False, "error": gettext("Missing group name")}), 400

    group_name = bleach.clean(request.args.get("group_name"))
    if group_name == "__ANON__":
        return (
            jsonify({"success": False, "error": gettext("The __ANON__ group cannot be deleted")}),
            400,
        )
    if group_name.startswith(PAIRWISE_PREFIX):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "This group is managed by the user visibility diagram -- disconnect the "
                        "users there instead of deleting it directly"
                    ),
                }
            ),
            400,
        )

    try:
        group = db.session.execute(db.session.query(Group).filter_by(name=group_name)).first()
        if not group:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "No such group: %(group_name)s",
                            group_name=request.args.get("group_name"),
                        ),
                    }
                ),
                404,
            )

        group = group[0]

        GroupUser.query.filter_by(group_id=group.id).delete()
        db.session.delete(group)
        db.session.commit()
    except BaseException as e:
        logger.error(f"Failed to delete {request.args.get('group_name')}: {e}")
        logger.debug(traceback.format_exc())
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Failed to delete %(group_name)s: %(e)s",
                        group_name=request.args.get("group_name"),
                        e=str(e),
                    ),
                }
            ),
            500,
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

        if a_to_b_groups and b_to_a_groups:
            edges.append(
                {"source": user_a.username, "target": user_b.username, "type": "solid", "manual": manual}
            )
        elif a_to_b_groups:
            edges.append(
                {"source": user_a.username, "target": user_b.username, "type": "dotted", "manual": manual}
            )
        else:
            edges.append(
                {"source": user_b.username, "target": user_a.username, "type": "dotted", "manual": manual}
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

    # dotted source -> target: source sends (IN), target receives (OUT)
    _set_membership(source.id, group.id, Group.IN, True)
    _set_membership(target.id, group.id, Group.OUT, True)
    if rel_type == "solid":
        _set_membership(target.id, group.id, Group.IN, True)
        _set_membership(source.id, group.id, Group.OUT, True)

    return jsonify({"success": True})


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
    GroupUser.query.filter_by(group_id=group.id).delete()
    db.session.delete(group)
    db.session.commit()

    return jsonify({"success": True})
