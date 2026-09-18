import datetime
import json
import os
import secrets
import string
import traceback
import uuid
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, SubElement, tostring

import bleach
import pika
import sqlalchemy
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_security import (
    admin_change_password,
    auth_required,
    current_user,
    hash_password,
    roles_accepted,
)
from werkzeug.utils import secure_filename

from raven import remote_clear
from raven.models.PendingClearCommand import PendingClearCommand
from raven.blueprints.marti_api.data_package_marti_api import (
    create_data_package_zip,
    save_data_package_file,
)
from raven.blueprints.raven_api.api import paginate, search
from raven.extensions import db, ldap_manager, logger
from raven.functions import iso8601_string_from_datetime
from raven.models.DataPackage import DataPackage
from raven.models.EUD import EUD
from raven.models.Group import Group
from raven.models.GroupUser import GroupUser
from raven.models.user import User
from raven.UsernameValidator import UsernameValidator

user_api_blueprint = Blueprint("user_api_blueprint", __name__)


def _protected_user_response(username: str):
    """Returns a 403 response if username is a protected system/service account
    (see RAVEN_PROTECTED_USERNAMES) being acted on by someone other than itself,
    otherwise None. A protected account can still manage itself -- e.g. "Admin"
    is a super-admin nobody else can touch, but Admin can still edit Admin --
    the caller-vs-self checks each route already has (can't delete/deactivate
    yourself, etc.) still apply on top of this."""
    if username == current_user.username:
        return None
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
    return None


def _add_to_anon_group(user: User):
    """Gives a newly created user an explicit membership (both directions)
    in the __ANON__ group, so they can see and be seen by default without
    an admin having to add them to a group first. Several call sites
    already fall back to __ANON__ for a user with no IN memberships at
    all, but that's a routing-time special case, not a real membership --
    it doesn't show up in the Groups tab or the visibility diagram, and
    every new fallback path has to remember to reimplement it. A real
    membership row makes this the default once, here, instead."""
    anon_group = db.session.execute(db.session.query(Group).filter_by(name="__ANON__")).first()
    if not anon_group:
        return
    anon_group = anon_group[0]
    for direction in (Group.IN, Group.OUT):
        membership = GroupUser()
        membership.user_id = user.id
        membership.group_id = anon_group.id
        membership.direction = direction
        db.session.add(membership)
    try:
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        db.session.rollback()


@user_api_blueprint.route("/api/user/add", methods=["POST"])
@roles_accepted("administrator")
def create_user():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to create users"
                    ),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username"))
    password = bleach.clean(request.json.get("password"))
    confirm_password = bleach.clean(request.json.get("confirm_password"))

    validated_username = UsernameValidator(app).validate(username)
    if validated_username[0]:
        return jsonify({"success": False, "error": f"{validated_username[0]}"}), 400

    if password != confirm_password:
        return jsonify({"success": False, "error": gettext("Passwords do not match")}), 400

    roles = request.json.get("roles")
    if not roles:
        roles = ["user"]
    roles_cleaned = []

    for role in roles:
        role = bleach.clean(role)
        role_exists = app.security.datastore.find_role(role)

        if not role_exists:
            return (
                jsonify(
                    {"success": False, "error": gettext("Role %(role)s does not exist", role=role)}
                ),
                400,
            )

        elif role == "administrator" and not current_user.has_role("administrator"):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "Only administrators can add users to the administrators role"
                        ),
                    }
                ),
                403,
            )

        elif role not in roles_cleaned:
            roles_cleaned.append(role)

    if not app.security.datastore.find_user(username=username):
        logger.info("Creating user {}".format(username))
        new_user = app.security.datastore.create_user(
            username=username,
            password=hash_password(password),
            roles=roles_cleaned,
            # CUSTOM: force_password_change patch -- new users must change their
            # admin-assigned password before doing anything else.
            force_password_change=True,
        )
        db.session.commit()
        _add_to_anon_group(new_user)
        return jsonify({"success": True}), 200
    else:
        logger.error("User {} already exists".format(username))
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s already exists", username=username),
                }
            ),
            400,
        )


@user_api_blueprint.route("/api/user/delete", methods=["POST"])
@roles_accepted("administrator")
def delete_user():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to delete users"
                    ),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username"))

    if username == current_user.username:
        return (
            jsonify({"success": False, "error": gettext("You can't delete your own account")}),
            400,
        )

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

    logger.info("Deleting user {}".format(username))

    try:
        from raven.models.UserFilterMember import UserFilterMember

        user = app.security.datastore.find_user(username=username)
        db.session.execute(sqlalchemy.delete(GroupUser).where(GroupUser.user_id == user.id))
        db.session.execute(
            sqlalchemy.delete(UserFilterMember).where(UserFilterMember.user_id == user.id)
        )
        app.security.datastore.delete_user(user)
    except BaseException as e:
        logger.error(traceback.format_exc())
        return (
            jsonify({"success": False, "error": gettext("Failed to delete user: %(e)s", e=str(e))}),
            400,
        )

    db.session.commit()
    return jsonify({"success": True}), 200


@user_api_blueprint.route("/api/user/password/reset", methods=["POST"])
@roles_accepted("administrator")
def admin_reset_password():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to reset passwords"
                    ),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username"))
    new_password = bleach.clean(request.json.get("new_password"))

    if not username or not new_password:
        return (
            jsonify(
                {"success": False, "error": gettext("Please specify a username and new password")}
            ),
            400,
        )

    if len(new_password) < app.config.get("SECURITY_PASSWORD_LENGTH_MIN"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Your password must be at least %(characters)s characters long",
                        characters=app.config.get("SECURITY_PASSWORD_LENGTH_MIN"),
                    ),
                }
            ),
            400,
        )

    if ":" in new_password or "@" in new_password:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Passwords should not include @ or : characters"),
                },
            ),
            400,
        )

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

    user = app.security.datastore.find_user(username=username)
    if user:
        admin_change_password(user, new_password, False)
        # CUSTOM: force_password_change patch -- admin_change_password() above
        # fires Flask-Security's password_changed signal, which our handler
        # uses to CLEAR force_password_change when a user sets their own new
        # password. An admin-issued reset is a temporary password too, so
        # re-set the flag here, after that signal has already run.
        user.force_password_change = True
        db.session.add(user)
        db.session.commit()
        return jsonify({"success": True}), 200
    else:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Could not find user %(username)s", username=username),
                }
            ),
            400,
        )


# CUSTOM: force_password_change patch -- lets an admin flag an account so the
# user is forced to set their own new password on next login, without the
# admin ever having to choose or type a temporary password for them.
@user_api_blueprint.route("/api/user/force_password_reset", methods=["POST"])
@roles_accepted("administrator")
def force_password_reset():
    username = bleach.clean(request.json.get("username"))
    if not username:
        return jsonify({"success": False, "error": gettext("Please specify a username")}), 400

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Could not find user %(username)s", username=username),
                }
            ),
            400,
        )

    user.force_password_change = True
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True}), 200


# CUSTOM: force_password_change patch -- for a user who has forgotten their
# password entirely (so force_password_reset alone won't help, since they
# can't log in with their old one to be prompted). Generates a random
# temporary password server-side, sets it, and hands it back to the admin to
# relay to the user. force_password_change is set so it must be changed
# before anything else works.
_TEMP_PASSWORD_ALPHABET = "".join(
    c for c in (string.ascii_letters + string.digits) if c not in "0OoIl1"
)


def _generate_temp_password(length: int = 12) -> str:
    return "".join(secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(length))


@user_api_blueprint.route("/api/user/issue_temp_password", methods=["POST"])
@roles_accepted("administrator")
def issue_temp_password():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to reset passwords"
                    ),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username"))
    if not username:
        return jsonify({"success": False, "error": gettext("Please specify a username")}), 400

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Could not find user %(username)s", username=username),
                }
            ),
            400,
        )

    temp_password = _generate_temp_password()
    admin_change_password(user, temp_password, False)
    user.force_password_change = True
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True, "password": temp_password}), 200


@user_api_blueprint.route("/api/user/deactivate", methods=["POST"])
@roles_accepted("administrator")
def deactivate_user():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to deactivate users"
                    ),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username", ""))
    if not username:
        return (
            jsonify(
                {"success": False, "error": gettext("Please specify the username to deactivate")}
            ),
            400,
        )

    if username == current_user.username:
        return (
            jsonify({"success": False, "error": gettext("You can't deactivate your own account")}),
            400,
        )

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

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

    deactivated = app.security.datastore.deactivate_user(user)
    if deactivated:
        db.session.commit()

        # Deactivating only blocks future logins -- a device that's already
        # connected keeps its open socket. Kick every one of the user's EUDs
        # off now, the same way send_file_to_user reaches a connected device:
        # publish to its uid on the "dms" exchange, which EudHandler.on_message
        # is bound to and reads from for that connection.
        euds = db.session.execute(db.session.query(EUD).filter_by(user_id=user.id)).all()
        if euds:
            try:
                rabbit_credentials = pika.PlainCredentials(
                    app.config.get("RAVEN_RABBITMQ_USERNAME"),
                    app.config.get("RAVEN_RABBITMQ_PASSWORD"),
                )
                rabbit_connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS"),
                        credentials=rabbit_credentials,
                    )
                )
                channel = rabbit_connection.channel()
                for eud in euds:
                    channel.basic_publish(
                        exchange="dms",
                        routing_key=eud[0].uid,
                        body=json.dumps({"uid": eud[0].uid, "kick": True}),
                    )
                channel.close()
                rabbit_connection.close()
            except BaseException as e:
                logger.error(f"Failed to kick {username}'s devices after deactivation: {e}")

        return jsonify({"success": True})
    else:
        return jsonify(
            {
                "success": False,
                "error": gettext("%(username)s is already deactivated", username=username),
            }
        )


@user_api_blueprint.route("/api/user/activate", methods=["POST"])
@roles_accepted("administrator")
def activate_user():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to activate users"
                    ),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username", ""))
    if not username:
        return (
            jsonify(
                {"success": False, "error": gettext("Please specify the username to activate")}
            ),
            400,
        )

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

    activated = app.security.datastore.activate_user(user)
    if activated:
        db.session.commit()
        return jsonify({"success": True})
    else:
        return jsonify(
            {
                "success": False,
                "error": gettext("%(username)s is already activated", username=username),
            }
        )


@user_api_blueprint.route("/api/user/site_access/grant", methods=["POST"])
@roles_accepted("administrator")
def grant_site_access():
    username = bleach.clean(request.json.get("username", ""))
    if not username:
        return (
            jsonify(
                {"success": False, "error": gettext("Please specify the username to grant access to")}
            ),
            400,
        )

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

    user.site_access = True
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True})


@user_api_blueprint.route("/api/user/site_access/revoke", methods=["POST"])
@roles_accepted("administrator")
def revoke_site_access():
    username = bleach.clean(request.json.get("username", ""))
    if not username:
        return (
            jsonify(
                {"success": False, "error": gettext("Please specify the username to revoke access from")}
            ),
            400,
        )

    if username == current_user.username:
        return (
            jsonify(
                {"success": False, "error": gettext("You can't revoke your own website access")}
            ),
            400,
        )

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

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

    user.site_access = False
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True})


@user_api_blueprint.route("/api/user/role", methods=["POST"])
@roles_accepted("administrator")
def set_user_role():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to assign roles"
                    ),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username", ""))
    roles = request.json.get("roles")
    roles_cleaned = []

    if not username or not roles:
        return (
            jsonify({"success": False, "error": gettext("Please specify a username and roles")}),
            400,
        )

    if username == current_user.username:
        return (
            jsonify({"success": False, "error": gettext("You can't change your own role")}),
            400,
        )

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

    for role in roles:
        role = bleach.clean(role)
        role_exists = app.security.datastore.find_role(role)

        if not role_exists:
            return (
                jsonify(
                    {"success": False, "error": gettext("Role %(role)s does not exist", role=role)}
                ),
                400,
            )

        elif role not in roles_cleaned:
            roles_cleaned.append(role)

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

    for role in user.roles:
        app.security.datastore.remove_role_from_user(user, role)

    for role in roles_cleaned:
        app.security.datastore.add_role_to_user(user, role)

    db.session.commit()
    return jsonify({"success": True})


@user_api_blueprint.route("/api/user/assign_eud", methods=["POST"])
@auth_required()
def assign_eud_to_user():
    username = bleach.clean(request.json.get("username")) if "username" in request.json else None
    eud_uid = bleach.clean(request.json.get("uid")) if "uid" in request.json else None
    user = None

    if not eud_uid:
        return (
            {"success": False, "error": "Please specify an EUD"},
            400,
            {"Content-Type": "application/json"},
        )
    if not username or username == current_user.username:
        user = current_user
    elif username != current_user.username and current_user.has_role("administrator"):
        user = app.security.datastore.find_user(username=username)
        if not user:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("User %(username)s does not exist", username=username),
                    }
                ),
                404,
            )

    eud = db.session.query(EUD).filter_by(uid=eud_uid).first()

    if not eud:
        return (
            jsonify(
                {"success": False, "error": gettext("EUD %(eud_uid)s not found", eud_uid=eud_uid)}
            ),
            404,
        )
    elif (
        eud.user_id
        and not current_user.has_role("administrator")
        and current_user.id != eud.user_id
    ):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("%(uid)s is already assigned to another user", uid=eud.uid),
                }
            ),
            403,
        )
    else:
        eud.user_id = user.id
        db.session.add(eud)
        db.session.commit()

        return jsonify({"success": True})


def _generate_fileshare_cot(
    data_package: DataPackage,
    sender_uid: str,
    sender_callsign: str,
    download_url: str,
    dest_callsign: str,
) -> Element:
    """Builds a Mission Package / file-share (b-f-t-r) CoT. The two earlier attempts at
    this used the wrong sha256sum attribute name (should be sha256) and were missing the
    <ackrequest> and <marti><dest> elements — found by checking FreeTAKServer's own
    working implementation of the same push (FreeTAKServer/core/services/RestAPI.py),
    since neither this server nor the upstream project has ever implemented this.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    event = Element(
        "event",
        {
            "type": "b-f-t-r",
            "how": "h-e",
            "version": "2.0",
            "uid": str(uuid.uuid4()),
            "start": iso8601_string_from_datetime(now),
            "time": iso8601_string_from_datetime(now),
            "stale": iso8601_string_from_datetime(now + datetime.timedelta(hours=1)),
        },
    )
    SubElement(
        event, "point", {"ce": "9999999", "le": "9999999", "hae": "0", "lat": "0", "lon": "0"}
    )
    detail = SubElement(event, "detail")
    SubElement(
        detail,
        "fileshare",
        {
            "filename": data_package.filename,
            "senderUrl": download_url,
            "sizeInBytes": str(data_package.size),
            "sha256": data_package.hash,
            "senderUid": sender_uid,
            "senderCallsign": sender_callsign,
            "name": data_package.filename,
        },
    )
    SubElement(
        detail,
        "ackrequest",
        {"uid": str(uuid.uuid4()), "ackrequested": "true", "tag": data_package.filename},
    )
    marti = SubElement(detail, "marti")
    SubElement(marti, "dest", {"callsign": dest_callsign})

    return event


@user_api_blueprint.route("/api/user/send_file", methods=["POST"])
@roles_accepted("administrator")
def send_file_to_user():
    """Uploads a file as a data package and sends a GeoChat message containing the
    download link to every EUD belonging to the target user, so it shows up as a chat
    notification in their TAK client.
    """
    username = bleach.clean(request.form.get("username", ""))
    if not username:
        return jsonify({"success": False, "error": gettext("Please specify a username")}), 400

    if "file" not in request.files:
        return jsonify({"success": False, "error": gettext("Please provide a file")}), 400

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s does not exist", username=username),
                }
            ),
            404,
        )

    euds = db.session.execute(db.session.query(EUD).filter_by(user_id=user.id)).all()
    euds = [eud[0] for eud in euds]
    if not euds:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "%(username)s has no devices enrolled to receive a file",
                        username=username,
                    ),
                }
            ),
            400,
        )

    file = request.files["file"]
    name, extension = os.path.splitext(file.filename)
    extension = extension.replace(".", "")
    if not extension and "zip" in file.mimetype:
        extension = "zip"

    if extension.lower() not in app.config.get("ALLOWED_EXTENSIONS"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Invalid file extension: %(extension)s", extension=extension
                    ),
                }
            ),
            400,
        )

    # Data package filenames must be globally unique, so resending a file that was
    # already sent before (by anyone) reuses the existing package instead of trying
    # to create a second one with a colliding name.
    safe_filename = "{}.zip".format(os.path.splitext(secure_filename(file.filename))[0])
    data_package = db.session.execute(
        db.session.query(DataPackage).filter_by(filename=safe_filename)
    ).first()

    if data_package:
        data_package = data_package[0]
    else:
        if extension.lower() != "zip":
            file_hash = create_data_package_zip(file)
        else:
            file_hash = save_data_package_file(file, username=current_user.username)

        data_package = db.session.execute(
            db.session.query(DataPackage).filter_by(hash=file_hash)
        ).first()
        if not data_package:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("Failed to save the uploaded file"),
                    }
                ),
                500,
            )
        data_package = data_package[0]

    url = urlparse(request.url_root)
    metadata_url = "https://{}:{}/Marti/api/sync/metadata/{}/tool".format(
        url.hostname, app.config.get("RAVEN_MARTI_HTTPS_PORT"), data_package.hash
    )

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            host=app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS"), credentials=rabbit_credentials
        )
    )
    channel = rabbit_connection.channel()
    for eud in euds:
        fileshare_event = _generate_fileshare_cot(
            data_package,
            app.config.get("RAVEN_SERVER_SENDER_UID", "server-uid"),
            app.config.get("RAVEN_SERVER_SENDER_CALLSIGN", "Server"),
            metadata_url,
            eud.callsign,
        )
        channel.basic_publish(
            exchange="dms",
            routing_key=eud.uid,
            body=json.dumps(
                {
                    "uid": app.config.get("RAVEN_NODE_ID"),
                    "cot": tostring(fileshare_event).decode("utf-8"),
                }
            ),
        )
    channel.close()
    rabbit_connection.close()

    logger.info(
        "{} sent file {} to {} ({} device(s))".format(
            current_user.username, data_package.filename, username, len(euds)
        )
    )

    return jsonify({"success": True})


@user_api_blueprint.route("/api/users")
@roles_accepted("administrator")
def get_users():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to manage users"
                    ),
                }
            ),
            400,
        )

    query = db.session.query(User)
    query = search(query, User, "username")

    filter_id = request.args.get("filter_id")
    if filter_id:
        from raven.models.UserFilterMember import UserFilterMember

        try:
            filter_id = int(filter_id)
        except ValueError:
            filter_id = None
        if filter_id is not None:
            query = query.join(
                UserFilterMember, UserFilterMember.user_id == User.id
            ).filter(UserFilterMember.filter_id == filter_id)

    # Pin protected system accounts (e.g. "Server") to the top of the list,
    # regardless of the requested sort column/direction, which paginate()
    # applies afterward as the secondary sort.
    protected_usernames = app.config.get("RAVEN_PROTECTED_USERNAMES", [])
    if protected_usernames:
        query = query.order_by(
            sqlalchemy.case((User.username.in_(protected_usernames), 0), else_=1)
        )

    return paginate(query, User)


@user_api_blueprint.route("/api/users/all")
@roles_accepted("administrator")
def get_all_users():
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to manage users"
                    ),
                }
            ),
            400,
        )

    query = db.session.query(User)

    filter_id = request.args.get("filter_id")
    if filter_id:
        from raven.models.UserFilterMember import UserFilterMember

        try:
            filter_id = int(filter_id)
        except ValueError:
            filter_id = None
        if filter_id is not None:
            query = query.join(
                UserFilterMember, UserFilterMember.user_id == User.id
            ).filter(UserFilterMember.filter_id == filter_id)

    users = db.session.execute(query).all()
    return_value = []

    for user in users:
        user = user[0]
        return_value.append(user.serialize())

    return return_value


@user_api_blueprint.route("/api/users/groups")
@roles_accepted("administrator")
def get_user_groups():
    """Gets a list of group memberships for a user
    :parameter: username

    :return: List of group memberships
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "LDAP is enabled, please use your LDAP server to manage groups"
                    ),
                }
            ),
            400,
        )

    username = request.args.get("username")
    if not username:
        return jsonify({"success": False, "error": gettext("Please provide a username")}), 400

    username = bleach.clean(username)

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

    group_memberships = db.session.execute(
        db.session.query(GroupUser).filter_by(user_id=user.id)
    ).all()
    memberships = []
    for membership in group_memberships:
        membership: GroupUser = membership[0]
        memberships.append(
            {
                "group_name": membership.group.name,
                "direction": membership.direction,
                "active": membership.enabled,
            }
        )

    return jsonify({"success": True, "results": memberships})


@user_api_blueprint.route("/api/users/groups", methods=["PUT"])
@roles_accepted("administrator")
def add_user_to_groups():
    """Adds a user to one or more groups
    :parameter: groups - List of groups to add a user to
    :parameter: username
    :parameter: direction - Group direction, must be either IN or OUT

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

    groups = request.json.get("groups")
    username = request.json.get("username")
    direction = request.json.get("direction")

    if not groups or not username or not direction:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Please provide a list of groups, a username, and a direction"
                    ),
                }
            ),
            400,
        )

    if direction != "IN" and direction != "OUT":
        return jsonify({"success": False, "error": gettext("Direction must be IN or OUT")}), 400

    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s doesn't exist", username=username),
                }
            ),
            404,
        )

    for group_name in groups:
        group_name = bleach.clean(group_name)
        group = db.session.execute(db.session.query(Group).filter_by(name=group_name)).first()
        if not group:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "Group %(group_name)s doesn't exist", group_name=group_name
                        ),
                    }
                ),
                404,
            )

        group = group[0]

        membership = GroupUser()
        membership.user_id = user.id
        membership.group_id = group.id
        membership.direction = direction

        try:
            db.session.add(membership)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            db.session.rollback()

    return jsonify({"success": True})


@user_api_blueprint.route("/api/users/filters", methods=["GET"])
@roles_accepted("administrator")
def get_user_filters():
    """List all user filters and their members

    :return: JSON array of {id, name, usernames}
    """
    from raven.models.UserFilter import UserFilter

    filters = db.session.execute(db.session.query(UserFilter).order_by(UserFilter.name)).all()
    return jsonify([f[0].serialize() for f in filters])


@user_api_blueprint.route("/api/users/filters", methods=["POST"])
@roles_accepted("administrator")
def create_user_filter():
    """Create an empty filter (PUT /api/users/filters also creates one by
    name as a side effect of adding a member, but the "Manage Filters" UI
    needs to be able to make one with nobody in it yet).

    :parameter: name

    :return: 400 if name is missing, 409 if a filter by that name already
        exists. 200 on success.
    """
    from raven.models.UserFilter import UserFilter

    name = request.json.get("name")
    if not name:
        return jsonify({"success": False, "error": gettext("Please provide a name")}), 400

    name = bleach.clean(name)

    if db.session.execute(db.session.query(UserFilter).filter_by(name=name)).first():
        return (
            jsonify({"success": False, "error": gettext("A filter named %(name)s already exists", name=name)}),
            409,
        )

    db.session.add(UserFilter(name=name))
    db.session.commit()
    return jsonify({"success": True})


@user_api_blueprint.route("/api/users/filters", methods=["PUT"])
@roles_accepted("administrator")
def add_user_to_filter():
    """Add a user to a filter, creating the filter first if this is the
    first time that name has been used.

    :parameter: username
    :parameter: filter_name

    :return: 400 if username or filter_name is missing, or the user doesn't
        exist. 200 on success (including if the user is already a member).
    """
    from raven.models.UserFilter import UserFilter
    from raven.models.UserFilterMember import UserFilterMember

    username = request.json.get("username")
    filter_name = request.json.get("filter_name")

    if not username or not filter_name:
        return (
            jsonify(
                {"success": False, "error": gettext("Please provide a username and filter_name")}
            ),
            400,
        )

    username = bleach.clean(username)
    filter_name = bleach.clean(filter_name)

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {"success": False, "error": gettext("User %(username)s does not exist", username=username)}
            ),
            400,
        )

    user_filter = db.session.execute(
        db.session.query(UserFilter).filter_by(name=filter_name)
    ).first()
    if user_filter:
        user_filter = user_filter[0]
    else:
        user_filter = UserFilter(name=filter_name)
        db.session.add(user_filter)
        db.session.commit()

    try:
        db.session.add(UserFilterMember(user_id=user.id, filter_id=user_filter.id))
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        db.session.rollback()

    return jsonify({"success": True})


@user_api_blueprint.route("/api/users/filters", methods=["DELETE"])
@roles_accepted("administrator")
def remove_user_from_filter():
    """Remove a user from a filter. The filter itself is left in place
    (possibly empty) for the admin to reuse or delete explicitly.

    :parameter: username
    :parameter: filter_name

    :return: 400 if username or filter_name is missing, 404 if the filter
        doesn't exist. 200 on success.
    """
    from raven.models.UserFilter import UserFilter
    from raven.models.UserFilterMember import UserFilterMember

    username = request.args.get("username")
    filter_name = request.args.get("filter_name")

    if not username or not filter_name:
        return (
            jsonify(
                {"success": False, "error": gettext("Please provide a username and filter_name")}
            ),
            400,
        )

    username = bleach.clean(username)
    filter_name = bleach.clean(filter_name)

    user = app.security.datastore.find_user(username=username)
    user_filter = db.session.execute(
        db.session.query(UserFilter).filter_by(name=filter_name)
    ).first()
    if not user or not user_filter:
        return jsonify({"success": False, "error": gettext("Filter or user not found")}), 404

    membership = db.session.get(UserFilterMember, {"user_id": user.id, "filter_id": user_filter[0].id})
    if membership:
        db.session.delete(membership)
        db.session.commit()

    return jsonify({"success": True})


@user_api_blueprint.route("/api/users/filters/<int:filter_id>", methods=["DELETE"])
@roles_accepted("administrator")
def delete_user_filter(filter_id):
    """Delete a filter entirely (all of its membership rows go with it).

    :return: 404 if the filter doesn't exist. 200 on success.
    """
    from raven.models.UserFilter import UserFilter

    user_filter = db.session.get(UserFilter, filter_id)
    if not user_filter:
        return jsonify({"success": False, "error": gettext("Filter not found")}), 404

    from raven.models.UserFilterMember import UserFilterMember

    for membership in db.session.execute(
        db.session.query(UserFilterMember).filter_by(filter_id=filter_id)
    ).all():
        db.session.delete(membership[0])
    # Both sides of the UserFilter <-> UserFilterMember relationship are
    # viewonly (membership is only ever written through UserFilterMember
    # directly), so the unit of work has no relationship info to order
    # these deletes by -- flush the member deletes first so they hit the DB
    # before the filter row does, or this trips the members table's own FK
    # to it.
    db.session.flush()
    db.session.delete(user_filter)
    db.session.commit()

    return jsonify({"success": True})


@user_api_blueprint.route("/api/user/clear_content", methods=["POST"])
@roles_accepted("administrator")
def clear_user_content():
    """Remotely clear ATAK content on a user's devices.

    Sends a signed ``t-x-raven-clr`` command (see raven.remote_clear) to each of
    the user's EUDs. Only devices running the C4 Raven Remote Clear plugin act
    on it; the plugin verifies the server signature, that the command targets
    its own uid, and that it arrived over the server stream, then runs ATAK's
    Clear Content (a full local wipe; the app exits). This does not touch
    server-side data and is not reversible on the device.

    Two delivery modes, chosen by ``queue_if_offline``:

    * false (default): best-effort live publish to every device's direct-message
      queue with a ten-minute TTL. Reaches whoever is genuinely connected right
      now; anything else is silently lost.
    * true: store-and-forward. One PendingClearCommand row is written for EVERY
      device and NOTHING is published live. EudHandler delivers the row on the
      device's next connection. Devices whose row currently says "Connected"
      are asked (via the ``eud_control`` exchange) to drop their socket; ATAK
      reconnects within seconds and the pending row is delivered then.

    Why queue mode ignores last_status entirely: that column lags reality by up
    to the TCP keepalive window. A phone whose wifi was switched off moments
    ago still reads "Connected", so a "send live if online, else queue" rule
    publishes into a dead socket, consumes the message (auto_ack) and never
    retries it -- observed 2026-09-19. The plugin sends no delivery
    acknowledgement, so the server cannot tell a live send that landed from
    one that vanished, and sending live AND queueing would double-wipe a
    device that really was online. The only safe rule is a single delivery
    path: store, then deliver on the next connection, forcing that connection
    for devices that look online.
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("LDAP is enabled, please manage users on your LDAP server"),
                }
            ),
            400,
        )

    username = bleach.clean(request.json.get("username", ""))
    if not username:
        return (
            jsonify({"success": False, "error": gettext("Please specify a username")}),
            400,
        )

    # Protected accounts (other admins, etc.) are shielded the same way as
    # deactivation: an admin shouldn't be able to wipe a protected peer's device.
    protected_response = _protected_user_response(username)
    if protected_response:
        return protected_response

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s does not exist", username=username),
                }
            ),
            404,
        )

    clearmaps = bool(request.json.get("clearmaps", False))
    # See the docstring: when set, every device gets a stored command that is
    # delivered on its next connection (EudHandler.parse_device_info), and
    # devices that look online are told to reconnect so that happens now.
    # When unset, only devices online right now are reached (best effort).
    queue_if_offline = bool(request.json.get("queue_if_offline", False))

    euds = db.session.execute(db.session.query(EUD).filter_by(user_id=user.id)).all()
    if not euds:
        return (
            jsonify(
                {"success": False, "error": gettext("This user has no enrolled devices")}
            ),
            400,
        )

    node_id = app.config.get("RAVEN_NODE_ID")
    now = datetime.datetime.now(datetime.timezone.utc)
    sent_now = 0
    queued = 0
    reconnect_requested = 0
    rabbit_connection = None
    try:
        if queue_if_offline:
            # Persist first, publish second: the row must be committed before
            # any reconnect it triggers can look for it.
            for eud in euds:
                device = eud[0]
                db.session.add(
                    PendingClearCommand(
                        eud_uid=device.uid,
                        clearmaps=clearmaps,
                        requested_by=current_user.username,
                        requested_at=now,
                        node_id=node_id,
                    )
                )
                queued += 1
            db.session.commit()

        rabbit_credentials = pika.PlainCredentials(
            app.config.get("RAVEN_RABBITMQ_USERNAME"),
            app.config.get("RAVEN_RABBITMQ_PASSWORD"),
        )
        rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS"),
                credentials=rabbit_credentials,
            )
        )
        channel = rabbit_connection.channel()

        if queue_if_offline:
            # Ask every handler for a device that looks online to drop its
            # socket. ATAK auto-reconnects and the stored row is delivered on
            # that reconnect. A handler whose peer is already dead (status not
            # yet caught up) just closes early; nothing is lost either way.
            # Args must match the declaration in raven.app / EudHandler
            # exactly or the broker closes the channel with 406.
            channel.exchange_declare("eud_control", durable=True, exchange_type="direct")
            for eud in euds:
                device = eud[0]
                if device.last_status == "Connected":
                    channel.basic_publish(
                        exchange="eud_control",
                        routing_key=device.uid,
                        body=json.dumps({"action": "disconnect", "uid": device.uid}),
                        properties=pika.BasicProperties(expiration="10000"),
                    )
                    reconnect_requested += 1
        else:
            # Best-effort live publish; expires in the queue after ten minutes.
            for eud in euds:
                device = eud[0]
                remote_clear.publish_clear_cot(
                    channel, device.uid, node_id, clearmaps=clearmaps
                )
                sent_now += 1
        channel.close()
    except BaseException as e:
        db.session.rollback()
        logger.error(f"Failed to send clear-content command for {username}: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if rabbit_connection is not None and rabbit_connection.is_open:
            rabbit_connection.close()

    logger.warning(
        "Admin %s issued remote clear-content for %s: %d sent now, %d queued for "
        "next connection, %d reconnect(s) requested (clearmaps=%s, queue_if_offline=%s)",
        current_user.username,
        username,
        sent_now,
        queued,
        reconnect_requested,
        clearmaps,
        queue_if_offline,
    )
    return jsonify(
        {
            "success": True,
            "devices": len(euds),
            "sent_now": sent_now,
            "queued": queued,
            "reconnect_requested": reconnect_requested,
            "clearmaps": clearmaps,
        }
    )
