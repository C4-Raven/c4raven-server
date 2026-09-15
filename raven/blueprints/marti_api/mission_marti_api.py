import datetime
import hashlib
import io
import json
import os
import time
import traceback
import uuid
import zipfile
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, SubElement, fromstring, tostring

import bleach
import flask
import jwt
import pika
import sqlalchemy.exc
from bs4 import BeautifulSoup
from flask import Blueprint, Response
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_security import current_user, hash_password, verify_password
from sqlalchemy import insert, or_, update
from werkzeug.utils import secure_filename

from raven.blueprints.marti_api.data_package_marti_api import save_data_package_file
from raven.blueprints.marti_api.marti_api import verify_client_cert
from raven.extensions import db, logger
from raven.functions import datetime_from_iso8601_string, iso8601_string_from_datetime
from raven.models.CoT import CoT
from raven.models.EUD import EUD
from raven.models.Group import Group
from raven.models.GroupMission import GroupMission
from raven.models.GroupUser import GroupUser
from raven.models.Mission import Mission
from raven.models.MissionChange import (
    MissionChange,
    generate_mission_change_cot,
    upsert_mission_uid_and_change,
)
from raven.models.MissionContent import MissionContent
from raven.models.MissionContentMission import MissionContentMission
from raven.models.MissionInvitation import InvitationTypeEnum, MissionInvitation
from raven.models.MissionLogEntry import MissionLogEntry
from raven.models.MissionRole import MissionRole
from raven.models.MissionUID import MissionUID
from raven.models.Team import Team
from raven.models.user import User

mission_marti_api = Blueprint("mission_marti_api", __name__)


# Only allow access to the mission/data sync API over SSL/port 8443 with a valid client cert.
# nginx will proxy the cert in a header called X-Ssl-Cert by default. This is configurable in ots_https and with the
# RAVEN_SSL_CERT_HEADER option in config.yml
# @mission_marti_api.before_request
# def verify_client_cert_before_request():
#    if not verify_client_cert():
#        return jsonify({'success': False, 'error': 'Missing or invalid client certificate'}), 400


def _mission_token_header() -> str | None:
    """Return the bearer mission token from the request, if any.

    TAK Server reads it from the MissionAuthorization header first and only falls back to
    Authorization (MissionServiceDefaultImpl), so clients written against it may send the token
    only in the former. We previously looked at Authorization alone, which made every token-guarded
    route (DELETE mission, ...) answer 401 to such clients even when they held a valid owner token.
    """
    for header in ("MissionAuthorization", "Authorization"):
        value = request.headers.get(header)
        if value and "Bearer" in value:
            if header == "MissionAuthorization":
                logger.info("Mission token supplied via MissionAuthorization header")
            return value.replace("Bearer ", "").strip()
    return None


def verify_token() -> dict | bool:
    token = _mission_token_header()
    if not token:
        return False

    with open(
        os.path.join(
            app.config.get("RAVEN_CA_FOLDER"), "certs", "raven", "raven.pub"
        ),
        "r",
    ) as key:
        try:
            return jwt.decode(token, key.read(), algorithms=["RS256"])
        except BaseException as e:
            logger.error("Failed to validate mission token: {}".format(e))
            logger.debug(traceback.format_exc())
            return False


# iTAK sucks and doesn't send a token for some reason...
def verify_itak_certificate(
    mission_name: str = None, mission_guid: str = None
) -> MissionRole | flask.Response:
    # Every error path must return a real flask.Response (not a (jsonify, status) tuple): all callers
    # test `isinstance(result, flask.Response)`, so a tuple would silently grant access.
    # Get the username from the client cert forwarded by nginx
    cert = verify_client_cert()
    if not cert:
        return flask.make_response(
            jsonify({"success": False, "error": "Missing or invalid client certificate"}), 401
        )
    username = cert.get_subject().commonName

    # Check that the user exists
    user = db.session.execute(db.session.query(User).filter_by(username=username)).first()
    if not user:
        return flask.make_response(
            jsonify({"success": False, "error": f"User {username} not found"}), 401
        )
    user = user[0]

    # Check that the user owns this EUD
    eud_uid = request.args.get("creatorUid")
    if not eud_uid:
        return flask.make_response(jsonify({"success": False, "error": "Invalid creatorUid"}), 400)

    eud = db.session.execute(db.session.query(EUD).filter_by(uid=eud_uid, user_id=user.id)).first()
    if not eud:
        return flask.make_response(
            jsonify({"success": False, "error": f"User {username} does not own EUD {eud_uid}"}),
            401,
        )
    eud = eud[0]

    if not mission_name and mission_guid:
        mission = db.session.execute(db.session.query(Mission).filter_by(guid=mission_guid)).first()
        if not mission:
            return flask.make_response(
                jsonify({"success": False, "error": f"Invalid mission GUID: {mission_guid}"}),
                404,
            )
        mission_name = mission[0].name

    # Check that the EUD is subscribed to this mission
    mission_role = db.session.execute(
        db.session.query(MissionRole).filter_by(
            clientUid=eud.uid, username=username, mission_name=mission_name
        )
    ).first()
    if not mission_role:
        logger.error(f"Access denied {username} {mission_name} {eud_uid}")
        return flask.make_response(jsonify({"success": False, "error": "Access Denied"}), 403)

    return mission_role[0]


def check_permission(mission_name: str = None, mission_guid: str = None) -> bool | flask.Response:
    """Returns True when access is granted, otherwise a flask.Response (never a tuple: callers use isinstance)."""
    if "iTAK" not in request.user_agent.string:
        token = verify_token()
        if mission_name and (not token or token.get("MISSION_NAME") != mission_name):
            return flask.make_response(
                jsonify({"success": False, "error": "Missing or invalid token"}), 401
            )
        elif mission_guid and (not token or token.get("MISSION_GUID") != mission_guid):
            return flask.make_response(
                jsonify({"success": False, "error": "Missing or invalid token"}), 401
            )
    else:
        cert_is_valid = verify_itak_certificate(mission_name, mission_guid)
        if isinstance(cert_is_valid, flask.Response):
            return cert_is_valid

    return True


def _resolve_mission_name(mission_name: str | None, mission_guid: str | None = None) -> str | None:
    """
    TAK Server exposes a /missions/guid/<guid>/... twin of nearly every /missions/<name>/... route and
    TAKX uses the GUID form for most of Data Sync; the handlers here key on the name, so resolve it once.
    """
    if mission_name:
        return mission_name
    if mission_guid:
        mission = db.session.execute(db.session.query(Mission).filter_by(guid=mission_guid)).first()
        if mission:
            return mission[0].name
    return None


def _mission_not_found(identifier: str | None):
    return (
        jsonify(
            {
                "success": False,
                "error": gettext("Mission %(mission_name)s not found", mission_name=identifier or ""),
            }
        ),
        404,
    )


def generate_token(mission: Mission, eud_uid: str):
    """
    jti: Unique UUID for the token
    iat: Time token was issued. Can be used to invalidate a token if it was issued before a security event occurred
    sub: The thing the token identifies, the EUD's UID in this case. Used to verify EUD roles, ie MISSION_SUBSCRIBER, MISSION_OWNER, or MISSION_READ_ONLY
    MISSION_NAME: The mission this token is for
    MISSION_GUID: The guid of the mission this token is for

    :param mission:
    :param eud_uid:
    :return: string token
    """
    payload = {
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "sub": eud_uid,
        "iss": urlparse(request.base_url).hostname,
        "MISSION_NAME": mission.name,
        "MISSION_GUID": mission.guid,
    }

    server_key = open(
        os.path.join(
            app.config.get("RAVEN_CA_FOLDER"), "certs", "raven", "raven.nopass.key"
        ),
        "r",
    )

    token = jwt.encode(payload, server_key.read(), algorithm="RS256")
    server_key.close()

    return token


def generate_new_mission_cot(mission: Mission) -> Element:
    event = Element(
        "event",
        {
            "type": "t-x-m-n",
            "how": "h-g-i-g-o",
            "version": "2.0",
            "uid": str(uuid.uuid4()),
            "start": iso8601_string_from_datetime(datetime.datetime.now(datetime.timezone.utc)),
            "time": iso8601_string_from_datetime(datetime.datetime.now(datetime.timezone.utc)),
            "stale": iso8601_string_from_datetime(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            ),
        },
    )
    SubElement(
        event, "point", {"ce": "9999999", "le": "9999999", "hae": "0", "lat": "0", "lon": "0"}
    )
    detail = SubElement(event, "detail")
    SubElement(
        detail,
        "mission",
        {
            "type": Mission.CREATE,
            "tool": mission.tool or "public",
            "name": mission.name,
            "guid": mission.guid or "",
            "authorUid": mission.creator_uid or "",
        },
    )

    return event


def generate_invitation_cot(
    mission: Mission,
    uid: str,
    cot_type: str = "t-x-m-i",
    delete: bool = False,
    role: str | None = None,
) -> Element:
    """
    Generates an invitation (t-x-m-i) or role change (t-x-m-r) cot

    Data Sync clients (ATAK's Data Sync plugin, WinTAK, TAKX) only act on <mission> elements
    whose tool is "public" -- other tools (ExCheck, citrap, ...) belong to other plugins -- so the
    tool/guid/authorUid attributes are always emitted with a usable value even when the mission row
    was created by the web UI with tool="" (the UI's create dialog submits an empty string).
    :param mission:
    :param uid:
    :param cot_type:
    :param delete:
    :param role: role type being granted (MISSION_OWNER/MISSION_SUBSCRIBER/MISSION_READ_ONLY);
                 defaults to the mission's default role
    :return:
    """

    event = Element(
        "event",
        {
            "type": cot_type,
            "how": "h-g-i-g-o",
            "version": "2.0",
            "uid": str(uuid.uuid4()),
            "start": iso8601_string_from_datetime(datetime.datetime.now(datetime.timezone.utc)),
            "time": iso8601_string_from_datetime(datetime.datetime.now(datetime.timezone.utc)),
            "stale": iso8601_string_from_datetime(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            ),
        },
    )

    SubElement(
        event, "point", {"ce": "9999999", "le": "9999999", "hae": "0", "lat": "0", "lon": "0"}
    )
    detail = SubElement(event, "detail")
    mission_tag = SubElement(
        detail,
        "mission",
        {
            "type": Mission.INVITE,
            "tool": mission.tool or "public",
            "name": mission.name,
            "guid": mission.guid or "",
            "authorUid": mission.creator_uid or "",
            "token": generate_token(mission, uid),
        },
    )

    if not delete:
        role_type = role or mission.default_role or MissionRole.MISSION_SUBSCRIBER
        role_tag = SubElement(mission_tag, "role", {"type": role_type})
        permissions = SubElement(role_tag, "permissions")

        if role_type == MissionRole.MISSION_SUBSCRIBER:
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_READ})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_WRITE})
        elif role_type == MissionRole.MISSION_OWNER:
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_MANAGE_FEEDS})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_SET_PASSWORD})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_WRITE})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_MANAGE_LAYERS})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_UPDATE_GROUPS})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_DELETE})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_SET_ROLE})
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_READ})
        else:
            SubElement(permissions, "permission", {"type": MissionRole.MISSION_READ})

    return event


def generate_mission_delete_cot(mission: Mission) -> Element:
    event = Element(
        "event",
        {
            "type": "t-x-m-d",
            "how": "h-g-i-g-o",
            "version": "2.0",
            "uid": str(uuid.uuid4()),
            "start": iso8601_string_from_datetime(datetime.datetime.now(datetime.timezone.utc)),
            "time": iso8601_string_from_datetime(datetime.datetime.now(datetime.timezone.utc)),
            "stale": iso8601_string_from_datetime(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            ),
        },
    )
    SubElement(
        event, "point", {"ce": "9999999", "le": "9999999", "hae": "0", "lat": "0", "lon": "0"}
    )
    detail = SubElement(event, "detail")
    SubElement(
        detail,
        "mission",
        {
            "type": Mission.DELETE,
            "tool": mission.tool or "public",
            "name": mission.name,
            "guid": mission.guid or "",
            "authorUid": mission.creator_uid or "",
        },
    )

    return event


@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>")
def get_mission_by_guid(mission_guid: str):
    permission_granted = check_permission(mission_guid=mission_guid)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    password = request.args.get("password")
    mission = db.session.execute(db.session.query(Mission).filter_by(guid=mission_guid)).first()
    if not mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "No mission found with guid: %(mission_guid)s", mission_guid=mission_guid
                    ),
                }
            ),
            404,
        )
    mission = mission[0]

    if mission.password_protected and (not password or not verify_password(password, mission.password)):
        return jsonify({"success": False, "error": gettext("Invalid password")}), 401

    return jsonify(
        {
            "version": "3",
            "type": "Mission",
            "data": [mission.to_marti_json(logs=request.args.get("logs", "false").lower() == "true")],
            "nodeId": app.config.get("RAVEN_NODE_ID"),
        }
    )


@mission_marti_api.route("/Marti/api/missions")
def get_missions():
    cert = verify_client_cert()
    if not cert:
        return "", 401

    username = cert.get_subject().commonName
    user = app.security.datastore.find_user(username=username)
    if not user:
        logger.warning(f"/Marti/api/missions: no account matches certificate CN {username!r}")
        return jsonify({"success": False, "error": gettext("Unknown user certificate")}), 403

    # TAK Server semantics: passwordProtected defaults to false (password-protected missions are hidden
    # unless asked for) and the listing is filtered to a single tool, "public" (Data Sync), unless the
    # client names another one (ExCheck, citrap, ...)
    password_protected = request.args.get("passwordProtected", "false").lower() == "true"
    tool = bleach.clean(request.args.get("tool") or "public")

    default_role = request.args.get("defaultRole")
    if default_role:
        default_role = bleach.clean(default_role).lower() == "true"

    response = {
        "version": "3",
        "type": "Mission",
        "data": [],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }

    try:
        query = db.session.query(Mission)

        # Let admins see all missions
        if not user.has_role("administrator"):
            # Missions with no group assignment at all are public/ungrouped and visible to everyone
            group_filters = [GroupMission.mission_name.is_(None)]
            groups = db.session.execute(
                db.session.query(GroupUser).filter_by(user_id=user.id, direction=Group.IN)
            ).scalars()
            for group in groups:
                group_filters.append(GroupMission.group_id == group.group.id)
            query = query.outerjoin(GroupMission).where(or_(*group_filters))

        missions = db.session.execute(query).scalars()
        for mission in missions:
            if not password_protected and mission.password_protected:
                continue
            if (mission.tool or "public") != tool:
                continue
            response["data"].append(mission.to_marti_json())

    except BaseException as e:
        logger.error(f"Failed to get missions: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500

    return jsonify(response)


@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/invitations", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/<mission_name>/invitations", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/all/invitations", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/invitations", methods=["GET"])
def all_invitations(mission_name: str | None = None, mission_guid: str | None = None):
    # Each returned invitation carries a mission token minted for clientUid, so the caller must
    # hold a client cert for the user that owns that EUD (or be an administrator).
    cert = verify_client_cert()
    if not cert:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Missions are only supported on SSL connections"),
                }
            ),
            400,
        )
    username = cert.get_subject().commonName
    user = app.security.datastore.find_user(username=username)
    if not user:
        logger.warning(f"/Marti/api/missions/.../invitations: no account matches certificate CN {username!r}")
        return jsonify({"success": False, "error": gettext("Unknown user certificate")}), 403

    if "clientUid" in request.args and request.args.get("clientUid"):
        client_uid = bleach.clean(request.args.get("clientUid"))
    else:
        client_uid = None

    if client_uid and not user.has_role("administrator"):
        eud = db.session.execute(
            db.session.query(EUD).filter_by(uid=client_uid, user_id=user.id)
        ).first()
        if not eud:
            logger.warning(f"{username} asked for the invitations/tokens of EUD {client_uid} it does not own")
            return jsonify({"success": False, "error": gettext("Access Denied")}), 403

    response = {
        "version": "3",
        "type": "MissionInvitation",
        "data": [],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
        "messages": [],
    }

    query = db.session.query(MissionInvitation)
    if client_uid:
        query = query.where(MissionInvitation.client_uid == client_uid)

    if mission_name:
        query = query.join(Mission).where(Mission.name == mission_name)
    elif mission_guid:
        query = query.join(Mission).where(Mission.guid == mission_guid)

    invitations = db.session.execute(query).all()

    # TAK Server's /missions/all/invitations answers with just the mission names (Set<String>); the
    # other three routes return the full invitation objects
    names_only = request.path.rstrip("/").endswith("/missions/all/invitations")
    for invitation in invitations:
        invitation = invitation[0]
        if names_only:
            if invitation.mission_name not in response["data"]:
                response["data"].append(invitation.mission_name)
            continue
        token = generate_token(invitation.mission, client_uid) if client_uid and invitation.mission else ""
        response["data"].append(invitation.to_marti_json(token))

    return jsonify(response)


@mission_marti_api.route("/Marti/api/missions/<mission_name>", methods=["PUT", "POST"])
def put_mission(mission_name: str):
    """Used by the Data Sync plugin to create or change a mission"""
    cert = verify_client_cert()
    if not cert:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Missions are only supported on SSL connections"),
                }
            ),
            400,
        )

    username = cert.get_subject().commonName
    user = app.security.datastore.find_user(username=username)
    if not user:
        logger.warning(f"/Marti/api/missions/{mission_name}: no account matches certificate CN {username!r}")
        return jsonify({"success": False, "error": gettext("Unknown user certificate")}), 403

    new_mission = True

    if not mission_name or not request.args.get("creatorUid"):
        return (
            jsonify(
                {"success": False, "error": gettext("Please provide a mission name and creatorUid")}
            ),
            400,
        )

    eud = db.session.execute(
        db.session.query(EUD).filter_by(uid=request.args.get("creatorUid"))
    ).first()
    if not eud:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Invalid creatorUid: %(creator_uid)s",
                        creator_uid=request.args.get("creatorUid"),
                    ),
                }
            ),
            400,
        )
    eud = eud[0]

    password = None
    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if mission:
        mission = mission[0]
        new_mission = False
    else:
        mission = Mission()
        mission.name = bleach.clean(mission_name)
        if "password" in request.args and request.args.get("password"):
            password = hash_password(request.args.get("password"))

    mission.creator_uid = (
        mission.creator_uid or request.args.get("creatorUid") or mission.creator_uid or None
    )
    mission.description = request.args.get("description") or mission.description or None
    mission.tool = request.args.get("tool") or mission.tool or "public"
    mission.group = request.args.get("group") or mission.group or "__ANON__"
    mission.default_role = (
        MissionRole.normalize_role_type(request.args.get("defaultRole"))
        or mission.default_role
        or MissionRole.MISSION_SUBSCRIBER
    )
    mission.password = password or mission.password or None
    mission.password_protected = mission.password is not None
    mission.guid = mission.guid or str(uuid.uuid4())
    mission.create_time = mission.create_time or datetime.datetime.now(datetime.timezone.utc)

    try:
        db.session.add(mission)
        # Will raise IntegrityError if the mission exists, meaning we should update it
        db.session.commit()

        groups = request.args.get("group")
        if groups:
            for group_name in groups.split(","):
                group = db.session.execute(
                    db.session.query(Group).filter_by(name=group_name)
                ).scalar()
                if not group:
                    # Drop the GroupMission rows already staged for this request
                    db.session.rollback()
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": gettext(
                                    "Group not found: %(group_name)s", group_name=group_name
                                ),
                            }
                        ),
                        404,
                    )
                # (group_id, mission_name) is the composite PK; updating an existing mission must not
                # re-insert it or the IntegrityError below would turn the whole request into a no-op
                existing = db.session.execute(
                    db.session.query(GroupMission).filter_by(
                        group_id=group.id, mission_name=mission.name
                    )
                ).first()
                if not existing:
                    group_mission = GroupMission()
                    group_mission.group_id = group.id
                    group_mission.mission_name = mission.name
                    db.session.add(group_mission)
        else:
            # Default to the __ANON__ group
            existing = db.session.execute(
                db.session.query(GroupMission).filter_by(group_id=1, mission_name=mission.name)
            ).first()
            if not existing:
                group_mission = GroupMission()
                group_mission.group_id = 1
                group_mission.mission_name = mission.name
                db.session.add(group_mission)

        db.session.commit()

        if new_mission:
            mission_role = MissionRole()
            mission_role.clientUid = mission.creator_uid
            mission_role.username = eud.user.username if eud.user else "anonymous"
            mission_role.createTime = datetime.datetime.now(datetime.timezone.utc)
            mission_role.role_type = MissionRole.MISSION_OWNER
            mission_role.mission_name = mission_name
            db.session.add(mission_role)

            mission_change = MissionChange()
            mission_change.isFederatedChange = False
            mission_change.change_type = MissionChange.CREATE_MISSION
            mission_change.mission_name = mission_name
            mission_change.timestamp = mission.create_time
            mission_change.creator_uid = mission.creator_uid
            mission_change.server_time = mission.create_time

            db.session.add(mission_change)
            db.session.commit()

            event = generate_new_mission_cot(mission)

            rabbit_credentials = pika.PlainCredentials(
                app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
            )
            rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
            rabbit_connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
            )
            channel = rabbit_connection.channel()

            groups = db.session.execute(
                db.session.query(GroupUser).filter_by(user_id=user.id, enabled=True)
            ).scalars()
            for group in groups:
                channel.basic_publish(
                    exchange="groups",
                    routing_key=f"{group.group.name}.{group.direction}",
                    body=json.dumps(
                        {
                            "uid": app.config.get("RAVEN_NODE_ID"),
                            "cot": tostring(event).decode("utf-8"),
                        }
                    ),
                )

            channel.close()
            rabbit_connection.close()
    except sqlalchemy.exc.IntegrityError:
        # Mission exists, needs updating
        db.session.rollback()
        db.session.execute(
            update(Mission).where(Mission.name == mission_name).values(**mission.serialize())
        )
        db.session.commit()
        return jsonify(
            {
                "version": "3",
                "type": "Mission",
                "data": [mission.to_marti_json()],
                "nodeId": app.config.get("RAVEN_NODE_ID"),
            }
        )
    except BaseException as e:
        logger.error(f"Failed to add mission: {e}")
        logger.debug(traceback.format_exc())
        return (
            jsonify({"success": False, "error": gettext("Failed to add mission: %(e)s", e=str(e))}),
            500,
        )

    token = generate_token(mission, mission.creator_uid)
    mission_json = mission.to_marti_json()
    mission_json["token"] = token

    if new_mission:
        mission_json["ownerRole"] = MissionRole.OWNER_ROLE

    response = {
        "version": "3",
        "type": "Mission",
        "data": [mission_json],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }

    if new_mission:
        return jsonify(response), 201
    else:
        return jsonify(response), 200


@mission_marti_api.route("/Marti/api/missions/<mission_name>", methods=["GET"])
def get_mission(mission_name: str):
    """Used by the Data Sync plugin to get a feed's metadata"""
    if not mission_name:
        return jsonify({"success": False, "error": gettext("Invalid mission name")}), 400

    mission_name = bleach.clean(mission_name)

    try:
        mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
        if not mission:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "Mission %(mission_name)s not found", mission_name=mission_name
                        ),
                    }
                ),
                404,
            )

        return jsonify(
            {
                "version": "3",
                "type": "Mission",
                "data": [
                    mission[0].to_marti_json(logs=request.args.get("logs", "false").lower() == "true")
                ],
                "nodeId": app.config.get("RAVEN_NODE_ID"),
            }
        )
    except BaseException as e:
        logger.error(f"Failed to get mission: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 400


@mission_marti_api.route("/Marti/api/missions/<mission_name>", methods=["DELETE"])
@mission_marti_api.route("/Marti/api/missions", methods=["DELETE"])
def delete_mission(mission_name: str = None):
    """Used by the Data Sync plugin to delete a feed"""

    # ATAK sends a creatorUid param, but we ignore it in favor of the UID in the signed JWT token that ATAK also sends.
    creator_uid = request.args.get("creatorUid")
    # TAK Server also takes DELETE /Marti/api/missions?guid=<guid>
    mission_name = _resolve_mission_name(mission_name, request.args.get("guid"))
    if not mission_name:
        return _mission_not_found(request.args.get("guid"))

    # Nothing to authorise against if the mission is already gone (e.g. deleted from the web UI).
    # Answer 404 like TAK Server so the client drops its stale local copy instead of retrying on a 401.
    if not db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first():
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Mission %(mission_name)s not found", mission_name=mission_name
                    ),
                }
            ),
            404,
        )

    if "iTAK" not in request.user_agent.string:
        token = verify_token()
        if not token or token["MISSION_NAME"] != mission_name:
            return jsonify({"success": False, "error": gettext("Missing or invalid token")}), 401
        eud_uid = token["sub"]
    else:
        # cert_is_valid will either be True or flask.Response. If it's flask.Response it indicates an error
        role = verify_itak_certificate(mission_name)
        if isinstance(role, flask.Response):
            return role
        eud_uid = role.clientUid

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if mission:
        mission = mission[0]

        can_delete = False

        # Check if the UID in the token has the MISSION_OWNER role for this mission. If not, it can't delete the mission
        for role in mission.roles:
            if role.clientUid == eud_uid and role.role_type == MissionRole.MISSION_OWNER:
                can_delete = True
                break

        if not can_delete:
            return (
                jsonify(
                    {"success": False, "error": gettext("Only mission owners can delete missions")}
                ),
                403,
            )

        # Serialise the mission and its delete notification while the row still exists -- TAK Server
        # answers a delete with the deleted mission in the usual envelope
        response = {
            "version": "3",
            "type": "Mission",
            "data": [mission.to_marti_json()],
            "nodeId": app.config.get("RAVEN_NODE_ID"),
        }
        delete_cot = tostring(generate_mission_delete_cot(mission)).decode("utf-8")
        db.session.delete(mission)
        db.session.commit()

        rabbit_credentials = pika.PlainCredentials(
            app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
        )
        rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
        rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
        )
        channel = rabbit_connection.channel()
        channel.basic_publish(
            exchange="missions",
            routing_key="missions",
            body=json.dumps(
                {
                    "uid": app.config.get("RAVEN_NODE_ID"),
                    "cot": delete_cot,
                }
            ),
        )
        channel.close()
        rabbit_connection.close()

        return jsonify(response)
    else:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Mission %(mission_name)s not found", mission_name=mission_name
                    ),
                }
            ),
            404,
        )


@mission_marti_api.route("/Marti/api/missions/<mission_name>/password", methods=["PUT", "DELETE"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/password", methods=["PUT", "DELETE"])
def set_password(mission_name: str = None, mission_guid: str = None):
    """Used by the Data Sync plugin to add a password to a feed"""
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    if "iTAK" not in request.user_agent.string:
        token = verify_token()
        if not token or token["MISSION_NAME"] != mission_name:
            return jsonify({"success": False, "error": gettext("Missing or invalid token")}), 401
        eud_uid = token["sub"]
    else:
        # cert_is_valid will either be True or flask.Response. If it's flask.Response it indicates an error
        role = verify_itak_certificate(mission_name)
        if isinstance(role, flask.Response):
            return role
        eud_uid = role.clientUid

    if request.method == "PUT" and "password" not in request.args:
        return jsonify({"success": False, "error": gettext("Please provide the password")}), 400

    role = db.session.execute(
        db.session.query(MissionRole).filter_by(mission_name=mission_name, clientUid=eud_uid)
    ).first()
    if not role or role[0].role_type != MissionRole.MISSION_OWNER:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "You do not have permission to change this mission's password"
                    ),
                }
            ),
            403,
        )

    creator_uid = request.args.get("creatorUid")

    if request.method == "PUT":
        password = hash_password(request.args.get("password"))
        db.session.execute(
            update(Mission)
            .where(Mission.name == mission_name)
            .values(password=password, password_protected=True)
        )
    elif request.method == "DELETE":
        db.session.execute(
            update(Mission)
            .where(Mission.name == mission_name)
            .values(password=None, password_protected=False)
        )
    db.session.commit()

    return jsonify({"success": True})


def _build_invitation(
    mission: Mission,
    invitation_type: str,
    invitee: str,
    role: str | None,
    creator_uid: str | None,
) -> MissionInvitation | tuple:
    """
    Validate the invitee and return an un-persisted MissionInvitation, or a (jsonify, status)
    error tuple. Shared by the PUT .../invite/<type>/<invitee> route, the POST .../invite JSON
    route and the web UI so every path validates the same way (the FK columns on
    mission_invitations would otherwise raise IntegrityError -> 500 for unknown invitees).
    """
    if not invitation_type or not invitee:
        return (
            jsonify({"success": False, "error": gettext("Invalid invitation type")}),
            400,
        )
    invitation_type = invitation_type.lower()

    invitation = MissionInvitation()
    invitation.mission_name = mission.name
    invitation.creator_uid = creator_uid or mission.creator_uid
    # TAK Server lets the inviter choose the granted role (?role=MISSION_OWNER|MISSION_SUBSCRIBER|MISSION_READONLY_SUBSCRIBER)
    invitation.role = (
        MissionRole.normalize_role_type(role)
        or mission.default_role
        or MissionRole.MISSION_SUBSCRIBER
    )

    if invitation_type == "clientuid":
        eud = db.session.execute(db.session.query(EUD).filter_by(uid=invitee)).first()
        if not eud:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("No EUD found with UID %(invitee)s", invitee=invitee),
                    }
                ),
                404,
            )
        invitation.client_uid = invitee
        invitation.type = InvitationTypeEnum.clientUid

    elif invitation_type == "callsign":
        eud = db.session.execute(db.session.query(EUD).filter_by(callsign=invitee)).first()
        if not eud:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("No EUD found with callsign %(invitee)s", invitee=invitee),
                    }
                ),
                404,
            )
        invitation.callsign = invitee
        invitation.type = InvitationTypeEnum.callsign

    elif invitation_type == "username":
        user = db.session.execute(db.session.query(User).filter_by(username=invitee)).first()
        if not user:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "No user found with username %(invitee)s", invitee=invitee
                        ),
                    }
                ),
                404,
            )
        invitation.username = invitee
        invitation.type = InvitationTypeEnum.userName

    elif invitation_type == "group":
        group = db.session.execute(db.session.query(Group).filter_by(name=invitee)).first()
        if not group:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("No group found: %(invitee)s", invitee=invitee),
                    }
                ),
                404,
            )
        invitation.group_name = invitee
        invitation.type = InvitationTypeEnum.group

    elif invitation_type == "team":
        team = db.session.execute(db.session.query(Team).filter_by(name=invitee)).first()
        if not team:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("Team not found: %(invitee)s", invitee=invitee),
                    }
                ),
                404,
            )
        invitation.team_name = invitee
        invitation.type = InvitationTypeEnum.team

    else:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Invalid invitation type: %(invitation_type)s",
                        invitation_type=invitation_type,
                    ),
                }
            ),
            400,
        )

    return invitation


def _publish_invitation(channel, mission: Mission, invitee: str, role: str) -> None:
    """Send the t-x-m-i invitation CoT to the invitee over the dms exchange on an open channel."""
    event = generate_invitation_cot(mission, invitee, role=role)
    logger.debug(f"Sending invitation to mission {mission.name} to {invitee}")
    channel.basic_publish(
        exchange="dms",
        routing_key=invitee,
        body=json.dumps(
            {"uid": app.config.get("RAVEN_NODE_ID"), "cot": tostring(event).decode("utf-8")}
        ),
    )


def _create_invitation(
    mission: Mission,
    invitation_type: str,
    invitee: str,
    role: str | None = None,
    creator_uid: str | None = None,
    channel=None,
) -> tuple | None:
    """
    Validate the invitee, persist the MissionInvitation and publish the invitation CoT.
    Returns None on success or a (jsonify, status) error tuple. Callers must already have
    checked that the requester may invite to this mission (mission token / iTAK cert / web login).
    Pass an open pika channel to publish on it (bulk invites); otherwise a connection is opened
    and closed here.
    """
    invitation = _build_invitation(mission, invitation_type, invitee, role, creator_uid)
    if not isinstance(invitation, MissionInvitation):
        return invitation

    try:
        db.session.add(invitation)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError as e:
        db.session.rollback()
        logger.error(f"Failed to save invitation for {invitee} to mission {mission.name}: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Invalid invitee: %(invitee)s", invitee=invitee),
                }
            ),
            400,
        )

    if channel is not None:
        _publish_invitation(channel, mission, invitee, invitation.role)
        return None

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
    )
    try:
        own_channel = rabbit_connection.channel()
        _publish_invitation(own_channel, mission, invitee, invitation.role)
        own_channel.close()
    finally:
        rabbit_connection.close()

    return None


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/invite/<invitation_type>/<invitee>", methods=["PUT"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/invite/<invitation_type>/<invitee>", methods=["PUT"]
)
def invite(
    mission_name: str = None,
    invitation_type: str = None,
    invitee: str = None,
    mission_guid: str = None,
):
    """PUT .../invite/<type>/<invitee>: TAK Server's single-invitee form. The web UI does not call
    this route function; it uses _create_invitation() directly because it has no mission token."""
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return _mission_not_found(mission_name)
    mission = mission[0]

    error = _create_invitation(
        mission,
        invitation_type,
        invitee,
        role=request.args.get("role"),
        creator_uid=request.args.get("creatorUid"),
    )
    if error is not None:
        return error

    return "", 200


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/invite/<invitation_type>/<invitee>", methods=["DELETE"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/invite/<invitation_type>/<invitee>", methods=["DELETE"]
)
def delete_invitation(
    invitation_type: str, invitee: str, mission_name: str = None, mission_guid: str = None
):
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Mission %(mission_name)s not found", mission_name=mission_name
                    ),
                }
            ),
            404,
        )

    mission = mission[0]

    if invitation_type.lower() not in ["clientuid", "callsign", "username", "group", "team"]:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Invalid invitation type: %(invitation_type)s",
                        invitation_type=invitation_type,
                    ),
                }
            ),
            400,
        )

    # Doing it like this because I can select an EUD, user, group, or team and automatically
    # get all of their invitations
    query = db.session.query(MissionInvitation).where(
        MissionInvitation.mission_name == mission_name
    )
    if invitation_type.lower() == "clientuid":
        query = query.where(MissionInvitation.client_uid == invitee)
    elif invitation_type.lower() == "callsign":
        query = query.where(MissionInvitation.callsign == invitee)
    elif invitation_type.lower() == "username":
        query = query.where(MissionInvitation.username == invitee)
    elif invitation_type.lower() == "group":
        query = query.where(MissionInvitation.group_name == invitee)
    elif invitation_type.lower() == "team":
        query = query.where(MissionInvitation.team_name == invitee)

    invitations = db.session.execute(query).scalars()
    for invitation in invitations:
        db.session.delete(invitation)
    db.session.commit()

    return jsonify({"success": True})


@mission_marti_api.route("/Marti/api/missions/<mission_name>/invite", methods=["POST"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/invite", methods=["POST"])
def invite_json(mission_name: str = None, mission_guid: str = None):
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    creator_uid = request.args.get("creatorUid")
    invitees = request.get_json(silent=True)
    if not isinstance(invitees, list):
        return (
            jsonify({"success": False, "error": gettext("Expected a JSON list of invitations")}),
            400,
        )

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Mission not found: %(mission_name)s", mission_name=mission_name
                    ),
                }
            ),
            404,
        )
    mission = mission[0]

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
    )
    try:
        channel = rabbit_connection.channel()

        for invitee in invitees:
            if not isinstance(invitee, dict) or not invitee.get("type") or not invitee.get("invitee"):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": gettext("invitation found without type or invitee attribute"),
                        }
                    ),
                    400,
                )
            # TAK Server treats a missing role as "grant the mission's default role"
            role = invitee.get("role")
            if isinstance(role, dict):
                role = role.get("type")

            # Shared with PUT .../invite/<type>/<invitee>: validates that the EUD/user/group/team
            # exists (the FK columns would otherwise raise IntegrityError -> 500), commits and
            # publishes the invitation CoT on our channel.
            error = _create_invitation(
                mission,
                invitee["type"],
                invitee["invitee"],
                role=role,
                creator_uid=creator_uid,
                channel=channel,
            )
            if error is not None:
                return error

        channel.close()
    finally:
        rabbit_connection.close()

    return jsonify({"success": True})


@mission_marti_api.route("/Marti/api/missions/<mission_name>/subscriptions/roles")
def mission_roles(mission_name: str):
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    response = {
        "version": "3",
        "type": "MissionSubscription",
        "data": [],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }
    roles = db.session.execute(db.session.query(MissionRole).filter_by(mission_name=mission_name))
    for role in roles:
        response["data"].append(role[0].to_json())

    return jsonify(response)


@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/subscriptions/roles")
def mission_roles_by_guid(mission_guid: str):
    permission_granted = check_permission(mission_guid=mission_guid)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    response = {
        "version": "3",
        "type": "MissionSubscription",
        "data": [],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }
    mission = db.session.execute(db.session.query(Mission).filter_by(guid=mission_guid)).first()
    if mission:
        mission = mission[0]
        roles = db.session.execute(
            db.session.query(MissionRole).filter_by(mission_name=mission.name)
        )
        for role in roles:
            response["data"].append(role[0].to_json())

    return jsonify(response)


@mission_marti_api.route("/Marti/api/missions/<mission_name>/role", methods=["PUT"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/role", methods=["PUT"])
def change_eud_role(mission_name: str = None, mission_guid: str = None):
    """Used by Data Sync to change EUD mission roles or kick an EUD off of a mission"""
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    if "iTAK" not in request.user_agent.string:
        token = verify_token()
        if not token or token["MISSION_NAME"] != mission_name:
            return jsonify({"success": False, "error": gettext("Missing or invalid token")}), 401
        eud_uid = token["sub"]
    else:
        # cert_is_valid will either be True or flask.Response. If it's flask.Response it indicates an error
        role = verify_itak_certificate(mission_name)
        if isinstance(role, flask.Response):
            return role
        eud_uid = role.clientUid

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "No such mission found: %(mission_name)s", mission_name=mission_name
                    ),
                }
            ),
            404,
        )
    mission = mission[0]

    role = db.session.execute(
        db.session.query(MissionRole).filter_by(
            clientUid=eud_uid, mission_name=mission_name, role_type=MissionRole.MISSION_OWNER
        )
    ).first()
    if not role:
        return (
            jsonify(
                {"success": False, "error": gettext("Only mission owners can change EUD roles")}
            ),
            403,
        )

    client_uid = request.args.get("clientUid")
    if not client_uid:
        return jsonify({"success": False, "error": gettext("Please provide a UID")}), 400

    eud = db.session.execute(db.session.query(EUD).filter_by(uid=client_uid)).first()
    if not eud:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Invalid UID: %(client_uid)s", client_uid=client_uid),
                }
            ),
            400,
        )
    eud = eud[0]

    new_role = MissionRole.normalize_role_type(request.args.get("role"))
    if new_role and new_role not in [
        MissionRole.MISSION_OWNER,
        MissionRole.MISSION_SUBSCRIBER,
        MissionRole.MISSION_READ_ONLY,
    ]:
        return (
            jsonify(
                {"success": False, "error": gettext("Invalid role: %(new_role)s", new_role=new_role)}
            ),
            400,
        )
    elif new_role:
        r = db.session.execute(
            db.session.query(MissionRole).filter_by(clientUid=client_uid, mission_name=mission_name)
        ).all()
        for role in r:
            db.session.delete(role[0])
        db.session.commit()

        role = MissionRole()
        role.clientUid = client_uid
        try:
            role.username = eud.user.username
        except BaseException as e:
            role.username = "anonymous"
        role.createTime = datetime.datetime.now(datetime.timezone.utc)
        role.role_type = new_role
        role.mission_name = mission_name

        db.session.add(role)
        db.session.commit()

        # TAK Server announces a role change as t-x-m-r (createMissionRoleChangeMessage), not a fresh invite
        event = generate_invitation_cot(mission, role.clientUid, "t-x-m-r", role=new_role)
        body = {"uid": app.config.get("RAVEN_NODE_ID"), "cot": tostring(event).decode("utf-8")}

        rabbit_credentials = pika.PlainCredentials(
            app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
        )
        rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
        rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
        )
        channel = rabbit_connection.channel()
        channel.basic_publish(exchange="dms", routing_key=client_uid, body=json.dumps(body))
        channel.close()
        rabbit_connection.close()

    # No new role provided, kick the EUD off the mission
    else:
        old_role = db.session.execute(
            db.session.query(MissionRole).filter_by(mission_name=mission_name, clientUid=client_uid)
        ).first()
        if old_role:
            db.session.delete(old_role[0])
            db.session.commit()

        event = generate_invitation_cot(mission, client_uid, "t-x-m-r", delete=True)
        body = {"uid": app.config.get("RAVEN_NODE_ID"), "cot": tostring(event).decode("utf-8")}

        rabbit_credentials = pika.PlainCredentials(
            app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
        )
        rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
        rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
        )
        channel = rabbit_connection.channel()
        channel.basic_publish(exchange="dms", routing_key=client_uid, body=json.dumps(body))
        channel.close()
        rabbit_connection.close()

    return "", 200


@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/role")
@mission_marti_api.route("/Marti/api/missions/<mission_name>/role", methods=["GET"])
def get_role_by_guid(mission_guid: str = None, mission_name: str = None):
    permission_granted = check_permission(mission_name, mission_guid)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    if mission_guid:
        mission = db.session.execute(db.session.query(Mission).filter_by(guid=mission_guid)).first()
    else:
        mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return _mission_not_found(mission_guid or mission_name)
    mission = mission[0]

    token = verify_token()
    client_uid = request.args.get("clientUid") or (token.get("sub") if token else None)
    role_json = None
    for role in mission.roles:
        if client_uid and role.clientUid == client_uid:
            role_json = role.to_json()["role"]
            break
    if role_json is None:
        role_json = {
            MissionRole.MISSION_OWNER: MissionRole.OWNER_ROLE,
            MissionRole.MISSION_READ_ONLY: MissionRole.READ_ONLY_ROLE,
        }.get(mission.default_role, MissionRole.SUBSCRIBER_ROLE)

    response = {
        "version": "3",
        "type": "com.bbn.marti.sync.model.MissionRole",
        "data": role_json,
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }

    return jsonify(response)


@mission_marti_api.route("/Marti/api/missions/<mission_name>/subscriptions")
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/subscriptions")
def get_subscriptions(mission_name: str = None, mission_guid: str = None):
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    subscriptions = db.session.execute(
        db.session.query(MissionRole).filter_by(mission_name=mission_name)
    ).all()
    response = {
        "version": "3",
        "type": "MissionSubscription",
        "data": [],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }

    for subscription in subscriptions:
        response["data"].append(subscription[0].clientUid)

    return jsonify(response)


@mission_marti_api.route("/Marti/api/missions/<mission_name>/keywords", methods=["PUT"])
def put_mission_keywords(mission_name):
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Cannot find mission %(mission_name)s", mission_name=mission_name
                    ),
                }
            ),
            404,
        )
    mission = mission[0]

    new_keywords = request.json
    current_keywords = mission.keywords or []
    for keyword in new_keywords:
        if keyword not in current_keywords:
            current_keywords.append(keyword)

    db.session.execute(
        update(Mission).where(Mission.name == mission_name).values(keywords=current_keywords)
    )
    db.session.commit()

    return "", 200


@mission_marti_api.route("/Marti/api/missions/<mission_name>/subscription", methods=["PUT"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/subscription", methods=["PUT"])
def mission_subscribe(mission_name: str = None, mission_guid: str = None):
    """Used by the Data Sync plugin to subscribe to a feed"""
    cert = verify_client_cert()
    if not cert:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Missions are only supported on SSL connections"),
                }
            ),
            400,
        )
    username = cert.get_subject().commonName
    user = app.security.datastore.find_user(username=username)
    if not user:
        logger.warning(f"/Marti/api/missions/.../subscription: no account matches certificate CN {username!r}")
        return jsonify({"success": False, "error": gettext("Unknown user certificate")}), 403

    if mission_name:
        mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    elif mission_guid:
        mission = db.session.execute(db.session.query(Mission).filter_by(guid=mission_guid)).first()
    else:
        mission = None

    if not mission and mission_name:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Cannot find mission %(mission_name)s", mission_name=mission_name
                    ),
                }
            ),
            404,
        )
    if not mission and mission_guid:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Cannot find mission %(mission_guid)s", mission_guid=mission_guid
                    ),
                }
            ),
            404,
        )

    mission = mission[0]
    # TAKX (re)subscribes by GUID, so mission_name is None on that route -- everything below
    # (visibility check, token check, role lookup, RabbitMQ binding, invitation cleanup) keys on the name.
    mission_name = mission.name
    # Missions with no group assignment at all are public/ungrouped and visible to everyone
    group_filters = [GroupMission.mission_name.is_(None)]
    groups = db.session.execute(db.session.query(GroupUser).filter_by(user_id=user.id)).scalars()
    for group in groups:
        group_filters.append(GroupMission.group_id == group.group_id)

    visible_mission = db.session.execute(
        db.session.query(Mission)
        .filter_by(name=mission_name)
        .outerjoin(GroupMission)
        .where(or_(*group_filters))
    ).first()

    if not visible_mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "%(username)s and mission %(mission_name)s are not in the same group",
                        mission_name=mission_name,
                    ),
                }
            ),
            403,
        )

    response = {
        "version": "3",
        "type": "com.bbn.marti.sync.model.MissionSubscription",
        "data": {},
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }

    # And EUD will send a token if it has previously subscribed to the mission
    token = verify_token() if _mission_token_header() else False
    if token and (token.get("MISSION_NAME") != mission_name or not token.get("sub")):
        # A token for some other mission (or a stale one): TAK Server falls back to the default
        # role in that case rather than refusing the subscription, so do the same and let the
        # ?uid= path below identify the EUD
        logger.warning(f"Ignoring mission token that doesn't match mission {mission_name}")
        token = False
    if token:
        eud = db.session.execute(db.session.query(EUD).filter_by(uid=token["sub"])).first()
        if not eud:
            return jsonify({"success": False, "error": gettext("Invalid token")}), 400
        eud = eud[0]
        uid = token["sub"]
        role = db.session.execute(
            db.session.query(MissionRole).filter_by(mission_name=mission_name, clientUid=uid)
        ).first()

        # If this request has a token but no role in the DB, this EUD was invited and this is its first time subscribing
        if not role:
            role = MissionRole()
            role.clientUid = token["sub"]
            role.username = eud.user.username if eud.user else "anonymous"
            role.createTime = datetime.datetime.now(datetime.timezone.utc)
            role.role_type = mission.default_role
            role.mission_name = token["MISSION_NAME"]

            db.session.add(role)
            db.session.commit()
        else:
            role = role[0]

        response["data"] = {
            "token": _mission_token_header(),
            "clientUid": token["sub"],
            "username": role.username,
            "createTime": iso8601_string_from_datetime(role.createTime),
            "role": role.to_json()["role"],
        }

    # If no token is sent, this is a new subscription request
    else:
        if "uid" not in request.args:
            return jsonify({"success": False, "error": gettext("Missing UID")}), 400

        uid = bleach.clean(request.args.get("uid"))
        eud = db.session.execute(db.session.query(EUD).filter_by(uid=uid)).first()
        if not eud:
            return (
                jsonify({"success": False, "error": gettext("Invalid UID: %(uid)s", uid=uid)}),
                400,
            )
        eud = eud[0]

        if mission.password_protected:
            if not verify_password(request.args.get("password", ""), mission.password):
                return jsonify({"success": False, "error": gettext("Invalid password")}), 401

        role = db.session.execute(
            db.session.query(MissionRole).filter_by(mission_name=mission_name, clientUid=uid)
        ).first()
        if not role:
            role = MissionRole()
            role.clientUid = uid
            role.username = eud.user.username if eud.user else "anonymous"
            role.createTime = datetime.datetime.now(datetime.timezone.utc)
            role.role_type = mission.default_role
            role.mission_name = mission.name

            db.session.add(role)
            db.session.commit()
        else:
            role = role[0]

        token = generate_token(mission, uid)

        response["data"] = {
            "token": token,
            "clientUid": uid,
            "mission": mission.to_marti_json(logs=True),
            "username": role.username,
            "createTime": iso8601_string_from_datetime(role.createTime),
            "role": role.to_json()["role"],
        }

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
    )
    channel = rabbit_connection.channel()
    channel.queue_declare(queue=uid)
    channel.queue_bind(queue=uid, exchange="missions", routing_key=f"missions.{mission_name}")
    channel.close()
    rabbit_connection.close()

    # Delete any invitations to this mission for this EUD -- TAK Server clears both the clientUid and the
    # callsign invitation on subscribe
    invitation_filters = [MissionInvitation.client_uid == uid]
    if eud.callsign:
        invitation_filters.append(MissionInvitation.callsign == eud.callsign)
    invitations = db.session.execute(
        db.session.query(MissionInvitation)
        .filter_by(mission_name=mission_name)
        .where(or_(*invitation_filters))
    ).all()
    for invitation in invitations:
        db.session.delete(invitation[0])
    db.session.commit()

    return jsonify(response), 201


@mission_marti_api.route("/Marti/api/missions/<mission_name>/subscription", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/subscription", methods=["GET"])
def get_subscription(mission_name: str = None, mission_guid: str = None):
    """TAK Server's 'am I subscribed?' lookup: GET .../subscription?uid=<clientUid> -> the subscription or 404"""
    # The response contains a freshly minted mission token for `uid`, so the caller must prove it is
    # that EUD: a valid client cert whose user owns the EUD (or is an admin), or a mission token for it.
    cert = verify_client_cert()
    if not cert:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Missions are only supported on SSL connections"),
                }
            ),
            400,
        )
    username = cert.get_subject().commonName
    user = app.security.datastore.find_user(username=username)
    if not user:
        logger.warning(f"GET /Marti/api/missions/.../subscription: no account matches certificate CN {username!r}")
        return jsonify({"success": False, "error": gettext("Unknown user certificate")}), 403

    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return _mission_not_found(mission_name)
    mission = mission[0]

    uid = request.args.get("uid")
    role = None
    if uid:
        uid = bleach.clean(uid)

        token = verify_token()
        token_matches = bool(
            token
            and token.get("sub") == uid
            and (token.get("MISSION_NAME") == mission.name or token.get("MISSION_GUID") == mission.guid)
        )
        owns_eud = (
            db.session.execute(db.session.query(EUD).filter_by(uid=uid, user_id=user.id)).first()
            is not None
        )
        if not (token_matches or owns_eud or user.has_role("administrator")):
            logger.warning(f"{username} asked for the mission subscription/token of EUD {uid} it does not own")
            return jsonify({"success": False, "error": gettext("Access Denied")}), 403

        role = db.session.execute(
            db.session.query(MissionRole).filter_by(mission_name=mission_name, clientUid=uid)
        ).first()
    if not role:
        return jsonify({"success": False, "error": gettext("Mission subscription not found")}), 404
    role = role[0]

    return jsonify(
        {
            "version": "3",
            "type": "com.bbn.marti.sync.model.MissionSubscription",
            "data": {
                "token": generate_token(mission, uid),
                "clientUid": uid,
                "username": role.username,
                "createTime": iso8601_string_from_datetime(role.createTime),
                "role": role.to_json()["role"],
            },
            "nodeId": app.config.get("RAVEN_NODE_ID"),
        }
    )


@mission_marti_api.route("/Marti/api/missions/<mission_name>/subscription", methods=["DELETE"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/subscription", methods=["DELETE"])
def mission_unsubscribe(mission_name: str = None, mission_guid: str = None):
    """Used by the Data Sync plugin to unsubscribe to a feed"""
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    if "iTAK" not in request.user_agent.string:
        token = verify_token()
        if not token or token["MISSION_NAME"] != mission_name:
            return jsonify({"success": False, "error": gettext("Missing or invalid token")}), 401
        eud_uid = token["sub"]
    else:
        # cert_is_valid will either be True or flask.Response. If it's flask.Response it indicates an error
        role = verify_itak_certificate(mission_name)
        if isinstance(role, flask.Response):
            return role
        eud_uid = role.clientUid

    # if "uid" not in request.args:
    #    return jsonify({'success': False, 'error': 'Missing UID'}), 400

    # uid = bleach.clean(request.args.get("uid"))
    role = db.session.execute(
        db.session.query(MissionRole).filter_by(clientUid=eud_uid, mission_name=mission_name)
    ).first()

    if role:
        db.session.delete(role[0])
        db.session.commit()

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
    )
    try:
        channel = rabbit_connection.channel()
        try:
            channel.queue_unbind(
                queue=eud_uid, exchange="missions", routing_key=f"missions.{mission_name}"
            )
            channel.close()
        except pika.exceptions.AMQPError as e:
            # The EUD's queue is gone (it disconnected and the queue auto-deleted), so there is
            # nothing left to unbind. The role row is already deleted, so this is still a success.
            logger.warning(
                f"Could not unbind queue {eud_uid} from missions.{mission_name} while unsubscribing: {e}"
            )
    finally:
        rabbit_connection.close()

    return "", 200


@mission_marti_api.route("/Marti/api/missions/<mission_name>/changes", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/changes", methods=["GET"])
def mission_changes(mission_name: str = None, mission_guid: str = None):
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        return _mission_not_found(mission_guid)
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    squashed = request.args.get("squashed")
    if squashed:
        squashed = bleach.clean(squashed)

    response = {
        "version": "3",
        "type": "MissionChange",
        "data": [],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }

    changes = db.session.execute(
        db.session.query(MissionChange).filter_by(mission_name=mission_name)
    ).all()
    for change in changes:
        response["data"].append(change[0].to_json())

    return jsonify(response)


@mission_marti_api.route("/Marti/api/missions/logs/entries", methods=["POST"])
def create_log_entry():
    permission_granted = check_permission(request.json["missionNames"][0])
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    mission = db.session.execute(
        db.session.query(Mission).filter_by(name=request.json["missionNames"][0])
    ).first()
    if not mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Mission not found: %(mission_name)s",
                        mission_name=request.json["missionNames"][0],
                    ),
                }
            ),
            404,
        )

    log_entry = MissionLogEntry()
    log_entry.content = request.json.get("content")
    log_entry.creator_uid = request.json.get("creatorUid")
    log_entry.entry_uid = str(uuid.uuid4())
    log_entry.mission_name = request.json.get("missionNames")[0]
    log_entry.server_time = datetime.datetime.now(datetime.timezone.utc)
    log_entry.dtg = datetime_from_iso8601_string(request.json.get("dtg"))
    log_entry.created = datetime.datetime.now(datetime.timezone.utc)
    log_entry.keywords = request.json.get("keywords")

    db.session.add(log_entry)
    db.session.commit()

    response = {
        "version": "3",
        "type": "com.bbn.marti.sync.model.LogEntry",
        "nodeId": app.config.get("RAVEN_NODE_ID"),
        "data": [log_entry.to_json()],
    }

    change_cot = log_entry.generate_cot()
    body = json.dumps({"uid": log_entry.creator_uid, "cot": tostring(change_cot).decode("utf-8")})

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
    )
    channel = rabbit_connection.channel()
    channel.basic_publish("missions", routing_key=f"missions.{log_entry.mission_name}", body=body)
    channel.close()
    rabbit_connection.close()

    return jsonify(response), 201


@mission_marti_api.route("/Marti/api/missions/<mission_name>/log", methods=["GET"])
def mission_log(mission_name):
    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Mission %(mission_name)s not found", mission_name=mission_name
                    ),
                }
            ),
            404,
        )
    mission = mission[0]

    response = {
        "version": "3",
        "type": "com.bbn.marti.sync.model.LogEntry",
        "data": [],
        "nodeId": app.config.get("RAVEN_NODE_ID"),
    }

    for log in mission.mission_logs:
        response["data"].append(log.to_json())

    return jsonify(response)


@mission_marti_api.route("/Marti/sync/upload", methods=["POST"])
def upload_content():
    """
    Used by the Data Sync plugin when adding files to a mission
    Also used to upload files and data packages

    :return: flask.Response
    """

    cert = verify_client_cert()
    if not cert:
        return jsonify({"success": False, "error": gettext("Missing or invalid certificate")}), 400

    username = cert.get_subject().commonName

    file_name = bleach.clean(request.args.get("name")) if "name" in request.args else None
    keywords = request.args.getlist("keywords")

    if "creatorUid" in request.args:
        creator_uid = request.args.get("creatorUid")
    # Older versions of iTAK use CreatorUid instead of creatorUid
    elif "CreatorUid" in request.args:
        creator_uid = request.args.get("CreatorUid")
    else:
        creator_uid = None

    if not file_name:
        return jsonify({"success": False, "error": gettext("File name cannot be blank")}), 400

    # When uploading data packages, iTAK doesn't include an extension. If the user agent is iTAK and
    # the content type is zip, assume that iTAK is uploading a data package
    if (
        "iTAK" in request.user_agent.string
        and request.content_type == "application/x-zip-compressed"
    ):
        file_hash = save_data_package_file(
            request.data, secure_filename(file_name) + ".zip", username, creator_uid
        )

        response = {
            "UID": str(uuid.uuid4()),
            "SubmissionDateTime": iso8601_string_from_datetime(),
            "MIMEType": "application/x-zip-compressed",
            "SubmissionUser": username,
            "PrimaryKey": 0,
            "Hash": file_hash,
            "CreatorUid": creator_uid,
            "Name": file_name,
        }

        return jsonify(response)

    # Never trust the client-supplied name on disk or in the DB: ?name=../../x would otherwise be
    # written outside the missions folder. data_package_marti_api reads files back by
    # content.filename, so the DB and on-disk names must both be the sanitised one.
    safe_name = secure_filename(file_name)
    filename, extension = os.path.splitext(safe_name)
    if not filename:
        safe_name = f"{uuid.uuid4().hex}{extension}"
        filename, _ = os.path.splitext(safe_name)

    if extension.replace(".", "").lower() not in app.config.get("ALLOWED_EXTENSIONS"):
        logger.error(f"{extension} is not an allowed file extension")
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "%(extension)s is not an allowed file extension", extension=extension
                    ),
                }
            ),
            400,
        )

    file = request.data
    sha256 = hashlib.sha256()
    sha256.update(file)

    content = db.session.execute(
        db.session.query(MissionContent).filter_by(hash=sha256.hexdigest())
    ).first()
    if not content:
        content = MissionContent()
        content.mime_type = request.content_type
        content.filename = safe_name
        content.submission_time = datetime.datetime.now(datetime.timezone.utc)
        content.submitter = username or "anonymous"
        content.uid = str(uuid.uuid4())
        content.creator_uid = creator_uid
        content.size = request.content_length
        content.expiration = -1
        content.keywords = keywords if keywords else []
        content.hash = sha256.hexdigest()
        content_pk = db.session.execute(insert(MissionContent).values(**content.serialize()))
        content_pk = content_pk.inserted_primary_key[0]
        db.session.commit()

    else:
        content = content[0]
        content_pk = content.id

        # For some reason iTAK changes file names to a timestamp with the format YYYYMMDD-HHMMSS so the file name in the DB
        # needs to be updated
        if safe_name != content.filename:
            content.filename = safe_name
            db.session.add(content)
            db.session.commit()

    # Save the content even if it exists in the database in case it was deleted from disk
    os.makedirs(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "missions"), exist_ok=True)
    with open(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "missions", safe_name), "wb") as f:
        f.write(file)
        f.flush()

    response = {
        "UID": content.uid,
        "SubmissionDateTime": iso8601_string_from_datetime(content.submission_time),
        "MIMEType": content.mime_type,
        "SubmissionUser": content.submitter,
        "PrimaryKey": content_pk,
        "Hash": content.hash,
        "CreatorUid": creator_uid,
        "Name": file_name,
    }

    return jsonify(response)


@mission_marti_api.route("/Marti/api/sync/metadata/<content_hash>/keywords", methods=["PUT"])
def add_content_keywords(content_hash: str):
    # Not validating if the EUD is subscribed to the mission since we're not given the mission name or GUID
    # Instead, assume this EUD isn't malicious since we require a valid cert in order to get here

    keywords = request.json
    content = db.session.execute(
        db.session.query(MissionContent).filter_by(hash=content_hash)
    ).first()
    if not content:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "No content found with hash: %(content_hash)s", content_hash=content_hash
                    ),
                }
            ),
            400,
        )
    content: MissionContent = content[0]
    current_keywords = content.keywords if content.keywords else []

    for keyword in keywords:
        if keyword not in current_keywords:
            current_keywords.append(keyword)
    db.session.execute(
        update(MissionContent)
        .where(MissionContent.hash == content_hash)
        .values(keywords=current_keywords)
    )
    db.session.commit()

    return "", 200


@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/contents", methods=["PUT"])
@mission_marti_api.route("/Marti/api/missions/<mission_name>/contents", methods=["PUT"])
def mission_contents(mission_name: str | None = None, mission_guid: str | None = None):
    """Associates content/files with a mission"""
    # Resolve the GUID form to a name *before* the permission check: check_permission(None)
    # grants access, and every row written below is keyed on mission_name.
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        logger.error(f"No such mission: {mission_guid}")
        return _mission_not_found(mission_guid)

    permission_granted = check_permission(mission_name)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    body = request.json

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        logger.error(f"No such mission: {mission_name}")
        return _mission_not_found(mission_name)

    mission = mission[0]

    if "hashes" in body:
        for content_hash in body["hashes"]:
            content = db.session.execute(
                db.session.query(MissionContent).filter_by(hash=content_hash)
            ).first()
            if not content:
                logger.error(f"No such file with hash {content_hash}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": gettext(
                                "No such file with hash %(content_hash)s", content_hash=content_hash
                            ),
                        }
                    ),
                    404,
                )

            content: MissionContent = content[0]

            mission_content_mission = db.session.execute(
                db.session.query(MissionContentMission).filter_by(
                    mission_content_id=content.id, mission_name=mission_name
                )
            ).first()
            if not mission_content_mission:
                mission_content_mission = MissionContentMission()
                mission_content_mission.mission_name = mission_name
                mission_content_mission.mission_content_id = content.id

                db.session.add(mission_content_mission)

            mission_change = db.session.execute(
                db.session.query(MissionChange).filter_by(
                    content_uid=content.uid, mission_name=mission_name
                )
            ).first()
            if not mission_change:
                mission_change = MissionChange()
                mission_change.isFederatedChange = False
                mission_change.change_type = MissionChange.ADD_CONTENT
                mission_change.content_uid = content.uid
                mission_change.mission_name = mission_name
                mission_change.timestamp = datetime.datetime.now(datetime.timezone.utc)
                mission_change.creator_uid = content.creator_uid
                mission_change.server_time = datetime.datetime.now(datetime.timezone.utc)

                db.session.add(mission_change)

                event = generate_mission_change_cot(
                    mission_name, mission, mission_change, content=content
                )

                # Must not rebind `body` here -- the "uids" branch below still reads request.json from it.
                _publish_mission_change_cot(mission_name, event, mission_change.creator_uid)

    if "uids" in body:
        creator_uid = request.args.get("creatorUid")
        for uid in body["uids"]:
            # iTAK sucks. It sends a CoT and makes a PUT to this endpoint rather than including a <dest mission="mission_name">
            # tag in the CoT. This endpoint finishes before the CoT can be parsed and inserted into the database. In that case
            # we insert a row in the mission_uids table with the CoT data missing, and the parse_point method in
            # cot_controller will fill it in
            cot = db.session.execute(db.session.query(CoT).filter_by(uid=uid)).first()
            cot_type = latitude = longitude = iconset_path = color = callsign = None
            if cot:
                cot = cot[0]
                cot_type = cot.type
                # CoT rows written by _store_mission_package_cot have no Point relationship
                if cot.point is not None:
                    latitude = cot.point.latitude
                    longitude = cot.point.longitude

                event = BeautifulSoup(cot.xml, "xml")
                usericon = event.find("usericon")
                color_tag = event.find("color")
                contact = event.find("contact")

                if usericon and "iconsetpath" in usericon.attrs:
                    iconset_path = usericon.attrs["iconsetpath"]
                elif usericon and "iconsetPath" in usericon.attrs:
                    iconset_path = usericon.attrs["iconsetPath"]

                if color_tag and "argb" in color_tag.attrs:
                    color = color_tag.attrs["argb"]
                elif color_tag and "value" in color_tag.attrs:
                    color = color_tag.attrs["value"]

                if contact and "callsign" in contact.attrs:
                    callsign = contact.attrs["callsign"]

            _mission_uid, _mission_change, change_cot = upsert_mission_uid_and_change(
                mission_name,
                mission,
                uid,
                creator_uid,
                datetime.datetime.now(datetime.timezone.utc),
                cot_type=cot_type,
                callsign=callsign,
                iconset_path=iconset_path,
                color=color,
                latitude=latitude,
                longitude=longitude,
            )
            _publish_mission_change_cot(mission_name, change_cot, creator_uid)

    db.session.commit()

    return jsonify(
        {
            "version": "3",
            "type": "Mission",
            "data": [mission.to_marti_json()],
            "nodeId": app.config.get("RAVEN_NODE_ID"),
        }
    )


@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/contents", methods=["DELETE"])
@mission_marti_api.route("/Marti/api/missions/<mission_name>/contents", methods=["DELETE"])
def delete_content(mission_name: str | None = None, mission_guid: str | None = None):
    # Resolve the GUID form first so the token's MISSION_NAME is compared against the real name
    # (otherwise every /guid/<guid>/contents caller 401s) and the rows below get a non-NULL name.
    mission_name = _resolve_mission_name(mission_name, mission_guid)
    if not mission_name:
        logger.error(f"Mission not found: {mission_guid}")
        return _mission_not_found(mission_guid)

    if "iTAK" not in request.user_agent.string:
        token = verify_token()
        if not token or token["MISSION_NAME"] != mission_name:
            return jsonify({"success": False, "error": gettext("Missing or invalid token")}), 401
        eud_uid = token["sub"]
    else:
        # cert_is_valid will either be True or flask.Response. If it's flask.Response it indicates an error
        role = verify_itak_certificate(mission_name, mission_guid)
        if isinstance(role, flask.Response):
            return role
        eud_uid = role.clientUid

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        logger.error(f"Mission not found: {mission_name}")
        return _mission_not_found(mission_name)
    mission = mission[0]

    mission_change = MissionChange()
    mission_change.isFederatedChange = False
    mission_change.change_type = MissionChange.REMOVE_CONTENT
    mission_change.mission_name = mission_name
    mission_change.timestamp = datetime.datetime.now(datetime.timezone.utc)
    mission_change.creator_uid = request.args.get("creatorUid")
    mission_change.server_time = datetime.datetime.now(datetime.timezone.utc)

    mission_uid = None
    cot_event = None
    if "uid" in request.args:
        mission_uid = db.session.execute(
            db.session.query(MissionUID).filter_by(uid=request.args.get("uid"))
        ).first()
        if not mission_uid:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext("UID %(uid)s not found", uid=request.args.get("uid")),
                    }
                ),
                404,
            )
        else:
            mission_uid = mission_uid[0]
            mission_uid.mission_name = None
            mission_change.mission_uid = mission_uid.uid
        cot_event = db.session.execute(
            db.session.query(CoT).filter_by(uid=request.args.get("uid"))
        ).first()
        if cot_event:
            cot_event = cot_event[0]
            cot_event.mission_name = None
            db.session.add(cot_event)
            cot_event = BeautifulSoup(cot_event.xml, "xml").find("event")

    # Files will be kept in the DB so the mission log is correct and on disk in case it gets added back to a mission
    content = None
    if "hash" in request.args:
        content = db.session.execute(
            db.session.query(MissionContent).filter_by(hash=request.args.get("hash"))
        ).first()
        if not content:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "No content found with hash %(hash)s", hash=request.args.get("hash")
                        ),
                    }
                ),
                404,
            )
        content = content[0]

        mission_change.content_uid = content.uid

        try:
            mission_content_mission = db.session.execute(
                db.session.query(MissionContentMission).filter_by(
                    mission_name=mission_name, mission_content_id=content.id
                )
            ).first()
            if mission_content_mission:
                db.session.delete(mission_content_mission[0])
                db.session.commit()
        except BaseException as e:
            logger.error(f"Failed to delete content with hash {request.args.get('hash')}: {e}")
            logger.debug(traceback.format_exc())
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "Failed to delete content with hash %(hash)s: %(e)s",
                            hash=request.args.get("hash"),
                            e=str(e),
                        ),
                    }
                ),
                500,
            )

    event = generate_mission_change_cot(
        mission_name,
        mission,
        mission_change,
        content=content,
        mission_uid=mission_uid,
        cot_event=cot_event,
    )
    body = {"uid": app.config.get("RAVEN_NODE_ID"), "cot": tostring(event).decode("utf-8")}

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
    )
    channel = rabbit_connection.channel()
    channel.basic_publish(
        exchange="missions", routing_key=f"missions.{mission_name}", body=json.dumps(body)
    )
    channel.close()
    rabbit_connection.close()

    db.session.add(mission_change)
    db.session.commit()

    return jsonify(
        {
            "version": "3",
            "type": "Mission",
            "data": [mission.to_marti_json()],
            "nodeId": app.config.get("RAVEN_NODE_ID"),
        }
    )


def _publish_mission_change_cot(mission_name: str, event: Element, creator_uid: str | None = None):
    # The body "uid" is the *sender* as far as EudHandler.on_message is concerned: it drops any
    # message whose uid matches the receiving EUD (echo suppression). Stamping the creator here
    # meant the uploading device never got its own change notification, so use the server node id
    # like the CoT-parser path and delete_content do. `creator_uid` is kept only so existing call
    # sites keep working.
    del creator_uid
    rabbit_body = json.dumps(
        {"uid": app.config.get("RAVEN_NODE_ID"), "cot": tostring(event).decode("utf-8")}
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
    channel.basic_publish("missions", routing_key=f"missions.{mission_name}", body=rabbit_body)
    channel.close()
    rabbit_connection.close()


def _store_mission_package_cot(
    mission_name: str, item_uid: str, event: BeautifulSoup, creator_uid: str | None
) -> None:
    """Persist a marker that arrived inside a mission package as a CoT row.

    The change notification we push only carries the marker's UID; every
    client (TAKX itself after a restart included) then fetches the marker
    with GET /Marti/api/cot/xml/<uid>, and /Marti/api/missions/<name>/cot
    is built from the same table. Markers dropped in TAKX only ever reach
    us inside the package zip -- never over the streaming connection, which
    is what normally fills the cot table -- so without this row both
    lookups 404 and the marker never renders on any other client.
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    def _attr_time(name: str) -> datetime.datetime:
        try:
            return datetime_from_iso8601_string(event.attrs[name])
        except (KeyError, ValueError, TypeError):
            return now

    sender_uid = None
    if creator_uid and db.session.execute(db.session.query(EUD).filter_by(uid=creator_uid)).first():
        sender_uid = creator_uid

    cot = db.session.execute(db.session.query(CoT).filter_by(uid=item_uid)).first()
    cot = cot[0] if cot else CoT()
    cot.uid = item_uid
    cot.how = event.attrs.get("how")
    cot.type = event.attrs.get("type")
    cot.sender_uid = sender_uid
    cot.timestamp = _attr_time("time")
    cot.start = _attr_time("start")
    cot.stale = _attr_time("stale")
    cot.xml = str(event)
    cot.mission_name = mission_name
    db.session.add(cot)
    db.session.commit()


def _parse_mission_package_map_items(file: bytes) -> tuple[str | None, list]:
    """A Data Sync "mission package" upload is a Data Package zip: a
    MANIFEST/manifest.xml declaring the package's own UID plus one or more
    <Content zipEntry="..."> entries, each usually a map-items/.../<uid>.cot
    file (the actual marker/point being synced). Returns (manifest_uid,
    [(item_uid, BeautifulSoup event), ...]) -- manifest_uid is None and the
    list is empty for anything that isn't a manifest zip (e.g. a plain
    photo/file upload), so callers can fall back to opaque-content handling.
    """
    manifest_uid = None
    map_items = []

    try:
        package = zipfile.ZipFile(io.BytesIO(file))
    except zipfile.BadZipFile:
        return None, []

    with package:
        manifest_entry = next(
            (name for name in package.namelist() if name.endswith("manifest.xml")), None
        )
        if not manifest_entry:
            return None, []

        manifest = BeautifulSoup(package.read(manifest_entry), "xml")
        for param in manifest.find_all("Parameter"):
            if param.attrs.get("name") == "uid":
                manifest_uid = param.attrs.get("value")
                break

        for content_tag in manifest.find_all("Content"):
            if content_tag.attrs.get("ignore") == "true":
                continue
            zip_entry = content_tag.attrs.get("zipEntry")
            if not zip_entry or not zip_entry.lower().endswith(".cot"):
                continue
            try:
                cot_bytes = package.read(zip_entry)
            except KeyError:
                continue
            event = BeautifulSoup(cot_bytes, "xml").find("event")
            if event and event.attrs.get("uid"):
                map_items.append((event.attrs["uid"], event))

    return manifest_uid, map_items


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/contents/missionpackage", methods=["PUT"]
)
def add_content(mission_name):
    """Used by the Data Sync plugin to upload and attach a mission package
    to a mission in one call -- unlike /Marti/sync/upload + PUT .../contents,
    which do that in two steps by content hash.

    A "mission package" here is a Data Package zip (MANIFEST/manifest.xml +
    map-items/.../<uid>.cot) -- this is how TAKX (and other TAK clients)
    sync a dropped marker to Data Sync, not a raw CoT with <dest mission>.
    The client checks the server's response against the item UID(s) it
    declared in its own manifest, so acknowledging the upload with a made-up
    content UID (the previous version of this fix) always reads back as
    "incompatible" even though the upload itself succeeds -- it has to
    actually parse the manifest and report a change for the UID(s) in it.

    This previously also required an Authorization bearer token and never
    saved anything even when that check passed -- every real client we've
    seen hit this (TAKX included) authenticates with its mTLS client cert
    like every other Marti API call, never sends that token, and always
    got a 401 here.
    """
    cert = verify_client_cert()
    if not cert:
        return jsonify({"success": False, "error": gettext("Missing or invalid certificate")}), 400

    username = cert.get_subject().commonName
    creator_uid = request.args.get("creatorUid") or request.args.get("clientUid")

    mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).first()
    if not mission:
        return (
            jsonify(
                {"success": False, "error": gettext("No such mission: %(mission_name)s", mission_name=mission_name)}
            ),
            404,
        )
    mission = mission[0]

    file = request.data
    sha256 = hashlib.sha256()
    sha256.update(file)
    file_hash = sha256.hexdigest()

    manifest_uid, map_items = _parse_mission_package_map_items(file)

    content = db.session.execute(
        db.session.query(MissionContent).filter_by(hash=file_hash)
    ).first()
    if not content:
        content = MissionContent()
        content.mime_type = request.content_type or "application/x-zip-compressed"
        content.filename = f"{mission_name}_{uuid.uuid4().hex}.zip"
        content.submission_time = datetime.datetime.now(datetime.timezone.utc)
        content.submitter = username or "anonymous"
        # MissionContent.uid is unique; a re-exported package keeps its manifest uid but has new
        # bytes (new hash), so reusing the manifest uid would raise IntegrityError on insert.
        content_uid = manifest_uid
        if content_uid and db.session.execute(
            db.session.query(MissionContent).filter_by(uid=content_uid)
        ).first():
            content_uid = None
        content.uid = content_uid or str(uuid.uuid4())
        content.creator_uid = creator_uid
        content.size = request.content_length
        content.expiration = -1
        content.keywords = []
        content.hash = file_hash
        db.session.execute(insert(MissionContent).values(**content.serialize()))
        db.session.commit()
        content = db.session.execute(
            db.session.query(MissionContent).filter_by(hash=file_hash)
        ).first()[0]
    else:
        content = content[0]

    os.makedirs(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "missions"), exist_ok=True)
    with open(
        os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "missions", content.filename), "wb"
    ) as f:
        f.write(file)
        f.flush()

    mission_content_mission = db.session.execute(
        db.session.query(MissionContentMission).filter_by(
            mission_content_id=content.id, mission_name=mission_name
        )
    ).first()
    if not mission_content_mission:
        mission_content_mission = MissionContentMission()
        mission_content_mission.mission_name = mission_name
        mission_content_mission.mission_content_id = content.id
        db.session.add(mission_content_mission)
        db.session.commit()

    changes_json = []

    if map_items:
        # Register each map-item the manifest declared as a mission UID
        # (marker), the same way mission_contents()'s "uids" branch does
        # for a CoT already sitting in our own database -- just sourced
        # from the zip's embedded CoT XML instead of a DB row.
        for item_uid, event in map_items:
            point = event.find("point")
            usericon = event.find("usericon")
            iconset_path = None
            if usericon and "iconsetpath" in usericon.attrs:
                iconset_path = usericon.attrs["iconsetpath"]
            elif usericon and "iconsetPath" in usericon.attrs:
                iconset_path = usericon.attrs["iconsetPath"]

            color_tag = event.find("color")
            color = None
            if color_tag and "argb" in color_tag.attrs:
                color = color_tag.attrs["argb"]
            elif color_tag and "value" in color_tag.attrs:
                color = color_tag.attrs["value"]

            contact = event.find("contact")

            mission_uid, mission_change, change_cot = upsert_mission_uid_and_change(
                mission_name,
                mission,
                item_uid,
                creator_uid,
                datetime.datetime.now(datetime.timezone.utc),
                cot_type=event.attrs.get("type"),
                callsign=contact.attrs["callsign"] if contact and "callsign" in contact.attrs else None,
                iconset_path=iconset_path,
                color=color,
                latitude=float(point.attrs["lat"]) if point else None,
                longitude=float(point.attrs["lon"]) if point else None,
            )

            # This came in as a mission package upload (map item wrapped in a
            # zip), not a bare UID association -- link the uploaded content
            # too so the response's contentResource (hash, size, filename)
            # reflects what was actually received, not just the marker's own
            # details.
            if mission_change.content_uid != content.uid:
                mission_change.content_uid = content.uid
                db.session.commit()

            _store_mission_package_cot(mission_name, item_uid, event, creator_uid)

            _publish_mission_change_cot(mission_name, change_cot, creator_uid)
            changes_json.append(mission_change.to_json())
    else:
        # No manifest/map-items found (e.g. a plain file, not a marker
        # package) -- fall back to treating the whole upload as one opaque
        # content item, keyed by its own hash-derived content UID.
        mission_change = db.session.execute(
            db.session.query(MissionChange).filter_by(content_uid=content.uid, mission_name=mission_name)
        ).first()
        if not mission_change:
            mission_change = MissionChange()
            mission_change.isFederatedChange = False
            mission_change.change_type = MissionChange.ADD_CONTENT
            mission_change.content_uid = content.uid
            mission_change.mission_name = mission_name
            mission_change.timestamp = datetime.datetime.now(datetime.timezone.utc)
            mission_change.creator_uid = creator_uid
            mission_change.server_time = datetime.datetime.now(datetime.timezone.utc)
            db.session.add(mission_change)
            db.session.commit()

            change_cot = generate_mission_change_cot(mission_name, mission, mission_change, content=content)
            _publish_mission_change_cot(mission_name, change_cot, creator_uid)
        else:
            mission_change = mission_change[0]

        changes_json.append(mission_change.to_json())

    db.session.commit()

    # TAKX's Feign client deserializes this endpoint's "data" as a list of
    # MissionChange, not Mission -- returning to_marti_json() here made it
    # try to read Mission's array-typed "externalData" as MissionChange's
    # object-typed one and blow up with a Jackson MismatchedInputException.
    #
    # goatak's server (a real, independently-built TAK-compatible
    # implementation) registers this exact route with no explicit status
    # code, i.e. a plain 200 -- unlike mission_subscribe()/create_log_entry(),
    # this one isn't a 201. 201 was this endpoint's prior guess, not
    # confirmed-working precedent like those two.
    #
    # goatak's handler also answers with *every* change on the mission, not
    # just the one this upload just created (mirrors mission_changes()'s own
    # GET .../changes, which already does the same full-list query) -- a
    # client cross-checking its upload against "the changes" plural, not a
    # single echoed record, would read a one-item list as incomplete.
    all_changes = db.session.execute(
        db.session.query(MissionChange).filter_by(mission_name=mission_name)
    ).all()

    return jsonify(
        {
            "version": "3",
            "type": "MissionChange",
            "data": [change[0].to_json() for change in all_changes],
            "nodeId": app.config.get("RAVEN_NODE_ID"),
        }
    )


@mission_marti_api.route("/Marti/api/missions/<mission_name>/cot")
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/cot")
def get_mission_cots(mission_name: str = None, mission_guid: str = None):
    """
    Used by the Data Sync plugin to get all CoTs associated with a feed. Returns the CoTs encapsulated by an
    <events> tag
    """

    permission_granted = check_permission(mission_name, mission_guid)
    if isinstance(permission_granted, flask.Response):
        return permission_granted

    if mission_name:
        cots = db.session.execute(db.session.query(CoT).filter_by(mission_name=mission_name)).all()
    elif mission_guid:
        mission = db.session.execute(db.session.query(Mission).filter_by(guid=mission_guid)).first()
        if mission:
            mission_name = mission[0].name
            cots = db.session.execute(
                db.session.query(CoT).filter_by(mission_name=mission_name)
            ).all()
        else:
            cots = []
    else:
        cots = []

    events = Element("events")

    for cot in cots:
        events.append(fromstring(cot[0].xml))

    return Response(
        response=tostring(events).decode("utf-8"), status=200, mimetype="application/xml"
    )


@mission_marti_api.route("/Marti/api/missions/<mission_name>/layers")
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/layers")
def get_mission_layers(mission_name: str = None, mission_guid: str = None):
    # Map layers aren't implemented; answer the way TAK Server does for a mission without any
    # (an empty MissionLayer envelope) -- the empty body we used to return is a JSON parse error
    return jsonify(
        {
            "version": "3",
            "type": "MissionLayer",
            "data": [],
            "nodeId": app.config.get("RAVEN_NODE_ID"),
        }
    )
