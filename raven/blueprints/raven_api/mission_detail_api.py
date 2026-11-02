"""Web UI side of a mission's detail page: everything about one mission in one call, and the
archive / KML downloads. Registers on data_sync_api (imported at the bottom of mission_api.py)."""

from xml.etree.ElementTree import fromstring

import bleach
from flask import jsonify, request
from flask_babel import gettext
from flask_security import auth_required, current_user

from raven.audit import record_audit_event
from raven.blueprints.marti_api.mission_data_marti_api import (
    archive_response,
    kml_response,
    layer_tree,
)
from raven.blueprints.raven_api.mission_api import data_sync_api
from raven.extensions import db, logger
from raven.functions import iso8601_string_from_datetime
from raven.mission_export import latest_mission_cots
from raven.models.Group import Group
from raven.models.GroupUser import GroupUser
from raven.models.Mission import Mission
from raven.models.MissionChange import MissionChange
from raven.models.MissionLogEntry import MissionLogEntry


def _can_view(mission: Mission) -> bool:
    """Same rule as the mission list (GET /api/missions): administrators see every mission, other
    users the missions of the groups they're in, or every mission if they're in none"""
    if current_user.has_role("administrator"):
        return True
    group_ids = {
        row.group_id
        for row in db.session.execute(
            db.session.query(GroupUser).filter_by(user_id=current_user.id, direction=Group.IN)
        ).scalars()
    }
    if not group_ids:
        return True
    return any(group.id in group_ids for group in mission.groups)


def _get_mission():
    """The ?name= mission if the current user may see it, else an error response"""
    name = request.args.get("name")
    if not name:
        return jsonify({"success": False, "error": gettext("Please specify a mission name")}), 400
    name = bleach.clean(name)
    mission = db.session.execute(db.session.query(Mission).filter_by(name=name)).scalar()
    # Missions the user can't see answer like missing ones, so names don't leak
    if not mission or not _can_view(mission):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Mission %(mission_name)s not found", mission_name=name),
                }
            ),
            404,
        )
    return mission


def _cot_item(cot) -> dict:
    item = {
        "uid": cot.uid,
        "type": cot.type,
        "callsign": None,
        "latitude": None,
        "longitude": None,
        "timestamp": iso8601_string_from_datetime(cot.timestamp) if cot.timestamp else None,
        "stale": iso8601_string_from_datetime(cot.stale) if cot.stale else None,
        "sender_uid": cot.sender_uid,
    }
    try:
        event = fromstring(cot.xml)
        point = event.find("point")
        if point is not None:
            item["latitude"] = float(point.get("lat"))
            item["longitude"] = float(point.get("lon"))
        contact = event.find("detail/contact")
        if contact is not None:
            item["callsign"] = contact.get("callsign")
    except Exception as e:
        logger.debug(f"Couldn't parse CoT {cot.uid} for the mission detail page: {e}")
    return item


@data_sync_api.route("/api/missions/detail")
@auth_required()
def mission_detail():
    mission = _get_mission()
    if not isinstance(mission, Mission):
        return mission

    info = mission.to_json()
    # The page shows these in their own sections
    for key in ("missionChanges", "contents", "uids", "externalData", "feeds"):
        info.pop(key, None)

    changes = db.session.execute(
        db.session.query(MissionChange)
        .filter_by(mission_name=mission.name)
        .order_by(MissionChange.server_time.desc(), MissionChange.id.desc())
    ).scalars()
    logs = db.session.execute(
        db.session.query(MissionLogEntry)
        .filter_by(mission_name=mission.name)
        .order_by(MissionLogEntry.dtg.desc())
    ).scalars()

    cots = latest_mission_cots(mission.name)
    cot_uids = {cot.uid for cot in cots}
    items = [_cot_item(cot) for cot in cots]
    # Items we only know from the mission's uid list (their CoT hasn't been stored)
    for mission_uid in mission.uids:
        if mission_uid.uid not in cot_uids:
            items.append(
                {
                    "uid": mission_uid.uid,
                    "type": mission_uid.cot_type,
                    "callsign": mission_uid.callsign,
                    "latitude": mission_uid.latitude,
                    "longitude": mission_uid.longitude,
                    "timestamp": (
                        iso8601_string_from_datetime(mission_uid.timestamp)
                        if mission_uid.timestamp
                        else None
                    ),
                    "stale": None,
                    "sender_uid": mission_uid.creator_uid,
                }
            )

    return jsonify(
        {
            "mission": info,
            "subscribers": [role.to_json() for role in mission.roles],
            "contents": [content.to_json()["data"] for content in mission.contents],
            "items": items,
            "layers": layer_tree(mission),
            "external_data": [item.to_json() for item in mission.external_data_items],
            "feeds": [feed.to_json() for feed in mission.feed_items],
            "changes": [change.to_json() for change in changes],
            "logs": [log.to_json() for log in logs],
        }
    )


@data_sync_api.route("/api/missions/archive")
@auth_required()
def mission_archive():
    mission = _get_mission()
    if not isinstance(mission, Mission):
        return mission
    record_audit_event(
        "missions",
        "mission_archive_export",
        username=current_user.username,
        details=f"Downloaded the archive of mission {mission.name}",
    )
    return archive_response(mission)


@data_sync_api.route("/api/missions/kml")
@auth_required()
def mission_kml():
    mission = _get_mission()
    if not isinstance(mission, Mission):
        return mission
    record_audit_event(
        "missions",
        "mission_kml_export",
        username=current_user.username,
        details=f"Exported mission {mission.name} as KML",
    )
    return kml_response(mission)
