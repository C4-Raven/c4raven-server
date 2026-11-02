"""Data Sync mission archive/KML export, layers (folders), external data and feeds.

These register on mission_marti_api's blueprint (imported at the bottom of mission_marti_api.py) and
answer in TAK Server's envelope ({"version": "3", "type": ..., "data": ..., "nodeId": ...}).
"""

import datetime
import uuid
from xml.etree.ElementTree import Element, SubElement

import bleach
import flask
from flask import Response
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext

from raven.blueprints.marti_api.mission_marti_api import (
    _mission_not_found,
    _publish_mission_change_cot,
    _resolve_mission_name,
    check_permission,
    mission_marti_api,
    verify_itak_certificate,
    verify_token,
)
from raven.extensions import db, logger
from raven.functions import iso8601_string_from_datetime
from raven.mission_export import (
    archive_entries,
    archive_filename,
    build_kml,
    kml_filename,
    stream_archive,
)
from raven.models.Mission import Mission
from raven.models.MissionChange import MissionChange, generate_mission_change_cot
from raven.models.MissionExternalData import MissionExternalData
from raven.models.MissionFeed import MissionFeed
from raven.models.MissionLayer import MissionLayer
from raven.models.MissionRole import MissionRole
from raven.models.MissionUID import MissionUID

ROLE_PERMISSIONS = {
    MissionRole.MISSION_OWNER: MissionRole.OWNER_ROLE["permissions"],
    MissionRole.MISSION_SUBSCRIBER: MissionRole.SUBSCRIBER_ROLE["permissions"],
    MissionRole.MISSION_READ_ONLY: MissionRole.READ_ONLY_ROLE["permissions"],
}


def _envelope(data_type: str, data):
    return jsonify(
        {"version": "3", "type": data_type, "data": data, "nodeId": app.config.get("RAVEN_NODE_ID")}
    )


def _error(message: str, status: int):
    return flask.make_response(jsonify({"success": False, "error": message}), status)


def _load_mission(mission_name: str | None, mission_guid: str | None = None):
    """Resolves the name/GUID route forms to a Mission, or a 404 response"""
    name = _resolve_mission_name(mission_name and bleach.clean(mission_name), mission_guid)
    if not name:
        return flask.make_response(*_mission_not_found(mission_guid))
    mission = db.session.execute(db.session.query(Mission).filter_by(name=name)).scalar()
    if not mission:
        return flask.make_response(*_mission_not_found(name))
    return mission


def _read_access(mission_name, mission_guid):
    """Mission lookup + the same token / iTAK cert check as the other read routes"""
    mission = _load_mission(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission
    granted = check_permission(mission.name)
    if isinstance(granted, flask.Response):
        return granted
    return mission


def _write_access(mission_name, mission_guid, permission: str):
    """Mission lookup + caller identity + a check that the caller's mission role carries
    `permission`. Returns (mission, caller eud uid) or a flask.Response."""
    mission = _load_mission(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission

    if "iTAK" not in request.user_agent.string:
        token = verify_token()
        if not token or token.get("MISSION_NAME") != mission.name:
            return _error(gettext("Missing or invalid token"), 401)
        eud_uid = token.get("sub")
        role = db.session.execute(
            db.session.query(MissionRole).filter_by(clientUid=eud_uid, mission_name=mission.name)
        ).scalar()
    else:
        role = verify_itak_certificate(mission.name)
        if isinstance(role, flask.Response):
            return role
        eud_uid = role.clientUid

    # A token without a role row (unsubscribed, kicked, or the row was cleaned up) gets nothing:
    # falling back to the mission's default role let a removed subscriber keep writing
    if not role:
        logger.warning(f"{eud_uid} has no role on mission {mission.name}")
        return _error(gettext("You are not subscribed to this mission"), 403)
    role_type = role.role_type
    if permission not in ROLE_PERMISSIONS.get(role_type, MissionRole.READ_ONLY_ROLE["permissions"]):
        logger.warning(f"{eud_uid} ({role_type}) lacks {permission} on mission {mission.name}")
        return _error(
            gettext(
                "Your mission role does not have the %(permission)s permission",
                permission=permission,
            ),
            403,
        )

    return mission, eud_uid


def _record_change(
    mission: Mission,
    change_type: str,
    creator_uid: str | None,
    external_data: dict | None = None,
    mission_feed: dict | None = None,
    mission_layer: dict | None = None,
    cot_type: str = "t-x-m-c",
) -> MissionChange:
    """Adds a MissionChange row and tells the mission's subscribers about it. Layer changes go out
    as a t-x-m-c-m (metadata) notification instead of a MissionChange, since TAK clients have no
    change type for them and only need to know to refetch the mission."""
    now = datetime.datetime.now(datetime.timezone.utc)
    change = MissionChange()
    change.isFederatedChange = False
    change.change_type = change_type
    change.mission_name = mission.name
    change.timestamp = now
    change.server_time = now
    change.creator_uid = creator_uid
    change.external_data = external_data
    change.mission_feed = mission_feed
    change.mission_layer = mission_layer
    db.session.add(change)
    db.session.commit()

    if cot_type == "t-x-m-c":
        event = generate_mission_change_cot(mission.name, mission, change)
    else:
        event = _metadata_change_cot(mission, change, cot_type)

    try:
        _publish_mission_change_cot(mission.name, event)
    except Exception as e:
        # The change is already recorded; subscribers pick it up on their next GET .../changes
        logger.error(f"Failed to publish mission change for {mission.name}: {e}")

    return change


def _metadata_change_cot(mission: Mission, change: MissionChange, cot_type: str) -> Element:
    timestamp = change.timestamp
    event = Element(
        "event",
        {
            "version": "2.0",
            "uid": str(uuid.uuid4()),
            "type": cot_type,
            "how": "h-g-i-g-o",
            "start": iso8601_string_from_datetime(timestamp),
            "time": iso8601_string_from_datetime(timestamp),
            "stale": iso8601_string_from_datetime(timestamp + datetime.timedelta(minutes=2)),
            "access": "Undefined",
        },
    )
    SubElement(
        event, "point", {"ce": "9999999", "le": "9999999", "hae": "0.0", "lat": "0.0", "lon": "0.0"}
    )
    detail = SubElement(event, "detail")
    SubElement(
        detail,
        "mission",
        {
            "type": Mission.CHANGE,
            "tool": mission.tool or "public",
            "name": mission.name,
            "guid": str(mission.guid),
            "authorUid": str(change.creator_uid or ""),
        },
    )
    return event


def _arg(name: str, body: dict | None = None):
    """A parameter from the query string or, failing that, the JSON body"""
    value = request.args.get(name)
    if value is None and body:
        value = body.get(name)
    return value


def _json_body() -> dict:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


# --- Archive and KML ---------------------------------------------------------------------------


@mission_marti_api.route("/Marti/api/missions/<mission_name>/archive", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/archive", methods=["GET"])
def get_mission_archive(mission_name: str = None, mission_guid: str = None):
    """The mission as a mission package zip: MANIFEST/manifest.xml, its files and its map items"""
    mission = _read_access(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission
    return archive_response(mission)


def archive_response(mission: Mission) -> Response:
    manifest, entries = archive_entries(mission)
    return Response(
        stream_archive(manifest, entries),
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{archive_filename(mission)}"'},
    )


@mission_marti_api.route("/Marti/api/missions/<mission_name>/kml", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/kml", methods=["GET"])
def get_mission_kml(mission_name: str = None, mission_guid: str = None):
    mission = _read_access(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission
    return kml_response(mission)


def kml_response(mission: Mission) -> Response:
    return Response(
        build_kml(mission),
        mimetype="application/vnd.google-earth.kml+xml",
        headers={"Content-Disposition": f'attachment; filename="{kml_filename(mission)}"'},
    )


# --- Layers ------------------------------------------------------------------------------------


def _ordered(siblings: list[MissionLayer]) -> list[MissionLayer]:
    """Follows the `after` chain; anything off the chain (a dangling after) goes last, by name"""
    by_after = {}
    for layer in siblings:
        by_after.setdefault(layer.after, []).append(layer)
    ordered, seen = [], set()
    current = None
    while True:
        candidates = [layer for layer in by_after.get(current, []) if layer.uid not in seen]
        if not candidates:
            break
        layer = candidates[0]
        ordered.append(layer)
        seen.add(layer.uid)
        current = layer.uid
    leftovers = [layer for layer in siblings if layer.uid not in seen]
    ordered.extend(sorted(leftovers, key=lambda layer: layer.name or ""))
    return ordered


def _layer_json(layer: MissionLayer, by_parent: dict, items: dict, contents: dict) -> dict:
    children = [
        _layer_json(child, by_parent, items, contents)
        for child in _ordered(by_parent.get(layer.uid, []))
    ]
    uids = [items[uid].to_json() for uid in (layer.uids or []) if uid in items]
    files = [contents[h].to_json() for h in (layer.hashes or []) if h in contents]
    return layer.to_json(children=children, uids=uids, contents=files)


def layer_tree(mission: Mission, root_uid: str | None = None) -> list[dict]:
    """The mission's layers as nested MissionLayer JSON: the root layers, or just root_uid's subtree"""
    layers = list(mission.layers)
    by_parent = {}
    for layer in layers:
        by_parent.setdefault(layer.parent_uid, []).append(layer)
    items = {mission_uid.uid: mission_uid for mission_uid in mission.uids}
    contents = {content.hash: content for content in mission.contents}
    if root_uid:
        roots = [layer for layer in layers if layer.uid == root_uid]
    else:
        roots = _ordered(by_parent.get(None, []))
    return [_layer_json(layer, by_parent, items, contents) for layer in roots]


def _find_layer(mission: Mission, layer_uid: str) -> MissionLayer | None:
    return db.session.execute(
        db.session.query(MissionLayer).filter_by(uid=layer_uid, mission_name=mission.name)
    ).scalar()


def _unlink(layer: MissionLayer) -> None:
    """Takes a layer out of its siblings' order: whoever came after it now comes after its predecessor"""
    db.session.query(MissionLayer).filter_by(
        mission_name=layer.mission_name, parent_uid=layer.parent_uid, after=layer.uid
    ).update({"after": layer.after})


def _link(layer: MissionLayer, after: str | None) -> None:
    """Slots a layer into its (new) parent's order after `after` (None: first)"""
    db.session.query(MissionLayer).filter(
        MissionLayer.mission_name == layer.mission_name,
        (
            MissionLayer.parent_uid == layer.parent_uid
            if layer.parent_uid
            else MissionLayer.parent_uid.is_(None)
        ),
        MissionLayer.after == after if after else MissionLayer.after.is_(None),
        MissionLayer.uid != layer.uid,
    ).update({"after": layer.uid})
    layer.after = after


def _last_sibling(
    mission: Mission, parent_uid: str | None, exclude: str | None = None
) -> str | None:
    query = db.session.query(MissionLayer).filter_by(
        mission_name=mission.name, parent_uid=parent_uid
    )
    siblings = [layer for layer in query.all() if layer.uid != exclude]
    ordered = _ordered(siblings)
    return ordered[-1].uid if ordered else None


def _validate_placement(mission: Mission, layer_uid: str | None, parent_uid, after):
    """Returns an error response if parent/after don't name layers in this mission, or the move
    would put a layer inside itself"""
    if parent_uid:
        parent = _find_layer(mission, parent_uid)
        if not parent:
            return _error(gettext("No such parent layer: %(uid)s", uid=parent_uid), 404)
        ancestor = parent
        while ancestor is not None:
            if layer_uid and ancestor.uid == layer_uid:
                return _error(gettext("A layer can't be moved inside itself"), 400)
            ancestor = _find_layer(mission, ancestor.parent_uid) if ancestor.parent_uid else None
    if after:
        sibling = _find_layer(mission, after)
        if not sibling or sibling.parent_uid != (parent_uid or None) or sibling.uid == layer_uid:
            return _error(gettext("No such sibling layer: %(uid)s", uid=after), 400)
    return None


@mission_marti_api.route("/Marti/api/missions/<mission_name>/layers", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/layers", methods=["GET"])
def get_mission_layers(mission_name: str = None, mission_guid: str = None):
    mission = _read_access(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission
    return _envelope("MissionLayer", layer_tree(mission))


@mission_marti_api.route("/Marti/api/missions/<mission_name>/layers/<layer_uid>", methods=["GET"])
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/layers/<layer_uid>", methods=["GET"]
)
def get_mission_layer(layer_uid: str, mission_name: str = None, mission_guid: str = None):
    mission = _read_access(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission
    tree = layer_tree(mission, layer_uid)
    if not tree:
        return _error(gettext("No such layer: %(uid)s", uid=layer_uid), 404)
    return _envelope("MissionLayer", tree[0])


@mission_marti_api.route("/Marti/api/missions/<mission_name>/layers", methods=["PUT", "POST"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/layers", methods=["PUT", "POST"])
def create_mission_layer(mission_name: str = None, mission_guid: str = None):
    """TAK Server's createMissionLayer: ?creatorUid=&name=&type=&parentUid=&after= (a JSON body
    with the same keys works too). The new layer goes after `after`, or last when it's omitted."""
    access = _write_access(mission_name, mission_guid, MissionRole.MISSION_MANAGE_LAYERS)
    if isinstance(access, flask.Response):
        return access
    mission, eud_uid = access
    body = _json_body()

    name = (_arg("name", body) or "").strip()
    layer_type = (_arg("type", body) or "").strip().upper()
    parent_uid = _arg("parentUid", body) or None
    after = _arg("after", body) or None
    layer_uid = _arg("uid", body) or str(uuid.uuid4())

    if not name or len(name) > 255:
        return _error(gettext("Please provide a layer name of at most 255 characters"), 400)
    if layer_type not in MissionLayer.TYPES:
        return _error(
            gettext(
                "Invalid layer type %(type)s, must be one of %(types)s",
                type=layer_type,
                types=", ".join(MissionLayer.TYPES),
            ),
            400,
        )
    if db.session.get(MissionLayer, layer_uid):
        return _error(gettext("A layer with uid %(uid)s already exists", uid=layer_uid), 409)
    error = _validate_placement(mission, None, parent_uid, after)
    if error:
        return error

    layer = MissionLayer()
    layer.uid = layer_uid
    layer.mission_name = mission.name
    layer.name = name
    layer.type = layer_type
    layer.parent_uid = parent_uid
    layer.creator_uid = _arg("creatorUid", body) or eud_uid
    layer.create_time = datetime.datetime.now(datetime.timezone.utc)
    layer.uids = []
    layer.hashes = []
    if after is None:
        layer.after = _last_sibling(mission, parent_uid)
    else:
        _link(layer, after)
    db.session.add(layer)
    db.session.commit()

    layer_json = layer_tree(mission, layer.uid)[0]
    _record_change(
        mission,
        MissionChange.ADD_MISSION_LAYER,
        layer.creator_uid,
        mission_layer=layer.to_json(),
        cot_type="t-x-m-c-m",
    )
    return _envelope("MissionLayer", layer_json)


def _layer_update(mission_name, mission_guid, layer_uid):
    access = _write_access(mission_name, mission_guid, MissionRole.MISSION_MANAGE_LAYERS)
    if isinstance(access, flask.Response):
        return access
    mission, eud_uid = access
    layer = _find_layer(mission, layer_uid)
    if not layer:
        return _error(gettext("No such layer: %(uid)s", uid=layer_uid), 404)
    return mission, eud_uid, layer


def _finish_layer_update(mission: Mission, layer: MissionLayer, eud_uid: str | None):
    db.session.commit()
    _record_change(
        mission,
        MissionChange.UPDATE_MISSION_LAYER,
        request.args.get("creatorUid") or eud_uid,
        mission_layer=layer.to_json(),
        cot_type="t-x-m-c-m",
    )
    return _envelope("MissionLayer", layer_tree(mission, layer.uid)[0])


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/layers/<layer_uid>/name", methods=["PUT"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/layers/<layer_uid>/name", methods=["PUT"]
)
def rename_mission_layer(layer_uid: str, mission_name: str = None, mission_guid: str = None):
    found = _layer_update(mission_name, mission_guid, layer_uid)
    if isinstance(found, flask.Response):
        return found
    mission, eud_uid, layer = found
    name = (_arg("name", _json_body()) or "").strip()
    if not name or len(name) > 255:
        return _error(gettext("Please provide a layer name of at most 255 characters"), 400)
    layer.name = name
    return _finish_layer_update(mission, layer, eud_uid)


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/layers/<layer_uid>/position", methods=["PUT"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/layers/<layer_uid>/position", methods=["PUT"]
)
def move_mission_layer(layer_uid: str, mission_name: str = None, mission_guid: str = None):
    """Reorders a layer among its siblings: ?after=<sibling uid>, or no after to make it first"""
    found = _layer_update(mission_name, mission_guid, layer_uid)
    if isinstance(found, flask.Response):
        return found
    mission, eud_uid, layer = found
    after = _arg("after", _json_body()) or None
    error = _validate_placement(mission, layer.uid, layer.parent_uid, after)
    if error:
        return error
    _unlink(layer)
    db.session.flush()
    _link(layer, after)
    return _finish_layer_update(mission, layer, eud_uid)


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/layers/<layer_uids>/parent", methods=["PUT"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/layers/<layer_uids>/parent", methods=["PUT"]
)
def reparent_mission_layers(layer_uids: str, mission_name: str = None, mission_guid: str = None):
    """Moves one or more (comma separated) layers under ?parentUid= (none: the top level), placed
    after ?after= or at the end"""
    body = _json_body()
    parent_uid = _arg("parentUid", body) or None
    after = _arg("after", body) or None
    moved = None
    for layer_uid in [uid for uid in layer_uids.split(",") if uid]:
        found = _layer_update(mission_name, mission_guid, layer_uid)
        if isinstance(found, flask.Response):
            db.session.rollback()
            return found
        mission, eud_uid, layer = found
        error = _validate_placement(mission, layer.uid, parent_uid, after)
        if error:
            db.session.rollback()
            return error
        _unlink(layer)
        db.session.flush()
        layer.parent_uid = parent_uid
        if after is None:
            layer.after = _last_sibling(mission, parent_uid, exclude=layer.uid)
        else:
            _link(layer, after)
        db.session.flush()
        # The next one in the list goes after this one, keeping the order they were given in
        after = layer.uid
        moved = (mission, eud_uid, layer)

    if not moved:
        return _error(gettext("Please provide at least one layer uid"), 400)
    mission, eud_uid, layer = moved
    return _finish_layer_update(mission, layer, eud_uid)


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/layers/<layer_uid>/items", methods=["PUT", "DELETE"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/layers/<layer_uid>/items", methods=["PUT", "DELETE"]
)
def mission_layer_items(layer_uid: str, mission_name: str = None, mission_guid: str = None):
    """Files mission items into a layer (PUT {"uids": [...], "hashes": [...]}) or takes them out
    (DELETE ?uid=...&hash=..., repeatable, or the same JSON body). UID/ITEM layers hold map items,
    CONTENTS layers hold files. Not part of TAK Server's API: it's how the web UI and scripts fill
    the folders."""
    found = _layer_update(mission_name, mission_guid, layer_uid)
    if isinstance(found, flask.Response):
        return found
    mission, eud_uid, layer = found
    body = _json_body()
    uids = list(body.get("uids") or []) + request.args.getlist("uid")
    hashes = list(body.get("hashes") or []) + request.args.getlist("hash")

    if uids and layer.type not in (MissionLayer.UID, MissionLayer.ITEM):
        return _error(gettext("Only UID and ITEM layers hold map items"), 400)
    if hashes and layer.type != MissionLayer.CONTENTS:
        return _error(gettext("Only CONTENTS layers hold files"), 400)

    current_uids = list(layer.uids or [])
    current_hashes = list(layer.hashes or [])
    if request.method == "PUT":
        for uid in uids:
            if not db.session.execute(
                db.session.query(MissionUID).filter_by(uid=uid, mission_name=mission.name)
            ).first():
                return _error(gettext("UID %(uid)s not found", uid=uid), 404)
            if uid not in current_uids:
                current_uids.append(uid)
        mission_hashes = {content.hash for content in mission.contents}
        for content_hash in hashes:
            if content_hash not in mission_hashes:
                return _error(
                    gettext("No content found with hash %(hash)s", hash=content_hash), 404
                )
            if content_hash not in current_hashes:
                current_hashes.append(content_hash)
    else:
        current_uids = [uid for uid in current_uids if uid not in uids]
        current_hashes = [h for h in current_hashes if h not in hashes]

    # Reassign (not mutate) so SQLAlchemy sees the JSON columns change
    layer.uids = current_uids
    layer.hashes = current_hashes
    return _finish_layer_update(mission, layer, eud_uid)


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/layers/<layer_uid>", methods=["DELETE"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/layers/<layer_uid>", methods=["DELETE"]
)
def delete_mission_layer(layer_uid: str, mission_name: str = None, mission_guid: str = None):
    """Deletes a layer and everything under it (the items themselves stay in the mission)"""
    found = _layer_update(mission_name, mission_guid, layer_uid)
    if isinstance(found, flask.Response):
        return found
    mission, eud_uid, layer = found

    snapshot = layer.to_json()
    response = layer_tree(mission, layer.uid)[0]

    def subtree(uid):
        children = (
            db.session.query(MissionLayer)
            .filter_by(mission_name=mission.name, parent_uid=uid)
            .all()
        )
        for child in children:
            yield from subtree(child.uid)
            yield child

    _unlink(layer)
    for child in list(subtree(layer.uid)):
        db.session.delete(child)
    db.session.delete(layer)
    db.session.commit()

    _record_change(
        mission,
        MissionChange.REMOVE_MISSION_LAYER,
        request.args.get("creatorUid") or eud_uid,
        mission_layer=snapshot,
        cot_type="t-x-m-c-m",
    )
    return _envelope("MissionLayer", response)


# --- External data -----------------------------------------------------------------------------

EXTERNAL_DATA_FIELDS = {
    "name": "name",
    "tool": "tool",
    "urlData": "url_data",
    "urlView": "url_view",
    "notes": "notes",
}


@mission_marti_api.route("/Marti/api/missions/<mission_name>/externaldata", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/externaldata", methods=["GET"])
def get_external_data(mission_name: str = None, mission_guid: str = None):
    mission = _read_access(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission
    return _envelope(
        "ExternalMissionData", [item.to_json() for item in mission.external_data_items]
    )


@mission_marti_api.route("/Marti/api/missions/<mission_name>/externaldata", methods=["POST", "PUT"])
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/externaldata", methods=["POST", "PUT"]
)
def set_external_data(mission_name: str = None, mission_guid: str = None):
    """TAK Server's setExternalMissionData: ?creatorUid= plus a JSON ExternalMissionData body
    ({id, name, tool, urlData, urlView, notes}). An existing id is updated, otherwise one is
    added; either way subscribers get an ADD_CONTENT change carrying the externalData."""
    access = _write_access(mission_name, mission_guid, MissionRole.MISSION_WRITE)
    if isinstance(access, flask.Response):
        return access
    mission, eud_uid = access
    body = _json_body()

    if not body.get("name") and not body.get("urlData") and not body.get("urlView"):
        return _error(gettext("External data needs a name, urlData or urlView"), 400)
    for key in ("urlData", "urlView"):
        url = body.get(key)
        if url and not str(url).lower().startswith(("http://", "https://")):
            return _error(gettext("%(field)s must be an http(s) URL", field=key), 400)
    for key in ("name", "tool"):
        if body.get(key) and len(str(body.get(key))) > 255:
            return _error(gettext("%(field)s is too long", field=key), 400)

    uid = str(body.get("id") or body.get("uid") or uuid.uuid4())[:255]
    item = db.session.execute(
        db.session.query(MissionExternalData).filter_by(mission_name=mission.name, uid=uid)
    ).scalar()
    if not item:
        item = MissionExternalData()
        item.uid = uid
        item.mission_name = mission.name
        item.create_time = datetime.datetime.now(datetime.timezone.utc)
        db.session.add(item)
    item.creator_uid = request.args.get("creatorUid") or eud_uid
    for key, column in EXTERNAL_DATA_FIELDS.items():
        if key in body:
            setattr(item, column, None if body[key] is None else str(body[key]))
    db.session.commit()

    _record_change(
        mission, MissionChange.ADD_CONTENT, item.creator_uid, external_data=item.to_json()
    )
    return _envelope("ExternalMissionData", item.to_json())


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/externaldata/<external_data_id>", methods=["DELETE"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/externaldata/<external_data_id>", methods=["DELETE"]
)
def delete_external_data(external_data_id: str, mission_name: str = None, mission_guid: str = None):
    access = _write_access(mission_name, mission_guid, MissionRole.MISSION_WRITE)
    if isinstance(access, flask.Response):
        return access
    mission, eud_uid = access
    item = db.session.execute(
        db.session.query(MissionExternalData).filter_by(
            mission_name=mission.name, uid=external_data_id
        )
    ).scalar()
    if not item:
        return _error(gettext("No such external data: %(uid)s", uid=external_data_id), 404)

    snapshot = item.to_json()
    if request.args.get("notes"):
        snapshot["notes"] = request.args.get("notes")
    db.session.delete(item)
    db.session.commit()

    _record_change(
        mission,
        MissionChange.REMOVE_CONTENT,
        request.args.get("creatorUid") or eud_uid,
        external_data=snapshot,
    )
    return _envelope("ExternalMissionData", snapshot)


@mission_marti_api.route(
    "/Marti/api/missions/<mission_name>/externaldata/<external_data_id>/change", methods=["POST"]
)
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/externaldata/<external_data_id>/change",
    methods=["POST"],
)
def notify_external_data_changed(
    external_data_id: str, mission_name: str = None, mission_guid: str = None
):
    """TAK Server's notifyExternalDataChanged: the external system's data changed, tell the
    subscribers (?creatorUid=&notes=, or the notes as the request body)"""
    access = _write_access(mission_name, mission_guid, MissionRole.MISSION_WRITE)
    if isinstance(access, flask.Response):
        return access
    mission, eud_uid = access
    item = db.session.execute(
        db.session.query(MissionExternalData).filter_by(
            mission_name=mission.name, uid=external_data_id
        )
    ).scalar()
    if not item:
        return _error(gettext("No such external data: %(uid)s", uid=external_data_id), 404)

    snapshot = item.to_json()
    notes = request.args.get("notes") or request.get_data(as_text=True)
    if notes:
        snapshot["notes"] = notes[:4096]
    _record_change(
        mission,
        MissionChange.ADD_CONTENT,
        request.args.get("creatorUid") or eud_uid,
        external_data=snapshot,
    )
    return _envelope("ExternalMissionData", snapshot)


# --- Feeds -------------------------------------------------------------------------------------


@mission_marti_api.route("/Marti/api/missions/<mission_name>/feeds", methods=["GET"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/feeds", methods=["GET"])
def get_mission_feeds(mission_name: str = None, mission_guid: str = None):
    mission = _read_access(mission_name, mission_guid)
    if isinstance(mission, flask.Response):
        return mission
    return _envelope("MissionFeed", [feed.to_json() for feed in mission.feed_items])


@mission_marti_api.route("/Marti/api/missions/<mission_name>/feed", methods=["POST", "PUT"])
@mission_marti_api.route("/Marti/api/missions/guid/<mission_guid>/feed", methods=["POST", "PUT"])
def create_mission_feed(mission_name: str = None, mission_guid: str = None):
    """TAK Server's createMissionFeed: ?creatorUid=&dataFeedUid=&filterPolygon=&filterCotTypes=
    &filterCallsign= (or a JSON body). Subscribers get a CREATE_DATA_FEED change."""
    access = _write_access(mission_name, mission_guid, MissionRole.MISSION_MANAGE_FEEDS)
    if isinstance(access, flask.Response):
        return access
    mission, eud_uid = access
    body = _json_body()

    data_feed_uid = (_arg("dataFeedUid", body) or "").strip()
    if not data_feed_uid or len(data_feed_uid) > 255:
        return _error(gettext("Please provide a dataFeedUid"), 400)

    cot_types = request.args.getlist("filterCotTypes") or body.get("filterCotTypes") or []
    if isinstance(cot_types, str):
        cot_types = [cot_types]
    filter_type = ",".join(t.strip() for t in cot_types if t and t.strip()) or _arg(
        "filterType", body
    )

    feed = MissionFeed()
    feed.uid = str(uuid.uuid4())
    feed.mission_name = mission.name
    feed.data_feed_uid = data_feed_uid
    feed.name = (_arg("name", body) or data_feed_uid)[:255]
    feed.filter_bbox = _arg("filterPolygon", body) or _arg("filterBbox", body) or None
    feed.filter_type = filter_type or None
    feed.filter_callsign = _arg("filterCallsign", body) or None
    feed.creator_uid = _arg("creatorUid", body) or eud_uid
    feed.create_time = datetime.datetime.now(datetime.timezone.utc)
    for value in (feed.filter_bbox, feed.filter_type):
        if value and len(value) > 1024:
            return _error(gettext("Feed filter is too long"), 400)
    db.session.add(feed)
    db.session.commit()

    _record_change(
        mission, MissionChange.CREATE_DATA_FEED, feed.creator_uid, mission_feed=feed.to_json()
    )
    return _envelope("MissionFeed", feed.to_json())


@mission_marti_api.route("/Marti/api/missions/<mission_name>/feed/<feed_uid>", methods=["DELETE"])
@mission_marti_api.route(
    "/Marti/api/missions/guid/<mission_guid>/feed/<feed_uid>", methods=["DELETE"]
)
def delete_mission_feed(feed_uid: str, mission_name: str = None, mission_guid: str = None):
    access = _write_access(mission_name, mission_guid, MissionRole.MISSION_MANAGE_FEEDS)
    if isinstance(access, flask.Response):
        return access
    mission, eud_uid = access
    feed = db.session.execute(
        db.session.query(MissionFeed).filter_by(mission_name=mission.name, uid=feed_uid)
    ).scalar()
    if not feed:
        return _error(gettext("No such mission feed: %(uid)s", uid=feed_uid), 404)

    snapshot = feed.to_json()
    db.session.delete(feed)
    db.session.commit()

    _record_change(
        mission,
        MissionChange.DELETE_DATA_FEED,
        request.args.get("creatorUid") or eud_uid,
        mission_feed=snapshot,
    )
    return _envelope("MissionFeed", snapshot)
