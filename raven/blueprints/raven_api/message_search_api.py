"""
Message search: query stored CoT by time, area, type, callsign/uid and chat/remarks text, and
export the same query as CSV or KML (like TAK Server's CoT query/export).

GET /api/message_search?<filters>&page=1&per_page=50        -> JSON page of results. Paging
                                                               stops at MAX_RESULT_WINDOW rows
                                                               and the total is counted up to
                                                               it ("total_capped" past that).
GET /api/message_search/export?<filters>&format=csv|kml     -> streamed file (audited)
GET /api/message_search/<cot_id>                            -> one message with its raw XML

Filters (all optional):
  start, end            ISO 8601 date/times on the CoT's time attribute (no offset = UTC).
                        With neither, the last DEFAULT_WINDOW (24 hours) is searched.
  min_lat, min_lon,     bounding box; min_lon > max_lon crosses the antimeridian
  max_lat, max_lon
  lat, lon, radius      center + radius in meters (equirectangular approximation, up to
                        MAX_RADIUS_METERS, which is accurate to well under 1% at that range)
  type                  CoT type prefix, e.g. "a-f-G" or "b-t-f"
  callsign              substring of the sender's or the marker's callsign
  uid                   exact CoT uid or sender uid
  text                  substring of the GeoChat message or the marker's remarks
  tracks=1              (KML only) also add one gx:Track per uid

Administrators see everything. Other users see what TAK routing would have delivered to them,
using their current group memberships (see visible_cots()).

Only plain columns and arithmetic are used so the same query runs on PostgreSQL, MySQL and
SQLite; there is no PostGIS dependency.
"""

import csv
import datetime
import io
import math
import re
from xml.sax.saxutils import escape

from flask import Blueprint, Response
from flask import current_app as app
from flask import jsonify, request, stream_with_context
from flask_babel import gettext
from flask_security import auth_required, current_user
from sqlalchemy import DateTime, and_, cast, false, func, literal, or_, select

from raven.audit import record_audit_event
from raven.extensions import db
from raven.functions import iso8601_string_from_datetime
from raven.models.Chatrooms import Chatroom
from raven.models.CoT import CoT
from raven.models.EUD import EUD
from raven.models.GeoChat import GeoChat
from raven.models.Group import Group
from raven.models.GroupUser import GroupUser
from raven.models.Marker import Marker
from raven.models.Point import Point

message_search_api_blueprint = Blueprint("message_search_api_blueprint", __name__)

DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 500
DEFAULT_EXPORT_MAX_ROWS = 100000
MAX_RADIUS_METERS = 500000
METERS_PER_DEGREE = 111320.0
# ATAK's "unknown" value for hae/ce/le
UNKNOWN_VALUE = 9999999.0
EXPORT_BATCH = 1000
# Searched when neither start nor end is given, so an empty search doesn't scan every CoT ever
DEFAULT_WINDOW = datetime.timedelta(hours=24)
# Paging only goes this deep (page * per_page) and the total is only counted this far: deep
# OFFSETs and exact counts over a large cots table are what make a search slow
MAX_RESULT_WINDOW = 10000

CSV_COLUMNS = (
    "timestamp",
    "uid",
    "type",
    "how",
    "callsign",
    "sender_callsign",
    "sender_uid",
    "latitude",
    "longitude",
    "hae",
    "ce",
    "le",
    "course",
    "speed",
    "chatroom",
    "message",
    "remarks",
    "mission",
    "stale",
)

# Characters XML 1.0 can't carry, even escaped
_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _parse_time(name):
    value = (request.args.get(name) or "").strip()
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(gettext("%(name)s must be an ISO 8601 date/time", name=name))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def _parse_float(name, minimum, maximum):
    value = (request.args.get(name) or "").strip()
    if not value:
        return None
    try:
        number = float(value)
    except ValueError:
        number = math.nan
    if math.isnan(number) or not minimum <= number <= maximum:
        raise ValueError(
            gettext(
                "%(name)s must be a number from %(minimum)s to %(maximum)s",
                name=name,
                minimum=minimum,
                maximum=maximum,
            )
        )
    return number


def _text(name, limit=255):
    return (request.args.get(name) or "").strip()[:limit] or None


def _like_escape(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_filters():
    """The search filters from the query string. Raises ValueError with a translated message."""
    filters = {
        "start": _parse_time("start"),
        "end": _parse_time("end"),
        "min_lat": _parse_float("min_lat", -90, 90),
        "max_lat": _parse_float("max_lat", -90, 90),
        "min_lon": _parse_float("min_lon", -180, 180),
        "max_lon": _parse_float("max_lon", -180, 180),
        "lat": _parse_float("lat", -90, 90),
        "lon": _parse_float("lon", -180, 180),
        "radius": _parse_float("radius", 0, MAX_RADIUS_METERS),
        "type": _text("type"),
        "callsign": _text("callsign"),
        "uid": _text("uid"),
        "text": _text("text"),
    }

    if filters["start"] and filters["end"] and filters["start"] > filters["end"]:
        raise ValueError(gettext("start must be before end"))
    if not filters["start"] and not filters["end"]:
        filters["start"] = datetime.datetime.now(datetime.timezone.utc) - DEFAULT_WINDOW
        filters["default_window"] = True

    bbox = [filters[k] for k in ("min_lat", "min_lon", "max_lat", "max_lon")]
    if any(v is not None for v in bbox) and not all(v is not None for v in bbox):
        raise ValueError(gettext("A bounding box needs min_lat, min_lon, max_lat and max_lon"))
    if filters["min_lat"] is not None and filters["min_lat"] > filters["max_lat"]:
        raise ValueError(gettext("min_lat must not be greater than max_lat"))

    circle = [filters[k] for k in ("lat", "lon", "radius")]
    if any(v is not None for v in circle) and not all(v is not None for v in circle):
        raise ValueError(gettext("A radius search needs lat, lon and radius"))

    return filters


NO_FILTERS = dict.fromkeys(
    (
        "start",
        "end",
        "min_lat",
        "max_lat",
        "min_lon",
        "max_lon",
        "lat",
        "lon",
        "radius",
        "type",
        "callsign",
        "uid",
        "text",
    )
)


def describe_filters(filters):
    """A short text form of the filters for the audit trail."""
    parts = []
    for key, value in filters.items():
        if value is None or key == "default_window":
            continue
        if isinstance(value, datetime.datetime):
            value = value.isoformat()
        parts.append(f"{key}={value}")
    return ", ".join(parts) or "none"


def _is_postgres():
    return db.session.get_bind().dialect.name == "postgresql"


# The cot_parser inserts aware UTC datetimes into naive DateTime columns. PostgreSQL converts
# those to its session time zone (the server's local time unless configured otherwise), SQLite
# and MySQL just drop the offset, leaving UTC. These two helpers undo that on both sides.


def _db_time(value):
    """An aware UTC datetime as something comparable with the naive CoT columns, keeping the
    column side bare so its index can be used."""
    if _is_postgres():
        return cast(literal(value, DateTime(timezone=True)), DateTime())
    return value.replace(tzinfo=None)


def _time_column(column):
    """A naive CoT time column as a value that reads back as (or as if) UTC."""
    if _is_postgres():
        return cast(column, DateTime(timezone=True))
    return column


def _active_membership(now):
    return and_(
        GroupUser.enabled.is_(True),
        or_(GroupUser.expires_at.is_(None), GroupUser.expires_at > now),
    )


def visibility_clause(user):
    """SQL condition for the CoT rows `user` may see, or None for no restriction (admins).

    Mirrors the live routing in cot_parser.route_cot() and the EUD handler's queue bindings,
    using the user's current memberships:
    * CoT sent by one of the user's own EUDs
    * CoT without a <dest>, sent by a user with an IN membership in a group the user has OUT
      membership in
    * CoT without a <dest> that went to __ANON__ (sender unknown, has no user, or the user has
      no IN groups), if the user receives __ANON__ (no OUT groups at all, or OUT in __ANON__)
    * CoT with a <dest>: chat messages to one of the user's EUDs, and other CoT addressed to
      one of their EUDs by callsign or uid
    Mission (<dest mission=...>) CoT is only shown to its sender here.
    """
    if user.has_role("administrator"):
        return None

    now = _utcnow()
    active = _active_membership(now)

    out_groups = [
        row[0]
        for row in db.session.query(GroupUser.group_id)
        .filter(GroupUser.user_id == user.id, GroupUser.direction == Group.OUT, active)
        .all()
    ]
    anon = db.session.query(Group.id).filter(Group.name == "__ANON__").scalar()
    receives_anon = not out_groups or (anon is not None and anon in out_groups)

    own_euds = db.session.query(EUD.uid, EUD.callsign).filter(EUD.user_id == user.id).all()
    own_uids = [e.uid for e in own_euds]

    senders_with_in = (
        select(EUD.uid)
        .join(GroupUser, GroupUser.user_id == EUD.user_id)
        .where(GroupUser.direction == Group.IN, active)
    )
    group_senders = senders_with_in.where(GroupUser.group_id.in_(out_groups))

    broadcast = [CoT.sender_uid.in_(group_senders)] if out_groups else []
    if receives_anon:
        broadcast.append(or_(CoT.sender_uid.is_(None), CoT.sender_uid.not_in(senders_with_in)))

    addressed = []
    if own_uids:
        addressed.append(GeoChat.chatroom_id.in_(own_uids))
    for eud in own_euds:
        for attr, value in (("uid", eud.uid), ("callsign", eud.callsign)):
            if value:
                addressed.append(
                    CoT.xml.like(f'%<dest {attr}="{_like_escape(value)}"%', escape="\\")
                )

    directed = CoT.xml.like("%<dest %")
    return or_(
        CoT.sender_uid.in_(own_uids) if own_uids else false(),
        and_(~directed, or_(*broadcast)) if broadcast else false(),
        and_(directed, or_(*addressed)) if addressed else false(),
    )


def _columns():
    return (
        CoT.id.label("id"),
        _time_column(CoT.timestamp).label("timestamp"),
        CoT.uid.label("uid"),
        CoT.type.label("type"),
        CoT.how.label("how"),
        _time_column(CoT.stale).label("stale"),
        CoT.sender_uid.label("sender_uid"),
        CoT.mission_name.label("mission"),
        EUD.callsign.label("sender_callsign"),
        Marker.callsign.label("marker_callsign"),
        Marker.remarks.label("remarks"),
        Point.latitude.label("latitude"),
        Point.longitude.label("longitude"),
        Point.hae.label("hae"),
        Point.ce.label("ce"),
        Point.le.label("le"),
        Point.course.label("course"),
        Point.speed.label("speed"),
        GeoChat.remarks.label("message"),
        Chatroom.name.label("chatroom"),
    )


def build_query(filters, user, columns=None):
    """A select() of the matching messages (unordered)."""
    query = (
        select(*(columns or _columns()))
        .select_from(CoT)
        .outerjoin(Point, Point.cot_id == CoT.id)
        .outerjoin(GeoChat, GeoChat.cot_id == CoT.id)
        .outerjoin(Chatroom, Chatroom.id == GeoChat.chatroom_id)
        .outerjoin(Marker, Marker.cot_id == CoT.id)
        .outerjoin(EUD, EUD.uid == CoT.sender_uid)
    )

    if filters["start"]:
        query = query.where(CoT.timestamp >= _db_time(filters["start"]))
    if filters["end"]:
        query = query.where(CoT.timestamp <= _db_time(filters["end"]))

    if filters["min_lat"] is not None:
        query = query.where(Point.latitude.between(filters["min_lat"], filters["max_lat"]))
        if filters["min_lon"] <= filters["max_lon"]:
            query = query.where(Point.longitude.between(filters["min_lon"], filters["max_lon"]))
        else:
            query = query.where(
                or_(Point.longitude >= filters["min_lon"], Point.longitude <= filters["max_lon"])
            )

    if filters["radius"] is not None:
        lat, lon = filters["lat"], filters["lon"]
        dlat = filters["radius"] / METERS_PER_DEGREE
        cos_lat = math.cos(math.radians(lat))
        # Index-friendly bounding box first, then the distance itself
        query = query.where(Point.latitude.between(lat - dlat, lat + dlat))
        if abs(lat) + dlat < 89 and dlat / max(cos_lat, 1e-6) < 180:
            dlon = dlat / cos_lat
            query = query.where(Point.longitude.between(lon - dlon, lon + dlon))
        dx = (Point.longitude - literal(lon)) * literal(cos_lat)
        dy = Point.latitude - literal(lat)
        query = query.where(dx * dx + dy * dy <= literal(dlat * dlat))

    if filters["type"]:
        query = query.where(CoT.type.like(_like_escape(filters["type"]) + "%", escape="\\"))

    if filters["callsign"]:
        like = f"%{_like_escape(filters['callsign'].lower())}%"
        query = query.where(
            or_(
                func.lower(EUD.callsign).like(like, escape="\\"),
                func.lower(Marker.callsign).like(like, escape="\\"),
            )
        )

    if filters["uid"]:
        query = query.where(or_(CoT.uid == filters["uid"], CoT.sender_uid == filters["uid"]))

    if filters["text"]:
        like = f"%{_like_escape(filters['text'].lower())}%"
        query = query.where(
            or_(
                func.lower(GeoChat.remarks).like(like, escape="\\"),
                func.lower(Marker.remarks).like(like, escape="\\"),
            )
        )

    visible = visibility_clause(user)
    if visible is not None:
        query = query.where(visible)

    return query


def _utc(value):
    if value is not None and value.tzinfo is not None:
        value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return value


def _iso(value):
    value = _utc(value)
    return iso8601_string_from_datetime(value) if value else None


def _known(value):
    if value is None or abs(value) >= UNKNOWN_VALUE:
        return None
    return value


def row_to_json(row):
    return {
        "id": row.id,
        "timestamp": _iso(row.timestamp),
        "stale": _iso(row.stale),
        "uid": row.uid,
        "type": row.type,
        "how": row.how,
        "callsign": row.marker_callsign or row.sender_callsign,
        "sender_callsign": row.sender_callsign,
        "sender_uid": row.sender_uid,
        "latitude": row.latitude,
        "longitude": row.longitude,
        "hae": _known(row.hae),
        "ce": _known(row.ce),
        "le": _known(row.le),
        "course": row.course,
        "speed": row.speed,
        "chatroom": row.chatroom,
        "message": row.message,
        "remarks": row.remarks,
        "mission": row.mission,
    }


def _bad_request(error):
    return jsonify({"success": False, "error": str(error)}), 400


def _int_arg(name, default, minimum, maximum):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _ordered(query):
    return query.order_by(CoT.timestamp.desc(), CoT.id.desc())


@message_search_api_blueprint.route("/api/message_search")
@auth_required()
def search_messages():
    try:
        filters = parse_filters()
    except ValueError as e:
        return _bad_request(e)

    per_page = _int_arg("per_page", DEFAULT_PER_PAGE, 1, MAX_PER_PAGE)
    page = _int_arg("page", 1, 1, max(1, MAX_RESULT_WINDOW // per_page))

    query = build_query(filters, current_user)
    # Counted no further than one past the window, so a huge match costs no more than that
    counted = db.session.execute(
        select(func.count()).select_from(query.limit(MAX_RESULT_WINDOW + 1).subquery())
    ).scalar()
    total_capped = counted > MAX_RESULT_WINDOW
    total = min(counted, MAX_RESULT_WINDOW)
    rows = db.session.execute(_ordered(query).limit(per_page).offset((page - 1) * per_page)).all()

    return jsonify(
        {
            "success": True,
            "results": [row_to_json(row) for row in rows],
            "total": total,
            "total_capped": total_capped,
            "max_results": MAX_RESULT_WINDOW,
            "current_page": page,
            "per_page": per_page,
            "total_pages": max(1, math.ceil(total / per_page)),
            "export_max_rows": export_max_rows(),
            # Set when no start/end was given and only the last 24 hours were searched
            "default_start": _iso(filters["start"]) if filters.get("default_window") else None,
        }
    )


@message_search_api_blueprint.route("/api/message_search/<int:cot_id>")
@auth_required()
def get_message(cot_id):
    query = build_query(
        NO_FILTERS,
        current_user,
        columns=_columns() + (CoT.xml.label("xml"),),
    ).where(CoT.id == cot_id)
    row = db.session.execute(query).first()
    if not row:
        return jsonify({"success": False, "error": gettext("Message not found")}), 404
    result = row_to_json(row)
    result["xml"] = row.xml
    return jsonify({"success": True, "message": result})


def export_max_rows():
    try:
        return max(1, int(app.config.get("RAVEN_MESSAGE_EXPORT_MAX_ROWS", DEFAULT_EXPORT_MAX_ROWS)))
    except (TypeError, ValueError):
        return DEFAULT_EXPORT_MAX_ROWS


def _stream(query, limit):
    """Rows of `query`, fetched in batches rather than all at once."""
    result = db.session.execute(
        query.limit(limit).execution_options(yield_per=EXPORT_BATCH, stream_results=True)
    )
    try:
        for row in result:
            yield row
    finally:
        result.close()


def _csv_cell(value):
    # Spreadsheet formula injection: text starting with these is run as a formula by Excel etc.
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def generate_csv(query, limit):
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    def flush():
        data = buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        return data

    writer.writerow(CSV_COLUMNS)
    yield flush()

    for count, row in enumerate(_stream(_ordered(query), limit), start=1):
        data = row_to_json(row)
        writer.writerow(
            [_csv_cell(data[column] if data[column] is not None else "") for column in CSV_COLUMNS]
        )
        if count % 200 == 0:
            yield flush()
    yield flush()


def _x(value):
    return escape(_INVALID_XML.sub("", str(value)))


def _kml_when(value):
    value = _utc(value)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _placemark(data, timestamp):
    name = data["callsign"] or data["uid"] or ""
    description = []
    for label, key in (
        ("Type", "type"),
        ("UID", "uid"),
        ("Sender", "sender_callsign"),
        ("Chat room", "chatroom"),
        ("Message", "message"),
        ("Remarks", "remarks"),
    ):
        if data[key]:
            description.append(f"{label}: {data[key]}")

    parts = [f"<Placemark><name>{_x(name)}</name>"]
    when = _kml_when(timestamp)
    if when:
        parts.append(f"<TimeStamp><when>{when}</when></TimeStamp>")
    if description:
        parts.append(f"<description>{_x(chr(10).join(description))}</description>")
    parts.append("<ExtendedData>")
    for key in CSV_COLUMNS:
        if data.get(key) is not None:
            parts.append(f'<Data name="{key}"><value>{_x(data[key])}</value></Data>')
    parts.append("</ExtendedData>")
    parts.append(
        f"<Point><coordinates>{data['longitude']},{data['latitude']}</coordinates></Point>"
        "</Placemark>\n"
    )
    return "".join(parts)


def _track(uid, name, points):
    whens = "".join(f"<when>{_kml_when(t)}</when>" for t, _, _ in points)
    coords = "".join(f"<gx:coord>{lon} {lat} 0</gx:coord>" for _, lat, lon in points)
    return (
        f"<Placemark><name>{_x(name or uid)}</name>"
        f'<ExtendedData><Data name="uid"><value>{_x(uid)}</value></Data></ExtendedData>'
        f"<gx:Track><altitudeMode>clampToGround</altitudeMode>{whens}{coords}</gx:Track>"
        "</Placemark>\n"
    )


def generate_kml(query, limit, tracks=False):
    located = query.where(Point.latitude.isnot(None), Point.longitude.isnot(None))

    yield (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2">\n'
        f"<Document><name>{_x(gettext('Message search'))}</name>\n"
        f"<Folder><name>{_x(gettext('Messages'))}</name>\n"
    )
    for row in _stream(_ordered(located), limit):
        yield _placemark(row_to_json(row), row.timestamp)
    yield "</Folder>\n"

    if tracks:
        yield f"<Folder><name>{_x(gettext('Tracks'))}</name>\n"
        current, name, points = None, None, []
        ordered = located.where(CoT.uid.isnot(None)).order_by(
            CoT.uid, CoT.timestamp.asc(), CoT.id.asc()
        )
        for row in _stream(ordered, limit):
            if row.uid != current:
                if len(points) > 1:
                    yield _track(current, name, points)
                current, name, points = row.uid, None, []
            name = row.marker_callsign or row.sender_callsign or name
            if row.timestamp:
                points.append((row.timestamp, row.latitude, row.longitude))
        if len(points) > 1:
            yield _track(current, name, points)
        yield "</Folder>\n"

    yield "</Document>\n</kml>\n"


@message_search_api_blueprint.route("/api/message_search/export")
@auth_required()
def export_messages():
    try:
        filters = parse_filters()
    except ValueError as e:
        return _bad_request(e)

    export_format = (request.args.get("format") or "csv").lower()
    if export_format not in ("csv", "kml"):
        return _bad_request(gettext("format must be csv or kml"))
    tracks = export_format == "kml" and request.args.get("tracks") in ("1", "true", "yes")

    limit = export_max_rows()
    query = build_query(filters, current_user)

    record_audit_event(
        "data_export",
        f"message_export_{export_format}",
        username=current_user.username,
        details=f"Message search export ({export_format.upper()}"
        + (", with tracks" if tracks else "")
        + f", max {limit} rows). Filters: {describe_filters(filters)}",
    )

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    if export_format == "csv":
        body, mimetype = generate_csv(query, limit), "text/csv"
    else:
        body, mimetype = generate_kml(query, limit, tracks), "application/vnd.google-earth.kml+xml"

    return Response(
        stream_with_context(body),
        mimetype=mimetype,
        headers={
            "Content-Disposition": f'attachment; filename="messages-{stamp}.{export_format}"',
            "X-Export-Max-Rows": str(limit),
            "Cache-Control": "no-store",
        },
    )
