"""Mission (Data Sync) exports: the mission archive (an ATAK mission package zip) and KML.

Shared by the Marti API (GET /Marti/api/missions/<name>/archive and .../kml, used by ATAK) and the
web API (the mission detail page's download buttons).
"""

import hashlib
import io
import os
import zipfile
from xml.etree.ElementTree import Element, SubElement, fromstring, tostring

from flask import current_app as app
from sqlalchemy import func
from werkzeug.utils import secure_filename

from raven.extensions import db, logger
from raven.models.CoT import CoT
from raven.models.Mission import Mission
from raven.models.MissionUID import MissionUID

KML_NAMESPACE = "http://www.opengis.net/kml/2.2"
# CoT's "unknown" sentinel for hae/ce/le
COT_UNKNOWN = 9999999.0
CHUNK_SIZE = 64 * 1024


def latest_mission_cots(mission_name: str) -> list[CoT]:
    """The newest CoT row of each map item in a mission (the cot table can hold several per uid)"""
    newest = (
        db.session.query(func.max(CoT.id).label("id"))
        .filter(CoT.mission_name == mission_name, CoT.uid.isnot(None))
        .group_by(CoT.uid)
        .subquery()
    )
    return list(
        db.session.execute(
            db.select(CoT).join(newest, CoT.id == newest.c.id).order_by(CoT.id)
        ).scalars()
    )


def content_file_path(content) -> str | None:
    """Where a MissionContent's file is on disk, looked up the same way /Marti/sync/content does"""
    _, extension = os.path.splitext(secure_filename(content.filename or ""))
    candidates = [
        os.path.join(app.config.get("UPLOAD_FOLDER") or "", f"{content.hash}{extension}"),
        os.path.join(
            app.config.get("RAVEN_DATA_FOLDER"), "missions", secure_filename(content.filename or "")
        ),
    ]
    for path in candidates:
        if content.filename and os.path.isfile(path):
            return path
    return None


def _safe_dir(uid: str) -> str:
    return secure_filename(uid) or hashlib.sha1(uid.encode()).hexdigest()


def _parameter(parent: Element, name: str, value) -> None:
    SubElement(parent, "Parameter", {"name": name, "value": str(value or "")})


def archive_entries(mission: Mission) -> tuple[bytes, list[tuple[str, str | bytes]]]:
    """Builds the manifest and the list of (zip entry name, file path or bytes) for a mission's
    archive. Everything that needs the database happens here, so the zip itself can be streamed
    after the request's session is gone.

    Layout is ATAK's mission package format, so the archive imports as a data package:
    MANIFEST/manifest.xml, <content uid>/<file name> for each file and <item uid>/<item uid>.cot
    for each map item.
    """
    manifest = Element("MissionPackageManifest", {"version": "2"})
    configuration = SubElement(manifest, "Configuration")
    _parameter(configuration, "uid", mission.guid or mission.name)
    _parameter(configuration, "name", mission.name)
    _parameter(configuration, "mission_name", mission.name)
    _parameter(configuration, "mission_label", mission.name)
    _parameter(configuration, "mission_guid", mission.guid)
    _parameter(configuration, "onReceiveDelete", "false")
    contents = SubElement(manifest, "Contents")

    entries: list[tuple[str, str | bytes]] = []
    used = set()

    for content in mission.contents:
        path = content_file_path(content)
        if not path:
            logger.warning(
                f"Mission {mission.name}: {content.filename} ({content.hash}) is missing on disk, "
                "leaving it out of the archive"
            )
            continue
        entry = f"{_safe_dir(content.uid or content.hash)}/{secure_filename(content.filename)}"
        if entry in used:
            continue
        used.add(entry)
        entries.append((entry, path))
        content_element = SubElement(contents, "Content", {"ignore": "false", "zipEntry": entry})
        _parameter(content_element, "uid", content.uid)
        _parameter(content_element, "name", content.filename)

    for cot in latest_mission_cots(mission.name):
        if not cot.xml:
            continue
        entry = f"{_safe_dir(cot.uid)}/{_safe_dir(cot.uid)}.cot"
        if entry in used:
            continue
        used.add(entry)
        xml = (
            cot.xml
            if cot.xml.lstrip().startswith("<?xml")
            else ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + cot.xml)
        )
        entries.append((entry, xml.encode("utf-8")))
        content_element = SubElement(contents, "Content", {"ignore": "false", "zipEntry": entry})
        _parameter(content_element, "uid", cot.uid)

    manifest_bytes = b'<?xml version="1.0" encoding="UTF-8"?>' + tostring(manifest)
    return manifest_bytes, entries


class _ChunkSink(io.RawIOBase):
    """A write-only, non-seekable file for zipfile: collects what it writes until drained"""

    def __init__(self):
        super().__init__()
        self._chunks: list[bytes] = []

    def writable(self):
        return True

    def seekable(self):
        return False

    def write(self, b):
        self._chunks.append(bytes(b))
        return len(b)

    def drain(self) -> bytes:
        data = b"".join(self._chunks)
        self._chunks.clear()
        return data


def stream_archive(manifest: bytes, entries: list[tuple[str, str | bytes]]):
    """Yields the archive zip in chunks without holding it (or any file) in memory whole"""
    sink = _ChunkSink()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("MANIFEST/manifest.xml", manifest)
        yield sink.drain()
        for name, source in entries:
            if isinstance(source, bytes):
                archive.writestr(name, source)
            else:
                try:
                    with open(source, "rb") as f, archive.open(name, "w") as out:
                        while chunk := f.read(CHUNK_SIZE):
                            out.write(chunk)
                            data = sink.drain()
                            if data:
                                yield data
                except OSError as e:
                    logger.error(f"Failed to add {source} to a mission archive: {e}")
            data = sink.drain()
            if data:
                yield data
    yield sink.drain()


def archive_filename(mission: Mission) -> str:
    return f"{secure_filename(mission.name) or 'mission'}.zip"


def kml_filename(mission: Mission) -> str:
    return f"{secure_filename(mission.name) or 'mission'}.kml"


def _float(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coordinates(lat, lon, hae=None) -> str:
    if hae is None or hae >= COT_UNKNOWN:
        hae = 0.0
    return f"{lon},{lat},{hae}"


def _kml_color(argb) -> str | None:
    """ATAK colors are signed 32-bit ARGB ints; KML wants aabbggrr hex"""
    try:
        value = int(argb) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None
    a, r, g, b = (value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF
    return f"{a:02x}{b:02x}{g:02x}{r:02x}"


def _extended_data(placemark: Element, values: dict) -> None:
    extended = SubElement(placemark, "ExtendedData")
    for key, value in values.items():
        if value:
            data = SubElement(extended, "Data", {"name": key})
            SubElement(data, "value").text = str(value)


def _placemark_from_cot(folder: Element, cot: CoT) -> bool:
    try:
        event = fromstring(cot.xml)
    except Exception as e:
        logger.warning(f"Skipping unparseable CoT {cot.uid} in KML export: {e}")
        return False

    point = event.find("point")
    detail = event.find("detail")
    contact = detail.find("contact") if detail is not None else None
    remarks = detail.find("remarks") if detail is not None else None
    links = detail.findall("link") if detail is not None else []

    name = (contact.get("callsign") if contact is not None else None) or cot.uid
    placemark = SubElement(folder, "Placemark", {"id": _safe_dir(cot.uid)})
    SubElement(placemark, "name").text = name
    if remarks is not None and remarks.text:
        SubElement(placemark, "description").text = remarks.text
    if cot.timestamp:
        timestamp = SubElement(placemark, "TimeStamp")
        SubElement(timestamp, "when").text = cot.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    color = None
    if detail is not None:
        for tag in ("color", "strokeColor"):
            element = detail.find(tag)
            if element is not None:
                color = _kml_color(element.get("argb") or element.get("value"))
                if color:
                    break
    if color:
        style = SubElement(placemark, "Style")
        SubElement(SubElement(style, "IconStyle"), "color").text = color
        SubElement(SubElement(style, "LineStyle"), "color").text = color

    _extended_data(placemark, {"uid": cot.uid, "type": event.get("type"), "how": event.get("how")})

    # Shapes, routes and rectangles carry their vertices as <link point="lat,lon[,hae]"/>
    vertices = []
    for link in links:
        parts = (link.get("point") or "").split(",")
        if len(parts) >= 2:
            lat, lon = _float(parts[0]), _float(parts[1])
            if lat is not None and lon is not None:
                vertices.append(
                    _coordinates(lat, lon, _float(parts[2]) if len(parts) > 2 else None)
                )

    if len(vertices) >= 2:
        cot_type = event.get("type") or ""
        closed = vertices[0] == vertices[-1] or cot_type.startswith("u-d-r")
        if closed and len(vertices) >= 3:
            if vertices[0] != vertices[-1]:
                vertices.append(vertices[0])
            polygon = SubElement(placemark, "Polygon")
            ring = SubElement(SubElement(polygon, "outerBoundaryIs"), "LinearRing")
            SubElement(ring, "coordinates").text = " ".join(vertices)
        else:
            line = SubElement(placemark, "LineString")
            SubElement(line, "coordinates").text = " ".join(vertices)
        return True

    if point is None:
        folder.remove(placemark)
        return False
    lat, lon = _float(point.get("lat")), _float(point.get("lon"))
    if lat is None or lon is None:
        folder.remove(placemark)
        return False
    SubElement(SubElement(placemark, "Point"), "coordinates").text = _coordinates(
        lat, lon, _float(point.get("hae"))
    )
    return True


def build_kml(mission: Mission) -> bytes:
    """A KML document with one Placemark per map item in the mission. Items with a CoT row use
    it (points, lines and polygons); items we only know from mission_uids become points."""
    kml = Element("kml", {"xmlns": KML_NAMESPACE})
    document = SubElement(kml, "Document")
    SubElement(document, "name").text = mission.name
    if mission.description:
        SubElement(document, "description").text = mission.description
    folder = SubElement(document, "Folder")
    SubElement(folder, "name").text = mission.name

    seen = set()
    for cot in latest_mission_cots(mission.name):
        if _placemark_from_cot(folder, cot):
            seen.add(cot.uid)

    uids = db.session.execute(
        db.select(MissionUID).filter_by(mission_name=mission.name).order_by(MissionUID.uid)
    ).scalars()
    for mission_uid in uids:
        if mission_uid.uid in seen or mission_uid.latitude is None or mission_uid.longitude is None:
            continue
        placemark = SubElement(folder, "Placemark", {"id": _safe_dir(mission_uid.uid)})
        SubElement(placemark, "name").text = mission_uid.callsign or mission_uid.uid
        _extended_data(placemark, {"uid": mission_uid.uid, "type": mission_uid.cot_type})
        SubElement(SubElement(placemark, "Point"), "coordinates").text = _coordinates(
            mission_uid.latitude, mission_uid.longitude
        )

    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(kml)
