import hashlib
import os
import traceback
import uuid
import zipfile
from io import BytesIO

import bleach
import sqlalchemy
from bs4 import BeautifulSoup
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from sqlalchemy import insert, update
from werkzeug.utils import secure_filename

from raven.extensions import db, logger
from raven.functions import datetime_from_iso8601_string
from raven.models.CITrap import CITrap
from raven.models.Point import Point

# strict_slashes=False so both "/Marti/api/citrap" and "/Marti/api/citrap/"
# resolve to the same routes -- real clients have been observed sending both.
citrap_api_blueprint = Blueprint("citrap_api_blueprint", __name__)


@citrap_api_blueprint.route("/Marti/api/missions/citrap/subscription", methods=["PUT"], strict_slashes=False)
def citrap_subscription():
    bleach.clean(request.args.get("uid", ""))
    return "", 201


@citrap_api_blueprint.route("/Marti/api/citrap", methods=["GET"], strict_slashes=False)
def search_citrap():
    query = db.session.query(CITrap)

    report_type = request.args.get("type")
    if report_type:
        query = query.filter_by(type=bleach.clean(report_type))

    callsign = request.args.get("callsign")
    if callsign:
        query = query.filter_by(user_callsign=bleach.clean(callsign))

    max_report_count = request.args.get("maxReportCount")
    if max_report_count:
        try:
            query = query.limit(int(max_report_count))
        except ValueError:
            pass

    reports = db.session.execute(query).scalars()
    return jsonify([r.to_json() for r in reports])


@citrap_api_blueprint.route("/Marti/api/citrap", methods=["POST"], strict_slashes=False)
def add_citrap():
    client_uid = request.args.get("clientUid")
    if not client_uid:
        return jsonify({"success": False, "error": gettext("clientUid not found")}), 400
    client_uid = bleach.clean(client_uid)

    reports_dir = os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    try:
        zipf = zipfile.ZipFile(BytesIO(request.data), "r", zipfile.ZIP_DEFLATED, False)
    except zipfile.BadZipFile:
        return jsonify({"success": False, "error": gettext("Invalid report package")}), 400

    report_filename = next((n for n in zipf.namelist() if n.endswith("report.xml")), None)
    if not report_filename:
        return jsonify({"success": False, "error": gettext("report.xml not found")}), 400

    manifest = zipf.read(report_filename).decode("utf-8")
    soup = BeautifulSoup(manifest, "xml")
    report = soup.find("report")
    if not report:
        return jsonify({"success": False, "error": gettext("Invalid report file")}), 400

    filename = f"{secure_filename(str(report.attrs.get('title') or uuid.uuid4()))}.zip"
    with open(os.path.join(reports_dir, filename), "wb") as f:
        f.write(request.data)

    sha256 = hashlib.sha256()
    sha256.update(request.data)

    point = Point()
    point.uid = report.attrs.get("id") or str(uuid.uuid4())
    point.device_uid = client_uid

    point_wkt = report.attrs.get("location")
    latitude = 0
    longitude = 0
    if point_wkt:
        try:
            coords = str(point_wkt).replace("POINT (", "").replace(")", "").split(" ")
            longitude, latitude = float(coords[0]), float(coords[1])
        except (IndexError, ValueError):
            latitude = longitude = 0

    point.latitude = latitude
    point.longitude = longitude
    point.timestamp = datetime_from_iso8601_string(report.attrs.get("dateTime"))

    point_result = db.session.execute(insert(Point).values(**point.serialize()))
    db.session.commit()
    point_pk = point_result.inserted_primary_key[0]

    citrap = CITrap()
    citrap.id = report.attrs.get("id") or str(uuid.uuid4())
    citrap.type = report.attrs.get("type")
    citrap.title = report.attrs.get("title")
    visibility = report.attrs.get("visibilityStatus")
    citrap.visible = str(visibility).lower() == "true" if visibility is not None else True
    citrap.delimiter = report.attrs.get("delimiter")
    citrap.user_callsign = report.attrs.get("userCallsign")
    citrap.user_description = report.attrs.get("userDescription")
    citrap.date_time = datetime_from_iso8601_string(report.attrs.get("dateTime"))
    citrap.date_time_description = report.attrs.get("dateTimeDescription")
    citrap.point_id = point_pk
    citrap.location_description = report.attrs.get("locationDescription")
    citrap.tags = report.attrs.get("tags")
    citrap.event_scale = report.attrs.get("eventScale")
    citrap.scale_description = report.attrs.get("scaleDescription")
    citrap.importance = report.attrs.get("importance")
    citrap.status = report.attrs.get("status")
    citrap.file_name = filename
    citrap.hash = sha256.hexdigest()

    try:
        db.session.add(citrap)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        db.session.rollback()
        db.session.execute(update(CITrap).where(CITrap.id == citrap.id).values(**citrap.serialize()))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add citrap report: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": gettext("Failed to add report")}), 500

    return jsonify({"id": citrap.id}), 201


@citrap_api_blueprint.route("/Marti/api/citrap/<id>", methods=["GET"], strict_slashes=False)
def get_citrap(id):
    citrap = db.session.get(CITrap, bleach.clean(id))
    if not citrap:
        return jsonify({"success": False, "error": gettext("Report not found")}), 404
    return jsonify(citrap.to_json())


@citrap_api_blueprint.route("/Marti/api/citrap/<id>", methods=["PUT"], strict_slashes=False)
def put_citrap(id):
    # Reports are re-submitted whole via POST /Marti/api/citrap (see the
    # IntegrityError branch of add_citrap, which updates in place on a
    # duplicate id) rather than partially updated via PUT.
    citrap = db.session.get(CITrap, bleach.clean(id))
    if not citrap:
        return jsonify({"success": False, "error": gettext("Report not found")}), 404
    return jsonify(citrap.to_json())


@citrap_api_blueprint.route("/Marti/api/citrap/<id>", methods=["DELETE"], strict_slashes=False)
def delete_citrap(id):
    citrap = db.session.get(CITrap, bleach.clean(id))
    if not citrap:
        return jsonify({"success": False, "error": gettext("Report not found")}), 404
    db.session.delete(citrap)
    db.session.commit()
    return jsonify({"success": True})
