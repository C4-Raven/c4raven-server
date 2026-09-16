import os
import shutil
import traceback
from datetime import datetime, timezone

from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request, send_from_directory
from flask_babel import gettext
from flask_security import auth_required, current_user
from sqlalchemy import update
from werkzeug.datastructures import ImmutableMultiDict

from raven.blueprints.marti_api.data_package_marti_api import (
    can_access_data_package,
    data_package_share,
    visible_data_packages,
)
from raven.blueprints.raven_api.api import paginate, search
from raven.extensions import db, logger
from raven.forms.data_package_form import DataPackageUpdateForm
from raven.models.Certificate import Certificate
from raven.models.DataPackage import DataPackage

data_package_api = Blueprint("data_package_api", __name__)


@data_package_api.route("/api/data_packages", methods=["PATCH"])
@auth_required()
def edit_data_package():
    # These flags push the package to every device, so only admins may set them
    if not current_user.has_role("administrator"):
        return jsonify({"success": False, "error": gettext("Administrator role required")}), 403

    form = DataPackageUpdateForm(formdata=ImmutableMultiDict(request.json))
    if not form.validate():
        return jsonify({"success": False, "errors": form.errors}), 400

    data_package = db.session.execute(
        db.session.query(DataPackage).filter_by(hash=form.hash.data)
    ).first()
    if not data_package:
        return (
            jsonify({"success": False, "error": f"Package with hash {form.hash.data} not found"}),
            404,
        )

    data_package = data_package[0]

    if data_package.filename.endswith("_CONFIG.zip"):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Server connection data packages can't be installed on enrollment or connection"
                    ),
                }
            ),
            400,
        )

    wants_auto_install = form.install_on_enrollment.data or form.install_on_connection.data
    if data_package.is_private and wants_auto_install:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Private data packages can't be installed on enrollment or connection"
                    ),
                }
            ),
            400,
        )

    if form.install_on_enrollment.data is not None:
        data_package.install_on_enrollment = form.install_on_enrollment.data
    if form.install_on_connection.data is not None:
        data_package.install_on_connection = form.install_on_connection.data

    data_package.submission_time = datetime.now(timezone.utc)

    db.session.execute(
        update(DataPackage)
        .filter(DataPackage.hash == data_package.hash)
        .values(**data_package.serialize())
    )
    db.session.commit()

    return jsonify({"success": True})


@data_package_api.route("/api/data_packages", methods=["DELETE"])
@auth_required()
def delete_data_package():
    file_hash = request.args.get("hash")
    if not file_hash:
        return jsonify({"success": False, "error": "Please provide a file hash"}), 400

    query = db.session.query(DataPackage)
    query = search(query, DataPackage, "hash")
    data_package = db.session.execute(query).first()
    if not data_package:
        return jsonify({"success": False, "error": gettext("Invalid/unknown hash")}), 400

    dp = data_package[0]
    is_owner = dp.submission_user == current_user.id or (
        dp.eud is not None and dp.eud.user_id == current_user.id
    )
    if not (is_owner or current_user.has_role("administrator")):
        return (
            jsonify(
                {"success": False, "error": gettext("You can only delete your own data packages")}
            ),
            403,
        )

    try:
        logger.warning(
            "Deleting data package {} - {}".format(data_package[0].filename, data_package[0].hash)
        )
        db.session.delete(data_package[0])
        db.session.commit()
        os.remove(
            os.path.join(app.config.get("UPLOAD_FOLDER"), "{}.zip".format(data_package[0].hash))
        )

        if data_package[0].certificate:
            Certificate.query.filter_by(id=data_package[0].certificate.id).delete()
            db.session.commit()
            shutil.rmtree(
                os.path.join(
                    app.config.get("RAVEN_CA_FOLDER"),
                    "certs",
                    data_package[0].certificate.common_name,
                ),
                ignore_errors=True,
            )
    except BaseException as e:
        logger.error("Failed to delete data package")
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True})


@data_package_api.route("/api/data_packages")
@auth_required()
def data_packages():
    query = db.session.query(DataPackage)
    query = search(query, DataPackage, "filename")
    query = search(query, DataPackage, "hash")
    query = search(query, DataPackage, "creator_uid")
    query = search(query, DataPackage, "keywords")
    query = search(query, DataPackage, "mime_type")
    query = search(query, DataPackage, "size")
    query = search(query, DataPackage, "tool")
    query = visible_data_packages(query, current_user, admin_sees_all=True)

    return paginate(query, DataPackage)


@data_package_api.route("/api/data_packages/download")
@auth_required()
def data_package_download():
    if "hash" not in request.args.keys():
        return (
            jsonify({"success": False, "error": gettext("Please provide a data package hash")}),
            400,
        )

    file_hash = request.args.get("hash")

    query = db.session.query(DataPackage)
    query = search(query, DataPackage, "hash")

    data_package = db.session.execute(query).first()

    if not data_package:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Data package with hash '%(hash)s' not found", hash=file_hash),
                }
            ),
            404,
        )

    if not can_access_data_package(data_package[0], current_user):
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("This data package is private to its sender and recipients"),
                }
            ),
            403,
        )

    download_name = data_package[0].filename
    name, extension = os.path.splitext(download_name)

    return send_from_directory(
        app.config.get("UPLOAD_FOLDER"),
        f"{file_hash}{extension}",
        as_attachment=True,
        download_name=download_name,
    )


@data_package_api.route("/api/data_packages", methods=["POST"])
@auth_required()
def upload_data_package():
    return data_package_share()
