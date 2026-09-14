import os
import uuid
from datetime import datetime, timezone

from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request, send_from_directory
from flask_babel import gettext
from flask_security import auth_required, current_user, roles_accepted
from werkzeug.utils import secure_filename

from raven.extensions import db, logger
from raven.models.SupportingDocument import SupportingDocument

supporting_document_api = Blueprint("supporting_document_api", __name__)


def supporting_documents_folder():
    folder = os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "supporting_documents")
    os.makedirs(folder, exist_ok=True)
    return folder


@supporting_document_api.route("/api/supporting_documents")
@auth_required()
def get_supporting_documents():
    documents = (
        db.session.query(SupportingDocument)
        .order_by(SupportingDocument.uploaded_at.desc())
        .all()
    )
    return jsonify({"results": [document.to_json() for document in documents]})


@supporting_document_api.route("/api/supporting_documents", methods=["POST"])
@auth_required()
@roles_accepted("administrator")
def upload_supporting_document():
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"success": False, "error": gettext("Please choose a file to upload")}), 400

    file = request.files["file"]
    filename = secure_filename(file.filename)
    stored_filename = f"{uuid.uuid4().hex}_{filename}"

    file.save(os.path.join(supporting_documents_folder(), stored_filename))
    size = os.path.getsize(os.path.join(supporting_documents_folder(), stored_filename))

    document = SupportingDocument(
        filename=filename,
        stored_filename=stored_filename,
        mime_type=file.mimetype,
        size=size,
        uploaded_at=datetime.now(timezone.utc),
        uploaded_by_id=current_user.id,
    )
    db.session.add(document)
    db.session.commit()

    return jsonify({"success": True, "document": document.to_json()})


@supporting_document_api.route("/api/supporting_documents/download")
@auth_required()
def download_supporting_document():
    document_id = request.args.get("id")
    if not document_id:
        return jsonify({"success": False, "error": gettext("Please provide a document ID")}), 400

    document = db.session.get(SupportingDocument, document_id)
    if not document:
        return jsonify({"success": False, "error": gettext("Document not found")}), 404

    return send_from_directory(
        supporting_documents_folder(),
        document.stored_filename,
        as_attachment=True,
        download_name=document.filename,
    )


@supporting_document_api.route("/api/supporting_documents", methods=["DELETE"])
@auth_required()
@roles_accepted("administrator")
def delete_supporting_document():
    document_id = request.args.get("id")
    if not document_id:
        return jsonify({"success": False, "error": gettext("Please provide a document ID")}), 400

    document = db.session.get(SupportingDocument, document_id)
    if not document:
        return jsonify({"success": False, "error": gettext("Document not found")}), 404

    try:
        os.remove(os.path.join(supporting_documents_folder(), document.stored_filename))
    except OSError:
        logger.warning(f"Supporting document file {document.stored_filename} was already missing on disk")

    db.session.delete(document)
    db.session.commit()

    return jsonify({"success": True})
