import os
import pathlib
import traceback

import bleach
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request, send_from_directory
from flask_babel import gettext
from flask_security import auth_required, current_user

from raven.blueprints.raven_api.api import paginate, search
from raven.audit import record_audit_event
from raven.extensions import db, logger
from raven.group_isolation import AUDIT_CATEGORY, can_see, filter_by_groups, resolve_group_names
from raven.models.VideoRecording import VideoRecording
from raven.models.VideoStream import VideoStream
from raven.recordings import contained_recording_path

video_api_blueprint = Blueprint("video_api_blueprint", __name__)


@video_api_blueprint.route("/api/videos/thumbnail", methods=["GET"])
@auth_required()
def thumbnail():
    path = request.args.get("path")
    recording = request.args.get("recording")
    if not path:
        return jsonify({"success": False, "error": "Please specify a path"}), 400

    # Normalise before the lookup: "redcam/" or "x/../redcam" used to miss the stream row (so
    # skip the group check) and still name the same folder on disk
    path = os.path.normpath(path.strip("/"))
    if path in ("", ".") or path == ".." or path.startswith("../") or os.path.isabs(path):
        return jsonify({"success": False, "error": gettext("Please specify a valid path")}), 400
    if recording is not None and (
        not recording or recording != os.path.basename(recording) or recording in (".", "..")
    ):
        return jsonify({"success": False, "error": gettext("Please specify a valid path")}), 400

    # The stream itself and any stream whose recordings folder this is inside of
    parts = path.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for video_stream in db.session.query(VideoStream).filter(VideoStream.path.in_(prefixes)):
        if not can_see(video_stream, current_user):
            return jsonify({"success": False, "error": gettext("Please specify a valid path")}), 400

    folder = os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "mediamtx", "recordings", path)
    if recording and os.path.exists(os.path.join(folder, recording + ".png")):
        return send_from_directory(folder, recording + ".png")

    elif os.path.exists(folder):
        return send_from_directory(folder, "thumbnail.png")

    return jsonify({"success": False, "error": gettext("Please specify a valid path")}), 400


@video_api_blueprint.route("/api/videos/recordings")
@auth_required()
def video_recordings():
    query = db.session.query(VideoRecording)
    query = search(query, VideoRecording, "path")
    # Recordings follow their stream's groups
    query = query.outerjoin(VideoStream, VideoRecording.path == VideoStream.path)
    query = filter_by_groups(query, VideoStream, current_user)

    return paginate(query, VideoRecording)


@video_api_blueprint.route("/api/videos/recording", methods=["GET", "DELETE", "HEAD"])
@auth_required()
def download_recording():
    if not request.args.get("id"):
        return jsonify({"success": False, "error": "Please specify a recording ID"}), 400
    recording_id = bleach.clean(request.args.get("id"))

    if recording_id.isdigit():
        recording_id = int(recording_id)
    else:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Invalid recording_id: %(recording_id)s", recording_id=recording_id
                    ),
                }
            ),
            400,
        )

    try:
        recording = db.session.execute(
            db.session.query(VideoRecording).filter(VideoRecording.id == recording_id)
        ).first()[0]
        if recording.video_stream is not None and not can_see(
            recording.video_stream, current_user
        ):
            return jsonify({"success": False, "error": gettext("Recording not found")}), 404

        if request.method == "GET":
            segment_path = contained_recording_path(recording.segment_path)
            if not segment_path:
                return jsonify({"success": False, "error": gettext("Recording not found")}), 404
            filename = pathlib.Path(segment_path)
            return send_from_directory(filename.parent, filename.name)
        elif request.method == "DELETE":
            # segment_path came from the MediaMTX webhook: never delete outside the
            # recordings folder
            segment_path = contained_recording_path(recording.segment_path)
            if segment_path and os.path.isfile(segment_path):
                os.remove(segment_path)
            elif recording.segment_path:
                logger.warning(f"Not deleting recording file {recording.segment_path!r}")
            db.session.delete(recording)
            db.session.commit()
            return jsonify({"success": True})
        elif request.method == "HEAD":
            return "", 200
    except:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": gettext("Recording not found")}), 404


@video_api_blueprint.route("/api/video_streams")
@auth_required()
def get_video_streams():
    query = db.session.query(VideoStream)
    query = search(query, VideoStream, "username")
    query = search(query, VideoStream, "protocol")
    query = search(query, VideoStream, "path")
    query = search(query, VideoStream, "uid")
    query = filter_by_groups(query, VideoStream, current_user)

    return paginate(query, VideoStream)


@video_api_blueprint.route("/api/video_streams/groups", methods=["PATCH"])
@auth_required()
def edit_video_stream_groups():
    """Sets which groups may see a video stream (and its recordings). An empty list makes it
    visible to everyone.

    :json: path, groups (list of group names)
    """
    if not current_user.has_role("administrator"):
        return jsonify({"success": False, "error": gettext("Administrator role required")}), 403

    body = request.get_json(silent=True) or {}
    path = body.get("path")
    names = body.get("groups")
    if not path or not isinstance(names, list):
        return (
            jsonify({"success": False, "error": gettext("Please provide a path and a list of groups")}),
            400,
        )

    video_stream = db.session.query(VideoStream).filter(VideoStream.path == path).first()
    if not video_stream:
        return jsonify({"success": False, "error": gettext("Path %(path)s not found", path=path)}), 404

    groups, missing = resolve_group_names(names)
    if missing:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Group not found: %(group_name)s", group_name=", ".join(missing)),
                }
            ),
            404,
        )

    before = video_stream.group_names
    video_stream.groups = groups
    db.session.commit()
    after = video_stream.group_names

    if before != after:
        record_audit_event(
            AUDIT_CATEGORY,
            "video_stream_groups_changed",
            actor=current_user.username,
            details=f"Video stream: {video_stream.path} · "
            f"Groups: {', '.join(before) or 'everyone'} -> {', '.join(after) or 'everyone'}",
        )

    return jsonify({"success": True, "groups": after})
