import datetime
import json
import os
import pathlib
import shlex
import traceback
import uuid
from urllib.parse import urlparse

import bleach
import requests
import sqlalchemy.exc
from ffmpeg import FFmpeg
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_ldap3_login import AuthenticationResponseStatus
from flask_security import auth_required, current_user, verify_password
from flask_security.utils import parse_auth_token
from sqlalchemy import update
from werkzeug.datastructures import ImmutableMultiDict

from raven.extensions import db, ldap_manager, logger
from raven.forms.MediaMTXPathConfig import MediaMTXPathConfig
from raven.models.VideoRecording import VideoRecording
from raven.models.VideoStream import VideoStream

mediamtx_api_blueprint = Blueprint("mediamtx_api_blueprint", __name__)


def get_stream_protocol(source_type):
    protocol = "rtsp"
    if source_type.startswith("rtsps"):
        protocol = "rtsps"
    if source_type.startswith("rtsp"):
        protocol = "rtsp"
    elif source_type == "hlsSource":
        protocol = "hls"
    elif source_type == "rpiCameraSource":
        protocol = "rpi_camera"
    elif source_type.startswith("rtmp"):
        protocol = "rtmp"
    elif source_type.startswith("srt"):
        protocol = "srt"
    elif source_type.startswith("udp"):
        protocol = "udp"
    elif source_type.startswith("webRTC"):
        protocol = "webrtc"

    return protocol


@mediamtx_api_blueprint.route("/api/mediamtx/webhook")
def mediamtx_webhook():
    token = request.args.get("token")
    if not token or bleach.clean(token) != app.config.get("RAVEN_MEDIAMTX_TOKEN"):
        logger.error("Invalid token")
        return jsonify({"success": False, "error": gettext("Invalid token")}), 401

    event = bleach.clean(request.args.get("event"))
    if event == "init":
        rtsp_port = bleach.clean(request.args.get("rtsp_port"))
        path = bleach.clean(request.args.get("path"))

        if path == "startup":
            paths = VideoStream.query.all()
            for path in paths:
                r = requests.post(
                    "{}/v3/config/paths/add/{}".format(
                        app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), path.path
                    ),
                    json=json.loads(path.mediamtx_settings),
                )
                logger.debug("Init added {} {}".format(path, r.status_code))

            # Get all paths from MediaMTX and make sure they're in Raven's database
            r = requests.get("{}/v3/paths/list".format(app.config.get("RAVEN_MEDIAMTX_API_ADDRESS")))
            paths = r.json()
            for path in paths["items"]:
                video_stream = (
                    db.session.query(VideoStream).where(VideoStream.path == path["name"]).first()
                )
                if not video_stream:
                    if not path["source"]:
                        continue
                    video_stream = VideoStream()
                    video_stream.protocol = get_stream_protocol(path["source"]["type"])

                    r = requests.get(
                        "{}/v3/config/global/get".format(app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"))
                    )
                    video_stream.port = r.json()["rtspAddress"].replace(":", "")

                    r = requests.get(
                        "{}/v3/config/paths/get/{}".format(
                            app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), path["name"]
                        )
                    )
                    video_stream.mediamtx_settings = json.dumps(r.json())

                    video_stream.path = path["name"]
                    video_stream.alias = path["name"]
                    video_stream.rtsp_reliable = 1
                    video_stream.ready = event == "ready"
                    video_stream.rover_port = -1
                    video_stream.ignore_embedded_klv = False
                    video_stream.buffer_time = None
                    video_stream.network_timeout = 10000
                    video_stream.uid = str(uuid.uuid4())
                    video_stream.generate_xml(urlparse(request.url_root).hostname)

                    db.session.add(video_stream)
                    db.session.commit()

    elif event == "connect":
        connection_type = bleach.clean(request.args.get("connection_type"))
        connection_id = bleach.clean(request.args.get("connection_id"))
        rtsp_port = bleach.clean(request.args.get("rtsp_port"))
    elif event == "ready" or event == "notready":
        rtsp_port = bleach.clean(request.args.get("rtsp_port"))
        path = bleach.clean(request.args.get("path"))
        query = bleach.clean(request.args.get("query"))
        source_type = bleach.clean(request.args.get("source_type"))
        source_id = bleach.clean(request.args.get("source_id"))

        video_stream = db.session.query(VideoStream).where(VideoStream.path == path).first()
        if video_stream:
            video_stream.ready = event == "ready"
            db.session.add(video_stream)
            db.session.commit()
            r = requests.patch(
                "{}/v3/config/paths/patch/{}".format(
                    app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), path
                ),
                json=json.loads(video_stream.mediamtx_settings),
            )
            logger.debug("Ready Patched path {}: {} - {}".format(path, r.status_code, r.text))
        else:
            video_stream = VideoStream()
            if source_type.startswith("rtsps"):
                video_stream.protocol = "rtsps"
            if source_type.startswith("rtsp"):
                video_stream.protocol = "rtsp"
            elif source_type == "hlsSource":
                video_stream.protocol = "hls"
            elif source_type == "rpiCameraSource":
                video_stream.protocol = "rpi_camera"
            elif source_type.startswith("rtmp"):
                video_stream.protocol = "rtmp"
            elif source_type.startswith("srt"):
                video_stream.protocol = "srt"
            elif source_type.startswith("udp"):
                video_stream.protocol = "udp"
            elif source_type.startswith("webRTC"):
                video_stream.protocol = "webrtc"

            # video_stream.query = query
            video_stream.port = rtsp_port
            video_stream.path = path
            video_stream.alias = path
            video_stream.rtsp_reliable = 1
            video_stream.ready = event == "ready"
            video_stream.rover_port = -1
            video_stream.ignore_embedded_klv = False
            video_stream.buffer_time = None
            video_stream.network_timeout = 10000
            video_stream.uid = str(uuid.uuid4())
            video_stream.generate_xml(urlparse(request.url_root).hostname)
            mediamtx_settings = MediaMTXPathConfig(None)
            mediamtx_settings.sourceOnDemand.data = source_id is not None
            mediamtx_settings.record.data = False
            video_stream.mediamtx_settings = json.dumps(mediamtx_settings.serialize())

            db.session.add(video_stream)
            db.session.commit()

        if event == "ready":
            os.makedirs(
                os.path.join(
                    app.config.get("RAVEN_DATA_FOLDER"), "mediamtx", "recordings", video_stream.path
                ),
                exist_ok=True,
            )

            try:
                (
                    FFmpeg()
                    .input(video_stream.to_json()["rtsp_link"] + "?token={}".format(token))
                    .option("y")
                    .output(
                        os.path.join(
                            app.config.get("RAVEN_DATA_FOLDER"),
                            "mediamtx",
                            "recordings",
                            video_stream.path,
                            "thumbnail.png",
                        ),
                        {"frames:v": 1},
                    )
                    .execute()
                )
            except BaseException as e:
                logger.error(f"Failed to create thumbnail: {e}")
                logger.debug(traceback.format_exc())

    elif event == "read":
        rtsp_port = bleach.clean(request.args.get("rtsp_port"))
        path = bleach.clean(request.args.get("path"))
        query = bleach.clean(request.args.get("query"))
        reader_type = bleach.clean(request.args.get("reader_type"))
        reader_id = bleach.clean(request.args.get("reader_id"))
    elif event == "disconnect":
        connection_type = bleach.clean(request.args.get("connection_type"))
        connection_id = bleach.clean(request.args.get("connection_id"))
        rtsp_port = bleach.clean(request.args.get("rtsp_port"))
    elif event == "segment_record":
        recording = VideoRecording()
        recording.segment_path = bleach.clean(request.args.get("segment_path"))
        recording.path = bleach.clean(request.args.get("path"))
        recording.in_progress = True
        recording.start_time = datetime.datetime.now(datetime.timezone.utc)

        with app.app_context():
            try:
                db.session.add(recording)
                db.session.commit()
            except sqlalchemy.exc.IntegrityError:
                db.session.rollback()
                db.session.execute(
                    update(VideoRecording)
                    .filter(VideoRecording.segment_path == recording.segment_path)
                    .values(**recording.serialize())
                )
                db.session.commit()
    elif event == "segment_record_complete":
        segment_path = bleach.clean(request.args.get("segment_path"))
        with app.app_context():
            recording = db.session.execute(
                db.session.query(VideoRecording).filter(VideoRecording.segment_path == segment_path)
            ).first()
            if recording and recording.count:
                recording = recording[0]
                recording.in_progress = False
                recording.stop_time = datetime.datetime.now(datetime.timezone.utc)
                recording.duration = (
                    recording.stop_time - recording.start_time.replace(tzinfo=datetime.timezone.utc)
                ).seconds
            else:
                recording = VideoRecording()
                recording.segment_path = bleach.clean(request.args.get("segment_path"))
                recording.path = bleach.clean(request.args.get("path"))
                recording.in_progress = False
                recording.stop_time = datetime.datetime.now(datetime.timezone.utc)

            try:
                probe = json.loads(
                    FFmpeg(executable="ffprobe")
                    .input(
                        recording.segment_path,
                        print_format="json",
                        show_streams=None,
                        show_format=None,
                    )
                    .execute()
                )
                for stream in probe["streams"]:
                    if stream["codec_type"].lower() == "video":
                        recording.width = stream["width"]
                        recording.height = stream["height"]
                        recording.video_bitrate = stream["bit_rate"]
                        recording.video_codec = stream["codec_name"]
                        FFmpeg().input(recording.segment_path, ss="00:00:01").option("y").output(
                            recording.segment_path + ".png", {"frames:v": 1}
                        ).execute()
                    elif stream["codec_type"].lower() == "audio":
                        recording.audio_codec = stream["codec_name"]
                        recording.audio_samplerate = stream["sample_rate"]
                        recording.audio_channels = stream["channels"]
                        recording.audio_bitrate = stream["bit_rate"]
                if "format" in probe and "size" in probe["format"]:
                    recording.file_size = probe["format"]["size"]
            except BaseException as e:
                logger.error(f"Failed to run ffprobe: {e}")
                logger.debug(traceback.format_exc())

            db.session.add(recording)
            db.session.commit()
        pass

    return "", 200


@mediamtx_api_blueprint.route("/api/mediamtx/stream/add", methods=["POST"])
@mediamtx_api_blueprint.route("/api/mediamtx/stream/update", methods=["PATCH"])
@auth_required()
def add_update_stream():
    try:
        form = MediaMTXPathConfig(formdata=ImmutableMultiDict(request.json))
        if not form.validate():
            return jsonify({"success": False, "errors": form.errors}), 400

        path = bleach.clean(request.json.get("path", ""))

        if not path:
            return jsonify({"success": False, "error": gettext("Please specify a path name")}), 400

        if path.startswith("/"):
            return (
                jsonify({"success": False, "error": gettext("Path cannot begin with a slash")}),
                400,
            )

        video = db.session.query(VideoStream).where(VideoStream.path == path).first()
        if not video and request.path.endswith("add"):
            video = VideoStream()
            video.path = path
            # Set before generate_xml() so the <uid> in the stored XML matches
            # the row (the column default only fires at INSERT time).
            video.uid = str(uuid.uuid4())
            video.username = current_user.username
            video.mediamtx_settings = json.dumps(form.serialize())
            video.rover_port = -1
            video.ignore_embedded_klv = False
            video.buffer_time = None
            video.rtsp_reliable = 1
            video.network_timeout = 10000
            video.generate_xml(urlparse(request.url_root).hostname)
        elif not video and request.path.endswith("update"):
            return (
                jsonify({"success": False, "error": gettext("Path %(path)s not found", path=path)}),
                400,
            )

        settings = json.loads(video.mediamtx_settings)

        for setting in request.json:
            if setting == "csrf_token" or setting == "sourceOnDemand" or setting == "path":
                continue

            # When the source URL is blank set sourceOnDemand to false in order to avoid a MediaMTX error
            if setting == "source":
                source = request.json.get(setting)
                if not source:
                    settings["sourceOnDemand"] = False
                # Run ffmpeg and yt-dlp for live YouTube videos
                elif urlparse(source).hostname in (
                    "youtube.com",
                    "www.youtube.com",
                    "youtu.be",
                    "m.youtube.com",
                ):
                    settings["source"] = None
                    settings["sourceOnDemand"] = False
                    yt_dlp_path = os.path.join(
                        pathlib.Path.home(), ".raven_venv", "bin", "yt-dlp"
                    )
                    # `source` reaches here from any logged-in user's request
                    # body (this route only requires @auth_required, not an
                    # admin role), and MediaMTX runs this whole string through
                    # its own shell (runOnDemand) -- it doesn't need an "sh -c"
                    # wrapper of our own (compare runOnConnect etc. in
                    # mediamtx.yml, which are plain commands). Previously the
                    # "youtube.com" substring check didn't validate the URL's
                    # actual host, and the value was interpolated into the
                    # shell command with no escaping at all, so a crafted
                    # "source" value was arbitrary command execution as
                    # whatever user MediaMTX runs as. shlex.quote makes each
                    # value inert regardless of its contents, and the hostname
                    # check above closes the substring-match bypass that let a
                    # non-YouTube URL reach this branch at all. (A first pass
                    # at this fix kept the redundant outer sh -c '...' wrapper,
                    # whose own single quotes collided with shlex.quote's and
                    # reopened the same injection -- confirmed by actually
                    # running the constructed command, not just by inspection,
                    # before landing this version.)
                    settings["runOnDemand"] = (
                        f'ffmpeg -re -i "$({shlex.quote(yt_dlp_path)} -g {shlex.quote(source)})" -c:v copy -f rtsp rtsp://127.0.0.1:8554/$RTSP_PATH'
                    )
                continue

            key = bleach.clean(setting)
            value = request.json.get(setting)
            if isinstance(value, str):
                value = bleach.clean(value)
            if value is not None:
                settings[key] = value
                logger.debug("set {} to {}".format(key, value))

        if request.path.endswith("update"):
            r = requests.patch(
                "{}/v3/config/paths/patch/{}".format(
                    app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), path
                ),
                json=settings,
            )
        else:
            r = requests.post(
                "{}/v3/config/paths/add/{}".format(
                    app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), path
                ),
                json=settings,
            )

        if r.status_code == 200:
            logger.debug("Patched path {}: {}".format(path, r.status_code))
            video.mediamtx_settings = json.dumps(settings)
            db.session.add(video)
            db.session.commit()
            return jsonify({"success": True})

        else:
            action = "add" if request.path.endswith("add") else "update"
            logger.error(
                "Failed to {} mediamtx path: {} - {}".format(
                    action, r.status_code, r.json()["error"]
                )
            )
            return jsonify({"success": False, "error": r.json()["error"]}), 400
    except BaseException as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@mediamtx_api_blueprint.route("/api/mediamtx/stream/delete", methods=["DELETE"])
@auth_required()
def delete_stream():
    try:
        path = bleach.clean(request.args.get("path", ""))

        if not path:
            return jsonify({"success": False, "error": gettext("Please specify a path name")}), 400

        video = db.session.query(VideoStream).filter(VideoStream.path == path).first()
        if not video:
            return (
                jsonify({"success": False, "error": gettext("Path %(path)s not found", path=path)}),
                400,
            )

        r = requests.delete(
            "{}/v3/config/paths/delete/{}".format(app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), path)
        )
        logger.debug("Delete status code: {}".format(r.status_code))

        # video_recordings.path is a foreign key into video_streams.path with
        # no cascade, so a stream with recordings has to have those rows (and
        # their files) cleared out first or the delete below raises a
        # ForeignKeyViolation.
        for recording in db.session.query(VideoRecording).filter(VideoRecording.path == path):
            try:
                os.remove(recording.segment_path)
            except OSError:
                pass
            db.session.delete(recording)

        db.session.delete(video)
        db.session.commit()
    except requests.exceptions.ConnectionError as e:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": gettext("MediaMTX is not running")}), 500

    if r.status_code != 404:
        return r.text, r.status_code
    else:
        return "", 200


# This is mainly for mediamtx authentication
@mediamtx_api_blueprint.route("/api/external_auth", methods=["POST"])
def external_auth():
    # This route is meant to be called only by MediaMTX itself (its
    # authHTTPAddress webhook, direct localhost-to-localhost) -- it exists to
    # decide whether *MediaMTX* should let a connection through, not to be a
    # public endpoint in its own right. Without this check it was reachable
    # directly by anyone at https://<host>/api/external_auth, completely
    # bypassing MediaMTX, and would run the same user/password verification
    # below against real accounts -- an unauthenticated, unlimited password
    # oracle. nginx always sets X-Forwarded-For on every request it proxies,
    # which a genuinely direct call from MediaMTX never has, so its presence
    # means this didn't actually come from MediaMTX and must be rejected.
    if request.headers.get("X-Forwarded-For"):
        return "", 401

    username = bleach.clean(request.json.get("user"))
    password = bleach.clean(request.json.get("password"))
    action = bleach.clean(request.json.get("action"))
    query = bleach.clean(request.json.get("query"))
    ip = bleach.clean(request.json.get("ip"))
    protocol = bleach.clean(request.json.get("protocol"))

    # Whitelist 127.0.0.1 to make things like YouTube video re-streaming work
    # (a local ffmpeg process publishing into MediaMTX on the server's own
    # behalf). Scoped to publish only -- nginx's own connections to MediaMTX
    # also come from 127.0.0.1, so without this restriction every public
    # HLS/WebRTC *read* proxied through nginx (i.e. every real viewer) would
    # match this too and skip the jwt/token check entirely, making a video's
    # plain URL viewable by anyone who can reach the domain, logged in or
    # not.
    if action == "publish" and ip and ip in app.config.get("RAVEN_IP_WHITELIST"):
        return "", 200

    # ATAK/WinTAK video feeds are plain <feed> XML (see VideoStream.generate_xml)
    # with no username/password fields at all, so a TAK client's RTSP DESCRIBE
    # never carries credentials -- it would always hit the 401 fallback below.
    # Publishing still goes through the same webhook with action=publish, so
    # this only opens up *watching* an existing feed over RTSP, not creating
    # one; HLS/WebRTC reads keep requiring the jwt/token query param below.
    if action == "read" and protocol == "rtsp":
        return "", 200

    # Token auth to prevent high CPU usage when reading HLS streams
    if "jwt" in query or "token" in query:
        query = query.split("&")
        for q in query:
            if "=" not in q:
                continue
            key, value = q.split("=")
            if key == "jwt":
                try:
                    parse_auth_token(value)
                    return "", 200
                except BaseException as e:
                    logger.error(f"Invalid token: {e}")
                    return "", 401
            elif key == "token":
                if value == app.config.get("RAVEN_MEDIAMTX_TOKEN"):
                    return "", 200
                else:
                    return "", 401

    auth_success = False

    # LDAP Auth
    if app.config.get("RAVEN_ENABLE_LDAP"):
        result = ldap_manager.authenticate(username, password)
        if result.status == AuthenticationResponseStatus.success:
            # Keep this import here to avoid a circular import when Raven is started
            from raven.blueprints.raven_api.ldap_api import save_user

            save_user(result.user_dn, result.user_id, result.user_info, result.user_groups)
            auth_success = True
        else:
            return "", 401
    # Flask-Security auth
    else:
        user = app.security.datastore.find_user(username=username)
        if not user:
            return "", 401
        if not verify_password(password, user.password):
            return "", 401
        auth_success = True

    if auth_success:
        if action == "publish":
            logger.debug("Publish {}".format(request.json.get("path")))
            v = VideoStream()
            v.uid = bleach.clean(request.json.get("id")) if request.json.get("id") else None
            v.rover_port = -1
            v.ignore_embedded_klv = False
            v.buffer_time = None
            v.network_timeout = 10000
            v.protocol = bleach.clean(request.json.get("protocol"))
            v.path = bleach.clean(request.json.get("path"))
            v.alias = v.path.split("/")[-1]
            v.username = bleach.clean(request.json.get("user"))
            path_config = MediaMTXPathConfig(None).serialize()
            path_config["sourceOnDemand"] = False
            v.mediamtx_settings = json.dumps(path_config)

            # `port` is the port TAK clients use to *view* the stream over
            # RTSP -- MediaMTX always re-serves every ingested stream over
            # RTSP on its one fixed port (rtspAddress in mediamtx.yml, 8554
            # by default) regardless of what protocol it was published with,
            # same as the "init"/"ready" webhook handlers above already
            # assume. An RTMP publish previously got 1935 (its own ingest
            # port) here instead, which isn't an RTSP port at all -- WinTAK
            # would fail with a fatal media error trying to open it.
            if v.protocol == "rtsp":
                v.port = 8554
                v.rtsp_reliable = 1
            elif v.protocol == "rtmp":
                v.port = 8554
                v.rtsp_reliable = 1
            else:
                v.rtsp_reliable = 0

            v.generate_xml(request.json.get("ip"))

            with app.app_context():
                try:

                    db.session.add(v)
                    db.session.commit()
                    r = requests.post(
                        "{}/v3/config/paths/add/{}".format(
                            app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), v.path
                        ),
                        json=path_config,
                    )
                    if r.status_code == 200:
                        logger.debug("Added path {} to mediamtx".format(v.path))
                    else:
                        logger.error(
                            "Failed to add path {} to mediamtx. Status code {} {}".format(
                                v.path, r.status_code, r.text
                            )
                        )
                    logger.debug("Inserted video stream {}".format(v.uid))
                except sqlalchemy.exc.IntegrityError as e:
                    try:
                        db.session.rollback()
                        video = (
                            db.session.query(VideoStream).filter(VideoStream.path == v.path).first()
                        )
                        r = requests.post(
                            "{}/v3/config/paths/add/{}".format(
                                app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), v.path
                            ),
                            json=json.loads(video.mediamtx_settings),
                        )
                        if r.status_code == 200:
                            logger.debug("Added path {} to mediamtx".format(v.path))
                        else:
                            logger.error(
                                "Failed to add path {} to mediamtx. Status code {} {}".format(
                                    v.path, r.status_code, r.text
                                )
                            )
                    except:
                        logger.error(traceback.format_exc())

        logger.debug("external_auth returning 200")
        return "", 200
    elif query:
        for arg in query.split("&"):
            key, value = arg.split("=")
            if key == "token" and value == app.config.get("RAVEN_MEDIAMTX_TOKEN"):
                return "", 200
    else:
        logger.debug("external_auth returning 401")
        return "", 401
