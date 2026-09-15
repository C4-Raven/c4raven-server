import json
import traceback
import uuid
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, fromstring, tostring

import requests
import sqlalchemy
from bs4 import BeautifulSoup
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from OpenSSL import crypto
from werkzeug.datastructures import ImmutableMultiDict

from raven import __version__ as version
from raven.blueprints.marti_api.marti_api import verify_client_cert
from raven.extensions import db, logger
from raven.forms.MediaMTXPathConfig import MediaMTXPathConfig
from raven.functions import iso8601_string_from_datetime
from raven.models.EUD import EUD
from raven.models.user import User
from raven.models.VideoRecording import VideoRecording
from raven.models.VideoStream import VideoStream

video_marti_api = Blueprint("video_marti_api", __name__)


@video_marti_api.route("/Marti/vcm", methods=["GET", "POST"])
def video():
    if request.method == "POST":
        soup = BeautifulSoup(request.data, "xml")
        video_connections = soup.find("videoConnections")
        if not video_connections or not video_connections.find("path"):
            return jsonify({"success": False, "error": gettext("Invalid video connection")}), 400

        path = video_connections.find("path").text or ""
        if path.startswith("/"):
            path = path[1:]

        if video_connections:
            v = VideoStream()
            v.protocol = video_connections.find("protocol").text
            v.alias = video_connections.find("alias").text
            v.uid = video_connections.find("uid").text
            v.port = video_connections.find("port").text
            v.rover_port = video_connections.find("roverPort").text
            v.ignore_embedded_klv = (
                video_connections.find("ignoreEmbeddedKLV").text.lower() == "true"
            )
            v.preferred_mac_address = video_connections.find("preferredMacAddress").text
            v.preferred_interface_address = video_connections.find("preferredInterfaceAddress").text
            v.path = path
            v.buffer_time = video_connections.find("buffer").text
            v.network_timeout = video_connections.find("timeout").text
            v.rtsp_reliable = video_connections.find("rtspReliable").text
            path_config = MediaMTXPathConfig(None).serialize()
            path_config["sourceOnDemand"] = False
            v.mediamtx_settings = json.dumps(path_config)

            # Discard username and password for security
            feed = soup.find("feed")
            address = feed.find("address").text
            feed.find("address").string.replace_with(address.split("@")[-1])

            v.xml = str(feed)

            with app.app_context():
                try:
                    db.session.add(v)
                    db.session.commit()
                    logger.debug("Inserted Video")
                except sqlalchemy.exc.IntegrityError as e:
                    db.session.rollback()
                    v = db.session.execute(
                        db.select(VideoStream).filter_by(path=v.path)
                    ).scalar_one()
                    v.protocol = video_connections.find("protocol").text
                    v.alias = video_connections.find("alias").text
                    v.uid = video_connections.find("uid").text
                    v.port = video_connections.find("port").text
                    v.rover_port = video_connections.find("roverPort").text
                    v.ignore_embedded_klv = (
                        video_connections.find("ignoreEmbeddedKLV").text.lower() == "true"
                    )
                    v.preferred_mac_address = video_connections.find("preferredMacAddress").text
                    v.preferred_interface_address = video_connections.find(
                        "preferredInterfaceAddress"
                    ).text
                    v.path = video_connections.find("path").text
                    v.buffer_time = video_connections.find("buffer").text
                    v.network_timeout = video_connections.find("timeout").text
                    v.rtsp_reliable = video_connections.find("rtspReliable").text
                    feed = soup.find("feed")
                    address = feed.find("address").text
                    feed.find("address").replace_with(address.split("@")[-1])

                    v.xml = str(feed)

                    db.session.commit()
                    logger.debug("Updated video")

        return "", 200

    elif request.method == "GET":
        try:
            with app.app_context():
                videos = db.session.execute(db.select(VideoStream)).scalars()
                videoconnections = Element("videoConnections")

                for video in videos:
                    # Make sure videos have the correct address based off of the Flask request and not 127.0.0.1
                    # This also forces all streams to bounce through MediaMTX
                    feed = BeautifulSoup(video.xml, "xml")

                    url = urlparse(request.url_root).hostname
                    path = feed.find("path").text
                    if not path.startswith("/"):
                        path = "/" + path

                    if "iTAK" in request.user_agent.string:
                        url = (
                            feed.find("protocol").text
                            + "://"
                            + url
                            + ":"
                            + feed.find("port").text
                            + path
                        )

                    if feed.find("address"):
                        feed.find("address").string.replace_with(url)
                    else:
                        address = feed.new_tag("address")
                        address.string = url
                        feed.feed.append(address)
                    videoconnections.append(fromstring(str(feed)))

            return tostring(videoconnections), 200
        except BaseException as e:
            logger.error(traceback.format_exc())
            return "", 500


@video_marti_api.route("/Marti/api/video")
def get_videos():
    cert = verify_client_cert()
    if not cert:
        # Shouldn't ever get here since nginx already verifies the cert
        return jsonify({"success": False, "error": gettext("Invalid Certificate")}), 400
    username = None
    for a in cert.get_subject().get_components():
        if a[0].decode("UTF-8") == "CN":
            username = a[1].decode("UTF-8")
            break

    user = app.security.datastore.find_user(username=username)
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s not found", username=username),
                }
            ),
            401,
        )
    videos = db.session.execute(db.select(VideoStream)).scalars()

    video_connections = {"videoConnections": []}
    for video in videos:
        video_connections["videoConnections"].append(video.to_marti_json(user))

    return jsonify(video_connections)


@video_marti_api.route("/Marti/api/video", methods=["POST"])
def add_video():
    cert = verify_client_cert()
    if not cert:
        return jsonify({"success": False, "error": gettext("Invalid Certificate")}), 400
    username = None
    for a in cert.get_subject().get_components():
        if a[0].decode("UTF-8") == "CN":
            username = a[1].decode("UTF-8")
            break

    videos = request.json or {}

    for video in videos.get("videoConnections") or []:
        for feed in video.get("feeds") or []:
            source = feed.get("url") or ""
            alias = feed.get("alias") or video.get("alias") or ""
            feed_uid = feed.get("uuid") or video.get("uuid")

            # Clients re-post the list they were given (carrying the uuid we
            # issued), so resolve by uid first and only then treat the alias
            # as a new MediaMTX path. Previously every POST was a blind INSERT
            # keyed on the alias, so re-posting an existing feed 500'd on the
            # primary key and nothing was ever updated.
            video_stream = None
            if feed_uid:
                video_stream = (
                    db.session.execute(db.select(VideoStream).filter_by(uid=feed_uid))
                    .scalars()
                    .first()
                )
            if not video_stream and alias:
                video_stream = (
                    db.session.execute(db.select(VideoStream).filter_by(path=alias.lstrip("/")))
                    .scalars()
                    .first()
                )

            if video_stream:
                if alias:
                    video_stream.alias = alias
                db.session.commit()
                continue

            path = alias.lstrip("/")
            if not path:
                continue

            data = ImmutableMultiDict({"path": path, "source": source})
            mediamtx_config = MediaMTXPathConfig(formdata=data, csrf_enabled=False).serialize()
            # MediaMTX rejects sourceOnDemand without a source (a feed the
            # client intends to publish into rather than have us pull)
            if not source:
                mediamtx_config["sourceOnDemand"] = False

            scheme = urlparse(source).scheme
            video_stream = VideoStream()
            video_stream.path = path
            video_stream.alias = alias
            video_stream.uid = feed_uid or str(uuid.uuid4())
            video_stream.protocol = "hls" if scheme in ("http", "https") else (scheme or "rtsp")
            video_stream.mediamtx_settings = json.dumps(mediamtx_config)
            video_stream.username = username
            video_stream.rover_port = -1
            video_stream.ignore_embedded_klv = False
            video_stream.buffer_time = None
            video_stream.rtsp_reliable = 1
            video_stream.network_timeout = 10000
            video_stream.generate_xml(urlparse(request.url_root).hostname)
            db.session.add(video_stream)
            db.session.commit()

            # Register the path with MediaMTX now. Previously the row was only
            # written to the database and MediaMTX learned of it on its next
            # restart (the "startup" webhook), so a client-added feed couldn't
            # be watched through the server until then.
            try:
                r = requests.post(
                    "{}/v3/config/paths/add/{}".format(
                        app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), path
                    ),
                    json=mediamtx_config,
                )
                if r.status_code != 200:
                    logger.error(
                        "Failed to add path {} to mediamtx. Status code {} {}".format(
                            path, r.status_code, r.text
                        )
                    )
            except requests.exceptions.RequestException:
                logger.error(traceback.format_exc())

    return "", 200


@video_marti_api.route("/Marti/api/video/<uid>")
def get_video(uid):
    cert = verify_client_cert()
    username = None
    for a in cert.get_subject().get_components():
        if a[0].decode("UTF-8") == "CN":
            username = a[1].decode("UTF-8")
            break

    video = db.session.execute(db.select(VideoStream).filter_by(uid=uid)).scalars().first()
    if not video:
        return jsonify({"success": False, "error": gettext("Video not found")}), 404
    user = db.session.execute(db.session.query(User).filter_by(username=username)).first()
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s not found", username=username),
                }
            ),
            401,
        )
    user = user[0]
    return video.to_marti_json(user), 200


@video_marti_api.route("/Marti/api/video/<uid>", methods=["DELETE"])
def delete_video(uid):
    cert = verify_client_cert()
    if not cert:
        return jsonify({"success": False, "error": gettext("Invalid Certificate")}), 400

    # The old code tested the raw Result object for truthiness (always True)
    # and then indexed it, so a real uid raised TypeError (500) and an unknown
    # uid never reached the 404 branch.
    video_stream = db.session.execute(db.select(VideoStream).filter_by(uid=uid)).scalars().first()
    if not video_stream:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Video stream with uid %(uid)s not found", uid=uid),
                }
            ),
            404,
        )

    try:
        requests.delete(
            "{}/v3/config/paths/delete/{}".format(
                app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"), video_stream.path
            )
        )
    except requests.exceptions.RequestException:
        logger.error(traceback.format_exc())

    # video_recordings.path -> video_streams.path has no cascade, so the
    # recording rows have to go first or this raises a ForeignKeyViolation.
    # The files themselves are deliberately left on disk: this is a TAK
    # client removing a feed from its list, not an admin purging recordings.
    for recording in db.session.execute(
        db.select(VideoRecording).filter_by(path=video_stream.path)
    ).scalars():
        db.session.delete(recording)

    db.session.delete(video_stream)
    db.session.commit()

    return "", 200
