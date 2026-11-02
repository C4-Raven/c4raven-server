import datetime
import json
from xml.etree.ElementTree import tostring

import pika
import requests
from flask import Blueprint
from flask import current_app as app
from sqlalchemy import delete, func, text, update

from raven.extensions import apscheduler, db, logger
from raven.functions import (
    datetime_from_iso8601_string,
    generate_delete_cot,
    iso8601_string_from_datetime,
)
from raven.models.Alert import Alert
from raven.models.CasEvac import CasEvac
from raven.models.Certificate import Certificate
from raven.models.Chatrooms import Chatroom
from raven.models.ChatroomsUids import ChatroomsUids
from raven.models.CoT import CoT
from raven.models.DataPackage import DataPackage
from raven.models.EUD import EUD
from raven.models.GeoChat import GeoChat
from raven.models.Group import Group
from raven.models.Marker import Marker
from raven.models.Mission import Mission
from raven.models.MissionChange import MissionChange
from raven.models.MissionContentMission import MissionContentMission
from raven.models.MissionInvitation import MissionInvitation
from raven.models.MissionRole import MissionRole
from raven.models.MissionUID import MissionUID
from raven.models.Point import Point
from raven.models.RBLine import RBLine
from raven.models.Team import Team
from raven.models.VideoRecording import VideoRecording
from raven.models.VideoStream import VideoStream
from raven.models.ZMIST import ZMIST

scheduler_blueprint = Blueprint("scheduler_blueprint", __name__)


def delete_video_recordings():
    with apscheduler.app.app_context():
        VideoRecording.query.delete()
        db.session.commit()

        try:
            r = requests.get(
                "{}/v3/recordings/list".format(app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"))
            )
            if r.status_code == 200:
                recordings = r.json()
                for path in recordings["items"]:
                    for recording in path["segments"]:
                        r = requests.delete(
                            "{}/v3/recordings/deletesegment".format(
                                app.config.get("RAVEN_MEDIAMTX_API_ADDRESS"),
                            ),
                            params={"start": recording["start"], "path": path["name"]},
                        )
                        if r.status_code != 200:
                            logger.error(
                                "Failed to delete {} from {}: {}".format(
                                    recording["start"], path["name"], r.text
                                )
                            )
        except BaseException as e:
            logger.error("Failed to delete recordings: {}".format(e))


def purge_data():
    # These are in a specific order to properly handle foreign key relationships
    delete_video_recordings()
    ZMIST.query.delete()
    VideoStream.query.delete()
    Alert.query.delete()
    CasEvac.query.delete()
    Certificate.query.delete()
    ChatroomsUids.query.delete()
    DataPackage.query.delete()
    Marker.query.delete()
    GeoChat.query.delete()
    Point.query.delete()
    RBLine.query.delete()
    Chatroom.query.delete()
    CoT.query.delete()
    MissionRole.query.delete()
    MissionContentMission.query.delete()
    MissionUID.query.delete()
    MissionChange.query.delete()
    Mission.query.delete()
    EUD.query.delete()
    Team.query.delete()
    db.session.commit()
    logger.info("Purged all data")


def reconcile_eud_status():
    # Backstop for the status bar: an EUD is only ever moved out of
    # "Connected" by its eud_handler thread publishing a disconnect (a
    # clean close, a keepalive-detected dead peer) or by the reconciliation
    # that runs when eud_handler itself restarts. Anything that kills that
    # thread without going through either path -- a RabbitMQ hiccup, an
    # unhandled exception mid-CoT-processing -- leaves the row stuck
    # "Connected" forever with no other code path to ever correct it. If a
    # "Connected" EUD hasn't been heard from in a while, it isn't connected.
    with apscheduler.app.app_context():
        # last_event_time is a naive "timestamp without time zone" column,
        # but it's written from tz-aware Python datetimes -- the driver
        # silently converts those to the DB session's timezone before
        # stripping tzinfo (this DB's session timezone is Australia/
        # Brisbane, UTC+10, so the column actually holds local wall-clock
        # values, not UTC). Comparing against a Python-computed UTC cutoff
        # was off by that same offset and never matched anything. Doing the
        # cutoff with the database's own now() instead keeps this correct
        # regardless of what the session timezone is or ever changes to,
        # since it goes through the identical conversion the writes did.
        db.session.execute(
            update(EUD)
            .where(EUD.last_status == "Connected")
            .where(EUD.last_event_time <= func.now() - text("interval '3 minutes'"))
            .values(last_status="Disconnected")
        )
        db.session.commit()


def delete_old_data():
    with apscheduler.app.app_context():
        timestamp = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            seconds=app.config.get("RAVEN_DELETE_OLD_DATA_SECONDS"),
            minutes=app.config.get("RAVEN_DELETE_OLD_DATA_MINUTES"),
            hours=app.config.get("RAVEN_DELETE_OLD_DATA_HOURS"),
            days=app.config.get("RAVEN_DELETE_OLD_DATA_DAYS"),
            weeks=app.config.get("RAVEN_DELETE_OLD_DATA_WEEKS"),
        )

        rabbit_credentials = pika.PlainCredentials(
            app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
        )
        rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
        rabbit_connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
        )
        channel = rabbit_connection.channel()

        # I wish I hadn't made the marker's timestamp field a string...
        markers = db.session.execute(db.session.query(Marker)).all()
        groups = db.session.execute(db.session.query(Group)).scalars()
        for marker in markers:
            marker = marker[0]
            if datetime_from_iso8601_string(marker.production_time) <= timestamp:
                cot = generate_delete_cot(marker.uid, marker.cot.type)
                for group in groups:
                    channel.basic_publish(
                        exchange="groups",
                        routing_key=f"{group.name}.{Group.OUT}",
                        body=json.dumps(
                            {"cot": tostring(cot).decode("utf-8"), "uid": app.config["RAVEN_NODE_ID"]}
                        ),
                        properties=pika.BasicProperties(
                            expiration=app.config.get("RAVEN_RABBITMQ_TTL")
                        ),
                    )
                    channel.basic_publish(
                        exchange="firehose",
                        routing_key="",
                        body=json.dumps(
                            {"cot": tostring(cot).decode("utf-8"), "uid": app.config["RAVEN_NODE_ID"]}
                        ),
                        properties=pika.BasicProperties(
                            expiration=app.config.get("RAVEN_RABBITMQ_TTL")
                        ),
                    )
                db.session.delete(marker)

        alerts = db.session.execute(
            db.session.query(Alert).where(Alert.start_time <= timestamp)
        ).all()
        for alert in alerts:
            alert = alert[0]
            cot = generate_delete_cot(alert.uid, alert.cot.type)
            for group in groups:
                channel.basic_publish(
                    exchange="groups",
                    routing_key=f"{group.name}.{Group.OUT}",
                    body=json.dumps(
                        {"cot": tostring(cot).decode("utf-8"), "uid": app.config["RAVEN_NODE_ID"]}
                    ),
                    properties=pika.BasicProperties(expiration=app.config.get("RAVEN_RABBITMQ_TTL")),
                )
                channel.basic_publish(
                    exchange="firehose",
                    routing_key="",
                    body=json.dumps(
                        {"cot": tostring(cot).decode("utf-8"), "uid": app.config["RAVEN_NODE_ID"]}
                    ),
                    properties=pika.BasicProperties(expiration=app.config.get("RAVEN_RABBITMQ_TTL")),
                )
            db.session.delete(alert)

        rb_lines = db.session.execute(
            db.session.query(RBLine).where(RBLine.timestamp <= timestamp)
        ).all()
        for rb_line in rb_lines:
            rb_line = rb_line[0]
            cot = generate_delete_cot(rb_line.uid, rb_line.cot.type)
            for group in groups:
                channel.basic_publish(
                    exchange="groups",
                    routing_key=f"{group.name}.{Group.OUT}",
                    body=json.dumps(
                        {"cot": tostring(cot).decode("utf-8"), "uid": app.config["RAVEN_NODE_ID"]}
                    ),
                    properties=pika.BasicProperties(expiration=app.config.get("RAVEN_RABBITMQ_TTL")),
                )
                channel.basic_publish(
                    exchange="firehose",
                    routing_key="",
                    body=json.dumps(
                        {"cot": tostring(cot).decode("utf-8"), "uid": app.config["RAVEN_NODE_ID"]}
                    ),
                    properties=pika.BasicProperties(expiration=app.config.get("RAVEN_RABBITMQ_TTL")),
                )
            db.session.delete(rb_line)

        db.session.execute(delete(GeoChat).where(GeoChat.timestamp <= timestamp))

        timestamp = datetime.datetime.now() - datetime.timedelta(
            seconds=app.config.get("RAVEN_DELETE_OLD_DATA_SECONDS"),
            minutes=app.config.get("RAVEN_DELETE_OLD_DATA_MINUTES"),
            hours=app.config.get("RAVEN_DELETE_OLD_DATA_HOURS"),
            days=app.config.get("RAVEN_DELETE_OLD_DATA_DAYS"),
            weeks=app.config.get("RAVEN_DELETE_OLD_DATA_WEEKS"),
        )

        db.session.execute(delete(MissionRole).where(MissionRole.createTime <= timestamp))
        db.session.execute(delete(MissionUID).where(MissionUID.timestamp <= timestamp))
        db.session.execute(delete(MissionChange).where(MissionChange.timestamp <= timestamp))
        db.session.execute(delete(EUD).where(EUD.last_event_time <= timestamp))
        db.session.execute(delete(Point).where(Point.timestamp <= timestamp))
        db.session.execute(delete(CoT).where(CoT.timestamp <= timestamp))
        db.session.commit()

        channel.close()
        rabbit_connection.close()

        logger.info(f"Deleted data older than {iso8601_string_from_datetime(timestamp)}")


def expire_group_memberships():
    # Removes group memberships whose expiry (set per member on the Groups
    # page, or from the group's default membership duration) has passed.
    from raven.group_policy import expire_memberships

    with apscheduler.app.app_context():
        try:
            removed = expire_memberships()
            if removed:
                logger.info(f"Expired {removed} group membership(s)")
        except BaseException as e:
            db.session.rollback()
            logger.error(f"Failed to expire group memberships: {e}")


def record_metrics_sample():
    # Snapshots the message counter totals once a minute for the Dashboard's rate chart
    # (raven.metrics.take_sample), keeping the last 24 hours.
    from raven.metrics import take_sample

    with apscheduler.app.app_context():
        try:
            take_sample(db.session)
        except BaseException as e:
            db.session.rollback()
            logger.error(f"Failed to record a metrics sample: {e}")


def apply_data_retention():
    # Deletes data older than each type's retention setting (the Data retention tab), in
    # batches. Also expires chat messages held for offline devices (48 hours by default).
    from raven.retention import apply_retention

    with apscheduler.app.app_context():
        try:
            apply_retention()
        except BaseException as e:
            db.session.rollback()
            logger.error(f"Data retention failed: {e}")


def refresh_crl():
    # Regenerates the CA's CRL before it expires (or if it's missing): nginx and the SSL
    # streaming port reject every client certificate once the CRL's nextUpdate has passed.
    from raven.cert_revocation import ensure_crl

    with apscheduler.app.app_context():
        try:
            ensure_crl(
                app.config.get("RAVEN_CA_FOLDER"), app.config.get("RAVEN_CA_PASSWORD"), logger
            )
        except BaseException as e:
            logger.error(f"Failed to refresh the CA's CRL: {e}")


# Kept so a stale job row/config entry that still references this old function name doesn't
# fail to load. (The ADS-B and AIS feed jobs that replaced it have since been removed.)
def get_airplanes_live_data():
    return
