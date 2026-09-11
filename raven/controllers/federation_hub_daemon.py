"""Standalone Federation Hub bridge daemon.

Bridges Raven's local CoT bus (RabbitMQ `groups` exchange) to Federation
Hub's FIG protocol (gRPC over mTLS on the broker's v2 port), so members of
RAVEN_FEDHUB_FEDERATE_GROUP are visible across whatever Federation Hub
already has federated. Federation Hub only relays what a federate actually
hands it -- this is the piece that does that handing-off.

Deliberately its OWN systemd service / OS process (like cot_parser and
eud_handler already are), never imported by or run inside the main `raven`
process. raven.app's gevent.monkey.patch_all() makes ordinary
threading.Thread a cooperative greenlet sharing one real OS thread with the
whole web server, and this bridge's workload -- multi-frame pika blocking
reads, a Queue handed between threads, a subprocess spawned to work around
the pika issue -- turned out to be unreliable inside that patched process no
matter how it was wired: a straight in-process consumer hung forever on any
message that needed multi-frame delivery; moving it to gevent's real-thread
threadpool fixed the hang but broke Queue and logging's internal locks
crossing the greenlet/thread boundary; spawning a dedicated unpatched
subprocess worker for just the RabbitMQ leg worked in isolation but gevent's
patched subprocess.Popen (and, after restoring the real Popen class, the
module-level _fork_exec global it also blanks out) turned even spawning that
subprocess into its own fight, and after finally winning that fight too, the
retry loop wrapping it silently stopped respawning after the first worker
died -- never proven root-caused, and not worth chasing further inside a
process this hostile to the workload. None of this is a problem here:
nothing else competes for this process's one thread of control, so
threading.Queue and pika.BlockingConnection.start_consuming() just work, the
same way they did in every standalone diagnostic script used to debug this
all along.
"""

import logging
import os
import queue
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from xml.etree.ElementTree import Element, SubElement, tostring

import grpc
import json
import pika
import yaml
from bs4 import BeautifulSoup
from flask import Flask

from raven.defaultconfig import DefaultConfig
from raven.extensions import db, logger
from raven.functions import datetime_from_iso8601_string, iso8601_string_from_datetime
from raven.proto.federation import fig_pb2, fig_pb2_grpc

# SQLAlchemy resolves string-based relationships (e.g. EUD's
# secondary="groups_missions") against every mapped class in the registry,
# not just the ones a given query touches -- the whole model graph has to be
# imported before the first query runs, the same as cot_parser.py does.
# User and Role are deliberately NOT imported here: they mix in
# Flask-Security's FsUserMixin, which needs fsqla.FsModels.set_db_info(db)
# called first (see create_app()) or class definition itself blows up.
from raven.models.Alert import Alert
from raven.models.CasEvac import CasEvac
from raven.models.Certificate import Certificate
from raven.models.Chatrooms import Chatroom
from raven.models.ChatroomsUids import ChatroomsUids
from raven.models.CITrap import CITrap
from raven.models.CoT import CoT
from raven.models.DataPackage import DataPackage
from raven.models.DeviceProfiles import DeviceProfiles
from raven.models.EUD import EUD
from raven.models.EUDStats import EUDStats
from raven.models.GeoChat import GeoChat
from raven.models.Group import Group
from raven.models.GroupMission import GroupMission
from raven.models.GroupUser import GroupUser
from raven.models.Icon import Icon
from raven.models.Marker import Marker
from raven.models.Meshtastic import MeshtasticChannel
from raven.models.Mission import Mission
from raven.models.MissionChange import MissionChange
from raven.models.MissionContentMission import MissionContentMission
from raven.models.MissionInvitation import MissionInvitation
from raven.models.MissionLogEntry import MissionLogEntry
from raven.models.MissionUID import MissionUID
from raven.models.Point import Point
from raven.models.RBLine import RBLine
from raven.models.Team import Team
from raven.models.VideoRecording import VideoRecording
from raven.models.VideoStream import VideoStream
from raven.models.WebAuthn import WebAuthn
from raven.models.ZMIST import ZMIST

# How long an inbound-injected uid is remembered before the outbound
# consumer is willing to forward it again. It only needs to survive one
# RabbitMQ round trip (publish -> our own bound queue delivering it back to
# us), so a few seconds of slack is generous.
_LOOPBACK_GUARD_SECONDS = 10


def _millis_from_iso8601(value: str | None) -> int:
    if not value:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    return int(datetime_from_iso8601_string(value).timestamp() * 1000)


def _iso8601_from_millis(value: int) -> str:
    if not value:
        return iso8601_string_from_datetime(datetime.now(timezone.utc))
    return iso8601_string_from_datetime(datetime.fromtimestamp(value / 1000, tz=timezone.utc))


def cot_xml_to_geoevent(cot_xml: str) -> fig_pb2.GeoEvent | None:
    """Flatten a Raven-internal CoT <event/> into the wire shape Federation
    Hub's FIG protocol expects. The full <detail> block is carried verbatim
    in `other` so a Raven peer on the other end can reconstruct the event
    with zero fidelity loss (see geoevent_to_cot_xml) -- the individual
    contact/__group/status/track fields below are populated too, but only
    as a best-effort fallback for a genuine TAK Server federate that doesn't
    know to look at `other`.
    """
    soup = BeautifulSoup(cot_xml, "xml")
    event = soup.find("event")
    if not event:
        return None

    point = event.find("point")
    detail = event.find("detail")
    contact = detail.find("contact") if detail else None
    group = detail.find("__group") if detail else None
    status = detail.find("status") if detail else None
    track = detail.find("track") if detail else None

    def f(tag, attr, default="0"):
        return float(tag[attr]) if tag and tag.has_attr(attr) else float(default)

    geo = fig_pb2.GeoEvent(
        sendTime=_millis_from_iso8601(event.get("time")),
        startTime=_millis_from_iso8601(event.get("start")),
        staleTime=_millis_from_iso8601(event.get("stale")),
        lat=f(point, "lat"),
        lon=f(point, "lon"),
        hae=f(point, "hae"),
        ce=f(point, "ce", "9999999"),
        le=f(point, "le", "9999999"),
        uid=event.get("uid", ""),
        type=event.get("type", ""),
        other=str(detail) if detail else "",
    )
    if contact and contact.has_attr("callsign"):
        geo.screenName = contact["callsign"]
    if contact and contact.has_attr("phone"):
        geo.phone = contact["phone"]
    if group and group.has_attr("name"):
        geo.groupName = group["name"]
    if group and group.has_attr("role"):
        geo.groupRole = group["role"]
    if status and status.has_attr("battery"):
        geo.battery = int(float(status["battery"]))
    if track and track.has_attr("course"):
        geo.course = float(track["course"])
    if track and track.has_attr("speed"):
        geo.speed = float(track["speed"])
    return geo


def geoevent_to_cot_xml(geo: fig_pb2.GeoEvent) -> str:
    """Reverse of cot_xml_to_geoevent. `how` isn't part of the FIG wire
    format at all, so it can't be round-tripped -- default to machine/GPS,
    which is what every position-reporting EUD sends anyway.
    """
    event = Element(
        "event",
        {
            "version": "2.0",
            "uid": geo.uid,
            "type": geo.type,
            "how": "m-g",
            "time": _iso8601_from_millis(geo.sendTime),
            "start": _iso8601_from_millis(geo.startTime),
            "stale": _iso8601_from_millis(geo.staleTime),
        },
    )
    SubElement(
        event,
        "point",
        {
            "lat": str(geo.lat),
            "lon": str(geo.lon),
            "hae": str(geo.hae),
            "ce": str(geo.ce or 9999999),
            "le": str(geo.le or 9999999),
        },
    )

    detail_parsed = None
    if geo.other:
        try:
            detail_parsed = BeautifulSoup(geo.other, "xml").find("detail")
        except Exception:
            detail_parsed = None

    if detail_parsed:
        # Re-attach the peer's own <detail> verbatim under our fresh <event>.
        event.append(_bs4_to_etree(detail_parsed))
    else:
        detail = SubElement(event, "detail")
        if geo.screenName or geo.phone:
            attrs = {}
            if geo.screenName:
                attrs["callsign"] = geo.screenName
            if geo.phone:
                attrs["phone"] = geo.phone
            SubElement(detail, "contact", attrs)
        if geo.groupName or geo.groupRole:
            attrs = {}
            if geo.groupName:
                attrs["name"] = geo.groupName
            if geo.groupRole:
                attrs["role"] = geo.groupRole
            SubElement(detail, "__group", attrs)
        if geo.battery:
            SubElement(detail, "status", {"battery": str(geo.battery)})
        if geo.course or geo.speed:
            SubElement(detail, "track", {"course": str(geo.course), "speed": str(geo.speed)})

    return tostring(event).decode("utf-8")


def _bs4_to_etree(tag) -> Element:
    element = Element(tag.name, {k: str(v) for k, v in tag.attrs.items()})
    children = tag.find_all(recursive=False)
    if not children:
        text = tag.get_text()
        element.text = text if text else None
    for child in children:
        element.append(_bs4_to_etree(child))
    return element


# GeoEvent.other is a free-form string that both ends of this bridge control
# entirely, so it doubles as an envelope: a position/contact CoT stores just
# its <detail> block there (see cot_xml_to_geoevent), but a direct message
# needs the *whole* event forwarded verbatim (its <dest> tag lives outside
# <detail>) plus which specific recipient this delivery is for -- a single
# DM CoT can carry more than one <dest> (one cot_parser publish per
# recipient), so the routing key has to travel explicitly rather than be
# re-derived by re-parsing <dest> on the inbound side, or a multi-recipient
# DM's other remote recipients all collapse onto whichever <dest> happens to
# parse first. Format: "RAWDM:<routing_key>\x00<raw cot xml>".
_DM_MARKER = "RAWDM:"


class FigFederateClient:
    def __init__(self, context):
        self.context = context
        cfg = context.app.config
        self.group_name = cfg.get("RAVEN_FEDHUB_FEDERATE_GROUP")
        self.self_uid = cfg.get("RAVEN_FEDHUB_FEDERATE_UID")
        self._recently_injected = {}
        self._recently_injected_lock = threading.Lock()
        # uid -> monotonic time we last sent it outbound (see
        # _on_outbound_message). Federation Hub echoes a server's own
        # outbound traffic back to it -- this is how _handle_federated_event
        # tells "our own event, bounced back" from "a genuinely remote
        # federate whose uid happens to collide with a local one" (a real
        # case: the same physical device can be independently enrolled on
        # two servers under different accounts, e.g. after a client
        # reconnected to the wrong one -- that's still real, current data
        # from the other server, not an echo, and shouldn't be dropped just
        # because a local EUD with the same uid also exists).
        self._recently_sent = {}
        self._recently_sent_lock = threading.Lock()
        self._outbound_queue = queue.Queue()

        # uid -> callsign for every remote member we've heard from over the
        # gRPC inbound stream since this process started -- the roster the
        # DM bridge binds the `dms` exchange against (see
        # _dm_outbound_loop). Deliberately in-memory rather than the EUD
        # table's federated_from column: an EUD can predate this bridge
        # (already known locally, so never got that column set) and still
        # be a perfectly real remote federate once it starts sending events.
        self._known_remote_members = {}
        self._known_remote_members_lock = threading.Lock()

        # Incoming federated CoT is attributed to this system account so it
        # flows through cot_parser's normal per-user group lookup (which is
        # what persists it, feeds the web map's socketio "point"/"eud"
        # events, and republishes it to the `groups` exchange) -- the same
        # path an EUD's own CoT takes, rather than only reaching TAK
        # protocol clients via a direct `groups` publish.
        with context:
            from raven.models.user import User

            federate_user = db.session.execute(
                db.session.query(User).filter_by(username=cfg.get("RAVEN_FEDHUB_FEDERATE_USERNAME"))
            ).first()
            self.federate_user_id = federate_user[0].id if federate_user else None
            if self.federate_user_id is None:
                logger.error(
                    "Federation Hub bridge: system account '{}' not found -- "
                    "inbound federated CoT won't be attributed to a group".format(
                        cfg.get("RAVEN_FEDHUB_FEDERATE_USERNAME")
                    )
                )

        self._channel = self._build_grpc_channel(cfg)
        self._stub = fig_pb2_grpc.FederatedChannelStub(self._channel)

    def start(self):
        threading.Thread(target=self._grpc_loop, name="fedhub-inbound", daemon=True).start()
        threading.Thread(target=self._server_event_loop, name="fedhub-server-event", daemon=True).start()
        threading.Thread(target=self._outbound_consumer_loop, name="fedhub-outbound", daemon=True).start()
        threading.Thread(target=self._dm_outbound_loop, name="fedhub-dm-outbound", daemon=True).start()

    def _build_grpc_channel(self, cfg) -> grpc.Channel:
        with open(cfg.get("RAVEN_FEDHUB_FEDERATE_CA"), "rb") as f:
            ca = f.read()
        with open(cfg.get("RAVEN_FEDHUB_FEDERATE_CERT"), "rb") as f:
            cert = f.read()
        with open(cfg.get("RAVEN_FEDHUB_FEDERATE_KEY"), "rb") as f:
            key = f.read()
        creds = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=cert)
        # ServerEventStream is held open indefinitely (see _server_event_loop)
        # with nothing else on the channel to naturally surface a dead TCP
        # connection -- observed in production going silent for hours with
        # no error logged at all: items kept landing in _outbound_queue, but
        # nothing was reaching the hub, because the underlying connection had
        # died without grpc's channel state noticing. HTTP/2 keepalive pings
        # give it something to time out on, so a dead connection gets
        # detected and the channel reconnects instead of stalling forever.
        # A 30s ping interval was fine while the broker was also forcibly
        # dropping every client stream every 15s (clientTimeoutTime in its
        # own config) anyway -- but once that was raised, the broker's own
        # ping-flood protection started closing the connection itself
        # (GOAWAY: too_many_pings) roughly every 60s instead. 5 minutes is
        # comfortably past what a Federation Hub-scale broker tolerates
        # while still catching a genuinely dead connection well before it'd
        # go unnoticed for hours.
        options = [
            ("grpc.keepalive_time_ms", 300000),
            ("grpc.keepalive_timeout_ms", 20000),
            ("grpc.keepalive_permit_without_calls", 1),
            ("grpc.http2.max_pings_without_data", 0),
        ]
        return grpc.secure_channel(cfg.get("RAVEN_FEDHUB_BROKER_ADDRESS"), creds, options=options)

    # -- outbound: local group traffic -> Federation Hub --------------------

    def _outbound_consumer_loop(self):
        cfg = self.context.app.config
        while True:
            try:
                credentials = pika.PlainCredentials(
                    cfg.get("RAVEN_RABBITMQ_USERNAME"), cfg.get("RAVEN_RABBITMQ_PASSWORD")
                )
                connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=cfg.get("RAVEN_RABBITMQ_SERVER_ADDRESS"), credentials=credentials, heartbeat=0
                    )
                )
                channel = connection.channel()
                channel.queue_declare(queue="fedhub_federate", exclusive=True)
                # `groups` is a topic exchange (routing keys are
                # "<group name>.OUT"/".IN"), so a single "*.OUT" binding
                # dynamically covers every group's outbound traffic -- not
                # just RAVEN_FEDHUB_FEDERATE_GROUP -- with no per-group
                # bindings to add or refresh as groups come and go. Whatever
                # group a federated user is actually assigned to on this
                # server now gets bridged, not only the one fixed group.
                channel.queue_bind(exchange="groups", queue="fedhub_federate", routing_key="*.OUT")

                def on_message(ch, method, properties, body):
                    try:
                        message = json.loads(body)
                    except (TypeError, ValueError):
                        return
                    routing_key = method.routing_key or ""
                    if not routing_key.endswith(".OUT"):
                        return
                    group_name = routing_key[: -len(".OUT")]
                    # __ANON__ is every new user's automatic default (see
                    # _add_to_anon_group) -- federating it would silently
                    # send every local user's default traffic to every
                    # federated peer. Only groups an admin actually assigned
                    # someone to are meant to cross servers.
                    if group_name == "__ANON__":
                        return
                    self._on_outbound_message(message, group_name)

                channel.basic_consume(queue="fedhub_federate", on_message_callback=on_message, auto_ack=True)
                logger.info("Federation Hub bridge bound to all groups (except __ANON__)")
                channel.start_consuming()
            except BaseException:
                logger.error(traceback.format_exc())
            time.sleep(5)

    def _on_outbound_message(self, message: dict, group_name: str):
        uid = message.get("uid")
        if not uid or uid == self.self_uid:
            return

        with self._recently_injected_lock:
            injected_at = self._recently_injected.pop(uid, None)
        if injected_at is not None and (time.monotonic() - injected_at) < _LOOPBACK_GUARD_SECONDS:
            # We just injected this uid from the hub -- don't hand it straight back.
            return

        geo = cot_xml_to_geoevent(message.get("cot", ""))
        if geo is None:
            logger.warning(f"FEDHUB outbound: cot_xml_to_geoevent returned None for uid={uid}")
            return
        with self._recently_sent_lock:
            self._recently_sent[uid] = time.monotonic()
        self._outbound_queue.put(fig_pb2.FederatedEvent(event=geo, federateGroups=[group_name]))
        logger.info(f"FEDHUB outbound: queued uid={uid} group='{group_name}'")

    # -- outbound: direct messages to a remote federated member -------------

    def _dm_outbound_loop(self):
        # Direct messages don't go through `groups` -- cot_parser publishes
        # them straight to the `dms` exchange (a `direct` exchange) with the
        # *recipient's* own uid/callsign as the routing key, which only ever
        # has a bound queue while that recipient is actually connected to
        # *this* server. A remote federated member is never connected here,
        # so with no matching binding the message is just dropped -- unless
        # we bind for them too. `direct` exchanges need one exact-match
        # binding per key (no wildcard), so this queue's bindings are kept
        # in sync with self._known_remote_members as it grows, which needs
        # start_consuming()'s blocking pump replaced with a manual one so
        # there's a place to periodically add new bindings.
        cfg = self.context.app.config
        while True:
            try:
                credentials = pika.PlainCredentials(
                    cfg.get("RAVEN_RABBITMQ_USERNAME"), cfg.get("RAVEN_RABBITMQ_PASSWORD")
                )
                connection = pika.BlockingConnection(
                    pika.ConnectionParameters(
                        host=cfg.get("RAVEN_RABBITMQ_SERVER_ADDRESS"), credentials=credentials, heartbeat=0
                    )
                )
                channel = connection.channel()
                channel.queue_declare(queue="fedhub_dms", exclusive=True)

                def on_message(ch, method, properties, body):
                    try:
                        message = json.loads(body)
                    except (TypeError, ValueError):
                        return
                    self._on_dm_message(message, method.routing_key)

                channel.basic_consume(queue="fedhub_dms", on_message_callback=on_message, auto_ack=True)

                bound_keys = set()
                while True:
                    with self._known_remote_members_lock:
                        roster = dict(self._known_remote_members)
                    for uid, callsign in roster.items():
                        for key in (uid, callsign):
                            if key and key not in bound_keys:
                                channel.queue_bind(exchange="dms", queue="fedhub_dms", routing_key=key)
                                bound_keys.add(key)
                    connection.process_data_events(time_limit=2)
            except BaseException:
                logger.error(traceback.format_exc())
            time.sleep(5)

    def _on_dm_message(self, message: dict, routing_key: str):
        uid = message.get("uid")
        cot_xml = message.get("cot", "")
        if not uid or uid == self.self_uid or not cot_xml:
            return
        # routing_key is which of this CoT's (possibly several -- a single
        # DM CoT can carry multiple <dest> tags, one publish per recipient
        # from cot_parser's side) destinations *this* delivery is for.
        # Carrying it explicitly, rather than re-deriving it by re-parsing
        # <dest> out of cot_xml on the inbound side, is what keeps a
        # multi-recipient DM's other remote recipients from all being
        # collapsed onto whichever <dest> happens to parse first.
        with self._recently_sent_lock:
            self._recently_sent[uid] = time.monotonic()

        now_millis = int(time.time() * 1000)
        geo = fig_pb2.GeoEvent(
            uid=uid,
            sendTime=now_millis,
            startTime=now_millis,
            staleTime=now_millis,
            other=_DM_MARKER + routing_key + "\x00" + cot_xml,
        )
        self._outbound_queue.put(fig_pb2.FederatedEvent(event=geo, federateGroups=[self.group_name]))
        logger.info(f"FEDHUB outbound: queued DM from uid={uid} to '{routing_key}'")

    def _server_event_generator(self):
        while True:
            yield self._outbound_queue.get()

    def _server_event_loop(self):
        # Federation Hub's own ServerEventStream handler (confirmed by
        # reading its source: tak.server.federation.hub.broker.
        # FederationHubBrokerService) sends its Subscription response and
        # then never closes the response stream, and separately its
        # SendOneEvent handler never responds at all -- so a Python client
        # waiting on either call to "complete" hangs until its own deadline
        # no matter what. What actually works: keep this call open
        # indefinitely with an infinite generator; the server processes each
        # event via onNext as it arrives regardless of whether the RPC
        # itself ever formally completes. Confirmed by broker byte counters
        # moving on a real event with the call still open.
        while True:
            try:
                self._stub.ServerEventStream(self._server_event_generator())
                logger.info("Federation Hub outbound stream ended -- reconnecting in 5s")
            except grpc.RpcError as e:
                logger.warning(
                    f"Federation Hub outbound stream dropped: {e.code()} {e.details()} -- reconnecting in 5s"
                )
            except BaseException:
                logger.error(traceback.format_exc())
            time.sleep(5)

    # -- inbound: Federation Hub -> local group ------------------------------

    def _grpc_loop(self):
        subscription = fig_pb2.Subscription(
            identity=fig_pb2.Identity(
                name=self.self_uid,
                uid=self.self_uid,
                description="C4Raven Federation Hub bridge",
            ),
            filter="",
        )
        inbound_conn = None
        inbound_channel = None
        while True:
            try:
                if inbound_conn is None or inbound_conn.is_closed:
                    inbound_conn = self._build_inbound_publish_connection()
                    inbound_channel = inbound_conn.channel()
                for federated_event in self._stub.ClientEventStream(subscription):
                    self._handle_federated_event(federated_event, inbound_channel)
            except grpc.RpcError as e:
                logger.warning(
                    f"Federation Hub event stream dropped: {e.code()} {e.details()} -- reconnecting in 5s"
                )
            except BaseException:
                logger.error(traceback.format_exc())
            time.sleep(5)

    def _build_inbound_publish_connection(self):
        cfg = self.context.app.config
        credentials = pika.PlainCredentials(
            cfg.get("RAVEN_RABBITMQ_USERNAME"), cfg.get("RAVEN_RABBITMQ_PASSWORD")
        )
        return pika.BlockingConnection(
            pika.ConnectionParameters(
                host=cfg.get("RAVEN_RABBITMQ_SERVER_ADDRESS"),
                credentials=credentials,
                heartbeat=0,
            )
        )

    def _handle_federated_event(self, federated_event: fig_pb2.FederatedEvent, inbound_channel):
        if not federated_event.HasField("event"):
            return  # metadata-only frame (provenance/hop-limit announcements etc.)

        geo = federated_event.event
        if geo.uid == self.self_uid:
            return

        # Federation Hub echoes a server's own outbound traffic back to it
        # along with everyone else's -- geo.uid == self.self_uid only
        # catches the daemon's own synthetic identity, not a real local
        # device's uid. Without this, a local device's own position/DM
        # traffic gets treated as newly-arrived federated traffic: it ends
        # up in _known_remote_members, which makes _dm_outbound_loop bind
        # the local device's own uid/callsign on the `dms` exchange, so a
        # same-server DM between two local users gets needlessly (and
        # sometimes duplicately) round-tripped through the hub instead of
        # just being delivered directly by cot_parser like any other local
        # DM.
        #
        # Originally this checked "does a local EUD exist for this uid",
        # but that's wrong when the same physical device is independently
        # enrolled on two servers under different accounts (a client that
        # connects to the wrong server, or switches servers) -- that's
        # real, current data from the other server, not an echo, and
        # dropping it just because a (possibly long-disconnected) local EUD
        # happens to share the uid would silently break federating it in.
        # _recently_sent -- set right before *we* hand a uid to the hub --
        # is the actual echo signal: only skip a uid we ourselves handed
        # the hub a moment ago, not any uid that merely looks local. Popped
        # rather than just read, same as _recently_injected above, so a
        # uid's entry doesn't sit in this dict forever once it's been
        # checked once -- otherwise every distinct uid this daemon ever
        # sends leaks a permanent entry for the life of the process.
        with self._recently_sent_lock:
            sent_at = self._recently_sent.pop(geo.uid, None)
        if sent_at is not None and (time.monotonic() - sent_at) < _LOOPBACK_GUARD_SECONDS:
            return

        with self._known_remote_members_lock:
            known = self._known_remote_members.get(geo.uid, "")
            resolved_callsign = geo.screenName or self._extract_callsign_from_other(geo.other) or known
            self._known_remote_members[geo.uid] = resolved_callsign

        if geo.other.startswith(_DM_MARKER):
            self._handle_federated_dm(geo, inbound_channel)
            return

        provenance_id = (
            federated_event.federateProvenance[0].federationServerId
            if federated_event.federateProvenance
            else "unknown-federate"
        )
        self._ensure_federated_eud(geo, provenance_id, resolved_callsign)

        # federateGroups carries the sending server's own group name(s) for
        # this event (see _on_outbound_message) -- route it straight to the
        # same-named group(s) here rather than through federate_user_id's
        # (the "Server" account's) own memberships, so it reaches whichever
        # group it actually belongs to instead of only whatever "Server"
        # happens to be a member of. Falls back to the old user_id-based
        # routing if a peer doesn't set it (e.g. Fed group's own bootstrap
        # membership on "Server" still covers that case either way).
        cot_xml = geoevent_to_cot_xml(geo)
        message = json.dumps(
            {
                "uid": geo.uid,
                "cot": cot_xml,
                "user_id": self.federate_user_id,
                "target_groups": [g for g in federated_event.federateGroups if g != "__ANON__"],
            }
        )

        with self._recently_injected_lock:
            self._recently_injected[geo.uid] = time.monotonic()

        self._publish_to_cot_parser(message, inbound_channel)

    def _handle_federated_dm(self, geo: fig_pb2.GeoEvent, inbound_channel):
        # Unlike a position/contact event, a direct message doesn't get
        # injected as a new local CoT -- it goes straight to the `dms`
        # exchange with the recipient's own uid/callsign as the routing
        # key, exactly like a same-server DM does, so it lands on their
        # real EudHandler connection instead of being (mis)treated as a
        # broadcast update from a device that doesn't exist here. Reuses
        # _grpc_loop's own inbound_channel rather than opening a fresh
        # RabbitMQ connection per message.
        routing_key, _, raw_xml = geo.other[len(_DM_MARKER) :].partition("\x00")
        if not routing_key or not raw_xml:
            logger.warning(f"FEDHUB inbound DM: malformed envelope for uid={geo.uid}, dropping")
            return
        message = json.dumps({"uid": geo.uid, "cot": raw_xml})
        inbound_channel.basic_publish(exchange="dms", routing_key=routing_key, body=message)
        logger.info(f"FEDHUB inbound: delivered DM from uid={geo.uid} to '{routing_key}'")

    @staticmethod
    def _extract_callsign_from_other(other: str) -> str:
        # Not every inbound GeoEvent carries screenName -- a bare position
        # ping often doesn't re-announce <contact> at all -- but `other`
        # (the peer's raw <detail> block, round-tripped verbatim per
        # geoevent_to_cot_xml) sometimes still has it even then.
        if not other:
            return ""
        try:
            contact = BeautifulSoup(other, "xml").find("contact")
            if contact and contact.has_attr("callsign"):
                return contact["callsign"]
        except Exception:
            pass
        return ""

    def _ensure_federated_eud(self, geo: fig_pb2.GeoEvent, provenance_id: str, resolved_callsign: str = ""):
        # cot_parser's `cot` table has a foreign key requiring sender_uid to
        # already exist in `euds` -- a genuinely remote federated device was
        # never locally enrolled, so without this row every federated event
        # gets rejected with a ForeignKeyViolation before it ever reaches the
        # map or the groups exchange. federated_from marks it as not a real
        # local enrollment, for the UI to render distinctly.
        with self.context:
            from raven.models.EUD import EUD

            existing = db.session.execute(db.session.query(EUD).filter_by(uid=geo.uid)).first()
            if existing:
                existing = existing[0]
                changed = False
                # The very first event for a uid sometimes arrives with no
                # callsign anywhere on it -- a bare t-x-d-d "went offline"
                # notice, for instance, never carries one -- so it gets
                # created with the raw uid as a placeholder (see below) and
                # no user account at all (see below). Once a later event
                # supplies a real callsign, backfill it here.
                if resolved_callsign and existing.callsign == geo.uid:
                    existing.callsign = resolved_callsign
                    changed = True
                # Separately: a user account can be missing even when the
                # callsign is already fine -- _ensure_federated_user can
                # fail (a transient error, a name collision) independently
                # of the EUD row itself succeeding. Retry it here using
                # whatever callsign is on record, not just on the
                # placeholder-callsign path above, so it isn't stuck missing
                # forever just because the callsign was never the problem.
                if not existing.user_id and existing.callsign != geo.uid:
                    existing.user_id = self._ensure_federated_user(existing.callsign)
                    changed = True
                if changed:
                    try:
                        db.session.commit()
                    except BaseException:
                        db.session.rollback()
                    else:
                        self._rename_placeholder_federated_user(
                            existing.user_id, geo.uid, existing.callsign
                        )
                return

            # No callsign anywhere on this uid's first-ever event. When
            # that event is itself a t-x-d-d "went offline" notice, there's
            # no identity to remember and never will be -- skip creating a
            # row for it entirely instead of leaving a permanent
            # uid-as-callsign placeholder in the EUDs table forever.
            # cot_parser tolerates the missing row fine for this uid:
            # insert_cot swallows the resulting IntegrityError, and the
            # t-x-d-d handler just no-ops when it finds no existing EUD.
            if not resolved_callsign and geo.type == "t-x-d-d":
                return

            # Still no callsign, but this is a real position/contact event
            # -- so register the EUD (cot_parser's FK still needs the row)
            # but skip creating a "fed-<uid>"-named user account for it. If
            # it turns out to be a real device after all, the backfill above
            # creates the account once we actually learn its callsign.
            callsign = resolved_callsign or geo.uid
            user_id = self._ensure_federated_user(resolved_callsign) if resolved_callsign else None
            eud = EUD(uid=geo.uid, callsign=callsign, federated_from=provenance_id, user_id=user_id)
            db.session.add(eud)
            try:
                db.session.commit()
            except BaseException:
                db.session.rollback()
                # Most likely the unique callsign collided with a local
                # device's -- still register the uid so cot_parser accepts
                # it, just without a friendly callsign.
                eud = EUD(uid=geo.uid, federated_from=provenance_id, user_id=user_id)
                db.session.add(eud)
                try:
                    db.session.commit()
                except BaseException:
                    db.session.rollback()
                    logger.error(traceback.format_exc())

    @staticmethod
    def _base_username_for_callsign(callsign: str) -> str:
        # callsign comes verbatim from a remote federate -- never trust it
        # into a username unsanitized.
        import bleach

        clean_callsign = bleach.clean(callsign, tags=[], strip=True).strip()[:64] if callsign else ""
        return f"fed-{clean_callsign}" if clean_callsign else "fed-user"

    def _ensure_federated_user(self, callsign: str) -> int | None:
        # A GroupUser row (what the Groups tab's "add member" actually
        # writes) is keyed by user_id, not by EUD -- so without a real User
        # row here, a federated device could never be added to any group
        # beyond the one it was federated in through. This account is never
        # meant to be logged into: active=False blocks it at the login form
        # regardless of the unusable random password, and it exists purely
        # so the device has a user_id to hang group memberships off of, the
        # same as any locally-enrolled EUD's owner does.
        import secrets

        from flask_security import hash_password

        from raven.models.user import User

        base_username = self._base_username_for_callsign(callsign)
        username = base_username
        suffix = 1
        while db.session.execute(db.session.query(User).filter_by(username=username)).first():
            suffix += 1
            username = f"{base_username}-{suffix}"

        try:
            user = self.context.app.security.datastore.create_user(
                username=username,
                password=hash_password(secrets.token_urlsafe(32)),
                active=False,
            )
            db.session.commit()
            return user.id
        except BaseException:
            db.session.rollback()
            logger.error(traceback.format_exc())
            return None

    def _rename_placeholder_federated_user(self, user_id: int | None, old_uid: str, callsign: str):
        # Mirrors the EUD.callsign backfill above: the account was created
        # with the raw uid as its username (via _ensure_federated_user, since
        # that's all _ensure_federated_eud had to give it at the time) --
        # once a real callsign is known, rename it to match so the Users
        # page doesn't show a wall of "fed-<uid>"-looking accounts forever.
        if not user_id:
            return
        with self.context:
            from raven.models.user import User

            user = db.session.execute(db.session.query(User).filter_by(id=user_id)).first()
            if not user:
                return
            user = user[0]

            # Only rename accounts still on their uid-derived placeholder --
            # never touch one that's since been given a real name some other
            # way (a prior heal, an admin edit).
            placeholder_base = self._base_username_for_callsign(old_uid)
            if user.username != placeholder_base and not user.username.startswith(f"{placeholder_base}-"):
                return

            new_base = self._base_username_for_callsign(callsign)
            new_username = new_base
            suffix = 1
            while (
                new_username != user.username
                and db.session.execute(
                    db.session.query(User).filter_by(username=new_username)
                ).first()
            ):
                suffix += 1
                new_username = f"{new_base}-{suffix}"

            if new_username == user.username:
                return

            user.username = new_username
            try:
                db.session.commit()
            except BaseException:
                db.session.rollback()
                logger.error(traceback.format_exc())

    def _publish_to_cot_parser(self, message: str, channel):
        # Feeding cot_parser (rather than publishing to `groups` ourselves)
        # gets federated CoT the same treatment as any EUD's own traffic:
        # persisted, fanned out to the web map's socketio events, and
        # published to `groups` under the federate account's own memberships.
        channel.basic_publish(exchange="cot_parser", routing_key="cot_parser", body=message)


def setup_logging(app):
    level = logging.INFO
    if app.config.get("DEBUG"):
        level = logging.DEBUG
    logger.setLevel(level)

    if sys.stdout.isatty():
        import colorlog

        color_log_handler = colorlog.StreamHandler()
        color_log_formatter = colorlog.ColoredFormatter(
            "%(log_color)s[%(asctime)s] - fedhub_bridge[%(process)d] - %(module)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S %Z",
        )
        color_log_handler.setFormatter(color_log_formatter)
        logger.addHandler(color_log_handler)
        logger.info("Added color logger")

    os.makedirs(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs"), exist_ok=True)
    fh = TimedRotatingFileHandler(
        os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs", "fedhub_bridge.log"),
        when=app.config.get("RAVEN_LOG_ROTATE_WHEN"),
        interval=app.config.get("RAVEN_LOG_ROTATE_INTERVAL"),
        backupCount=app.config.get("RAVEN_BACKUP_COUNT"),
    )
    fh.setFormatter(
        logging.Formatter(
            "[%(asctime)s] - fedhub_bridge[%(process)d] - %(module)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s"
        )
    )
    logger.addHandler(fh)


def create_app():
    app = Flask(__name__)
    app.config.from_object(DefaultConfig)

    config_path = os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "config.yml")
    if os.path.exists(config_path):
        app.config.from_file(config_path, load=yaml.safe_load)

    setup_logging(app)
    db.init_app(app)

    # raven.models.user.User mixes in Flask-Security's FsUserMixin, which
    # resolves its own relationships against FsModels.db at class-definition
    # time -- has to happen before that module is ever imported (here, via
    # FigFederateClient's own `from raven.models.user import User`).
    import sqlalchemy.exc
    from flask_security.models import fsqla

    try:
        fsqla.FsModels.set_db_info(db)
    except sqlalchemy.exc.InvalidRequestError:
        pass

    from raven.models.role import Role
    from raven.models.user import User

    # Full Security() init (not just set_db_info) -- hash_password() (used
    # by _ensure_federated_user) reads its hashing scheme from config that
    # only this registers, and blows up with a bare datastore otherwise.
    # This daemon never serves HTTP, so the login views/blueprints it adds
    # just sit unused; mirrors raven.app's own Security() call so a
    # federated-placeholder account hashes exactly like a real one.
    import flask_wtf
    from flask_security import Security, SQLAlchemyUserDatastore

    from raven.EmailValidator import EmailValidator
    from raven.forms.SiteAccessLoginForm import SiteAccessLoginForm
    from raven.models.WebAuthn import WebAuthn
    from raven.PasswordValidator import PasswordValidator
    from raven.UsernameValidator import UsernameValidator

    flask_wtf.CSRFProtect(app)
    user_datastore = SQLAlchemyUserDatastore(db, User, Role, WebAuthn)
    app.security = Security(
        app,
        user_datastore,
        mail_util_cls=EmailValidator,
        password_util_cls=PasswordValidator,
        username_util_cls=UsernameValidator,
        login_form=SiteAccessLoginForm,
    )

    return app


def main():
    app = create_app()

    if not app.config.get("RAVEN_FEDHUB_ENABLE") or not app.config.get("RAVEN_FEDHUB_FEDERATE_ENABLE"):
        logger.info("Federation Hub bridge disabled")
        # Idle forever rather than exiting -- keeps the systemd unit in a
        # stable "running" state instead of flapping through restarts.
        while True:
            time.sleep(3600)

    client = FigFederateClient(app.app_context())
    client.start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
