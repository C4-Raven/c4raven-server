import json
import threading
import time
import traceback
from datetime import datetime, timezone
from xml.etree.ElementTree import Element, SubElement, tostring

import gevent
import grpc
from bs4 import BeautifulSoup
from flask import Flask

from raven.controllers.rabbitmq_client import RabbitMQClient
from raven.extensions import logger
from raven.functions import datetime_from_iso8601_string, iso8601_string_from_datetime
from raven.proto.federation import fig_pb2, fig_pb2_grpc

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


class FigFederateClient(RabbitMQClient):
    """Bridges Raven's local CoT bus (RabbitMQ `groups` exchange) to
    Federation Hub's FIG protocol (gRPC over mTLS on the broker's v2 port),
    so members of RAVEN_FEDHUB_FEDERATE_GROUP are visible across whatever
    Federation Hub already has federated -- the piece that was missing
    entirely before this: Federation Hub only relays what a federate
    actually hands it, and nothing in Raven was doing that.

    app.py's gevent.monkey.patch_all() makes ordinary threading.Thread a
    cooperative greenlet sharing one real OS thread with the rest of the
    process (including the HTTP/socketio listener). grpc's Python stub calls
    block at the C level and don't cooperate with that scheduler, so every
    blocking gRPC call here is dispatched through gevent's own native
    threadpool instead -- the one thing in a gevent process that's actually
    safe to block synchronously on. Do not call self._stub methods directly
    from a greenlet; always go through self._threadpool.
    """

    def __init__(self, context: Flask):
        RabbitMQClient.__init__(self, context)

        self.group_name = context.app.config.get("RAVEN_FEDHUB_FEDERATE_GROUP")
        self.self_uid = context.app.config.get("RAVEN_FEDHUB_FEDERATE_UID")
        self._recently_injected = {}
        self._recently_injected_lock = threading.Lock()
        self._threadpool = gevent.get_hub().threadpool

        self._channel = self._build_grpc_channel(context)
        self._stub = fig_pb2_grpc.FederatedChannelStub(self._channel)

    def start(self):
        # Runs the whole blocking stream-read loop on a real OS thread, kept
        # alive for the life of the process -- not a one-off spawn().
        self._threadpool.spawn(self._grpc_loop)

    def _build_grpc_channel(self, context: Flask) -> grpc.Channel:
        cfg = context.app.config
        with open(cfg.get("RAVEN_FEDHUB_FEDERATE_CA"), "rb") as f:
            ca = f.read()
        with open(cfg.get("RAVEN_FEDHUB_FEDERATE_CERT"), "rb") as f:
            cert = f.read()
        with open(cfg.get("RAVEN_FEDHUB_FEDERATE_KEY"), "rb") as f:
            key = f.read()
        creds = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=cert)
        return grpc.secure_channel(cfg.get("RAVEN_FEDHUB_BROKER_ADDRESS"), creds)

    # -- outbound: local group traffic -> Federation Hub --------------------

    def on_channel_open(self, channel):
        self.rabbit_channel = channel
        self.rabbit_channel.queue_declare(queue="fedhub_federate", exclusive=True)
        self.rabbit_channel.queue_bind(
            exchange="groups", queue="fedhub_federate", routing_key=f"{self.group_name}.OUT"
        )
        self.rabbit_channel.basic_consume(
            queue="fedhub_federate", on_message_callback=self.on_message, auto_ack=True
        )
        self.rabbit_channel.add_on_close_callback(self.on_close)
        logger.info(f"Federation Hub bridge bound to group '{self.group_name}'")

    def on_message(self, unused_channel, basic_deliver, properties, body):
        try:
            message = json.loads(body)
        except (TypeError, ValueError):
            return

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
            return
        # on_message runs on the pika greenlet -- calling the (blocking) gRPC
        # stub here directly would stall it, so hand the call to the real
        # threadpool instead of running it inline.
        self._threadpool.spawn(self._send_one_event, uid, geo)

    def _send_one_event(self, uid: str, geo: fig_pb2.GeoEvent):
        try:
            self._stub.SendOneEvent(
                fig_pb2.FederatedEvent(event=geo, federateGroups=[self.group_name]), timeout=10
            )
        except grpc.RpcError as e:
            logger.error(f"Federation Hub SendOneEvent failed for {uid}: {e.code()} {e.details()}")
        except BaseException:
            logger.error(traceback.format_exc())

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
        while True:
            try:
                for federated_event in self._stub.ClientEventStream(subscription):
                    self._handle_federated_event(federated_event)
            except grpc.RpcError as e:
                logger.warning(
                    f"Federation Hub event stream dropped: {e.code()} {e.details()} -- reconnecting in 5s"
                )
            except BaseException:
                logger.error(traceback.format_exc())
            time.sleep(5)

    def _handle_federated_event(self, federated_event: fig_pb2.FederatedEvent):
        if not federated_event.HasField("event"):
            return  # metadata-only frame (provenance/hop-limit announcements etc.)

        geo = federated_event.event
        if geo.uid == self.self_uid:
            return

        cot_xml = geoevent_to_cot_xml(geo)
        message = json.dumps({"uid": geo.uid, "cot": cot_xml})

        with self._recently_injected_lock:
            self._recently_injected[geo.uid] = time.monotonic()

        # This runs on the gRPC stream's own thread, not the pika ioloop
        # thread RabbitMQClient owns -- pika channels aren't thread-safe, so
        # the publish has to be marshalled over rather than called directly.
        if self.rabbit_channel and not self.rabbit_channel.is_closed:
            self.rabbit_connection.ioloop.add_callback_threadsafe(
                lambda: self._publish_to_group(message)
            )

    def _publish_to_group(self, message: str):
        if self.rabbit_channel and not self.rabbit_channel.is_closed:
            self.rabbit_channel.basic_publish(
                exchange="groups", routing_key=f"{self.group_name}.OUT", body=message
            )
