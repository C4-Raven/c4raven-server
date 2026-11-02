"""
Chat for devices that are offline.

Live GeoChat routing (cot_parser.route_cot) publishes a message to the "dms" exchange by the
<dest> callsign/uid, or to the "groups" exchange for team chat, and a device's queue is only
bound to those exchanges while it is connected (EudHandler binds on connect and unbinds on
disconnect). A message sent while the recipient was offline matched no binding and was dropped
by RabbitMQ.

Now cot_parser also calls queue_offline_chat() for every GeoChat message. It works out who the
live routing addresses and stores one offline_chat_messages row per addressed device whose
euds row isn't "Connected". When the device next connects and identifies itself, EudHandler
calls deliver_pending(), which writes the stored CoTs straight to the device's socket, oldest
first, and stamps each row delivered.

Who gets a queued copy (bounded on purpose):
* Messages with <dest> tags -- direct messages, and ATAK's user-created group chats, which
  carry one <dest> per member -- go to exactly the devices named, as the live routing does.
* Team chat (chatroom named after a team colour, no <dest>) goes to the offline devices on that
  team that read one of the groups the sender writes to (or, for a sender without groups, the
  devices in __ANON__), which is the set the live group routing would reach.
* "All Chat Rooms" is not queued. It is a broadcast to every device that has ever connected,
  so queuing it would store one copy per device ever seen for every message. ATAK keeps no
  per-member list for it either.

Messages are held for the "offline_chat" retention setting (48 hours by default, see
raven/retention.py); older rows are not delivered and are purged by the retention job.

Duplicates: a device whose row says "Connected" gets the message live and no copy is queued.
The status can lag a dropped connection by up to ~30 seconds (EudHandler's TCP keepalive), so
a message sent in that window is queued and, if the device really was still connected, it gets
it twice. ATAK files GeoChat by message uid, so a repeated message replaces itself rather than
showing twice.
"""

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from raven.extensions import logger
from raven.functions import iso8601_string_from_datetime

ALL_CHAT_ROOMS = "All Chat Rooms"
# Platforms that never get a dms/groups queue in EudHandler
NO_QUEUE_PLATFORMS = ("OpenTAK ICU", "Meshtastic", "DMRCOT")
# How long a delivered CoT stays fresh. The stored message's own stale time has usually passed
# by the time it is delivered; its time/start and the remarks time are left as sent, so the
# chat still shows when the message was written.
DELIVERY_STALE = timedelta(hours=1)

_STALE_RE = re.compile(r'(<event\b[^>]*?\sstale=)(["\'])[^"\']*\2', re.S)


def utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _team_chat_recipients(session, chatroom, sender_uid, user_id):
    from raven.models.EUD import EUD
    from raven.models.Group import Group
    from raven.models.GroupUser import GroupUser
    from raven.models.Team import Team

    team = session.execute(select(Team).filter_by(name=chatroom)).scalars().first()
    if not team:
        return []

    query = select(EUD).where(EUD.team_id == team.id, EUD.uid != sender_uid)
    in_groups = []
    if user_id:
        in_groups = (
            session.execute(
                select(GroupUser.group_id).filter_by(
                    user_id=user_id, direction=Group.IN, enabled=True
                )
            )
            .scalars()
            .all()
        )
    if in_groups:
        readers = select(GroupUser.user_id).where(
            GroupUser.group_id.in_(in_groups),
            GroupUser.direction == Group.OUT,
            GroupUser.enabled.is_(True),
        )
        query = query.where(EUD.user_id.in_(readers))
    else:
        # __ANON__: devices whose user has no OUT memberships at all, and plain TCP devices
        with_groups = select(GroupUser.user_id).where(GroupUser.direction == Group.OUT)
        query = query.where(or_(EUD.user_id.is_(None), EUD.user_id.not_in(with_groups)))
    return session.execute(query).scalars().all()


def chat_recipients(session, event, sender_uid, user_id=None):
    """The euds rows a GeoChat event is addressed to (excluding the sender), or [] for
    anything that isn't a chat message or isn't queued (All Chat Rooms)."""
    from raven.models.EUD import EUD

    chat = event.find("__chat")
    if not chat or not event.find("remarks"):
        return []
    chatroom = chat.attrs.get("chatroom")
    if chat.attrs.get("id") == ALL_CHAT_ROOMS or chatroom == ALL_CHAT_ROOMS:
        return []

    recipients = {}
    has_dest = False
    for dest in event.find_all("dest"):
        if "mission" in dest.attrs:
            continue
        callsign = dest.attrs.get("callsign")
        dest_uid = dest.attrs.get("uid")
        eud = None
        # Same precedence as cot_parser.route_cot: ATAK/WinTAK address by callsign, iTAK by uid
        if callsign:
            has_dest = True
            eud = session.execute(select(EUD).filter_by(callsign=callsign)).scalars().first()
        elif dest_uid and dest_uid != sender_uid:
            has_dest = True
            eud = session.execute(select(EUD).filter_by(uid=dest_uid)).scalars().first()
        if eud is not None:
            recipients[eud.uid] = eud

    if not has_dest and chatroom:
        for eud in _team_chat_recipients(session, chatroom, sender_uid, user_id):
            recipients[eud.uid] = eud

    return [eud for uid, eud in recipients.items() if uid != sender_uid]


def queue_offline_chat(session, event, sender_uid, user_id=None, now=None):
    """Stores a copy of a GeoChat event for each addressed device that is offline. Returns the
    number of rows queued. Never raises."""
    from raven.models.OfflineChatMessage import OfflineChatMessage

    try:
        message_uid = event.attrs.get("uid")
        if not message_uid or not sender_uid:
            return 0

        offline = [
            eud
            for eud in chat_recipients(session, event, sender_uid, user_id)
            if eud.last_status != "Connected"
            and eud.platform not in NO_QUEUE_PLATFORMS
            and not eud.federated_from
        ]
        if not offline:
            return 0

        already = set(
            session.execute(
                select(OfflineChatMessage.recipient_uid).where(
                    OfflineChatMessage.message_uid == message_uid,
                    OfflineChatMessage.recipient_uid.in_([e.uid for e in offline]),
                )
            ).scalars()
        )
        chat = event.find("__chat")
        now = now or utcnow_naive()
        xml = str(event)
        queued = 0
        for eud in offline:
            if eud.uid in already:
                continue
            session.add(
                OfflineChatMessage(
                    recipient_uid=eud.uid,
                    sender_uid=sender_uid,
                    chatroom_id=chat.attrs.get("id") if chat else None,
                    message_uid=message_uid,
                    xml=xml,
                    created_at=now,
                )
            )
            queued += 1
        session.commit()
        if queued:
            logger.info(f"Queued chat {message_uid} for {queued} offline device(s)")
        return queued
    except IntegrityError:
        # Another cot_parser worker queued the same message at the same moment
        session.rollback()
        return 0
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to queue chat for offline devices: {e}")
        return 0


def pending_messages(session, uid, now=None):
    """Undelivered, unexpired messages for one device, oldest first."""
    from raven.models.OfflineChatMessage import OfflineChatMessage
    from raven.retention import OFFLINE_CHAT, keep_seconds

    query = select(OfflineChatMessage).where(
        OfflineChatMessage.recipient_uid == uid, OfflineChatMessage.delivered_at.is_(None)
    )
    seconds = keep_seconds(OFFLINE_CHAT, session)
    if seconds is not None:
        cutoff = (now or utcnow_naive()) - timedelta(seconds=seconds)
        query = query.where(OfflineChatMessage.created_at >= cutoff)
    query = query.order_by(OfflineChatMessage.created_at, OfflineChatMessage.id)
    return session.execute(query).scalars().all()


def refresh_stale(xml, now=None):
    """The stored CoT with its stale time moved forward so the device doesn't drop it."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    stale = iso8601_string_from_datetime(now + DELIVERY_STALE)
    return _STALE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{stale}{m.group(2)}", xml, count=1)


def deliver_pending(session, uid, send, now=None):
    """Sends every pending message for uid with send(bytes), oldest first, stamping each one
    delivered as soon as it has been written. Stops at the first failed write; the rest stay
    queued for the next connection. Returns the number delivered."""
    delivered = 0
    for message in pending_messages(session, uid, now):
        send(refresh_stale(message.xml).encode())
        message.delivered_at = utcnow_naive()
        session.commit()
        delivered += 1
    return delivered
