"""
Chat for devices that are offline.

Live GeoChat routing (cot_parser.route_cot) publishes a message to the "dms" exchange by the
<dest> callsign/uid, or to the "groups" exchange for team chat, and a device's queue is only
bound to those exchanges while it is connected (EudHandler binds on connect and unbinds on
disconnect). A message sent while the recipient was offline matched no binding and was dropped
by RabbitMQ.

Now cot_parser also calls queue_offline_chat() for every GeoChat message. It works out who the
live routing addresses and stores one offline_chat_messages row per addressed device, whatever
its euds row says (see "Connected devices" below). When the device next connects and identifies
itself, EudHandler calls deliver_pending(), which writes the stored CoTs straight to the
device's socket, oldest first, and stamps each row delivered. It does that before it starts
consuming the device's live queues, so the backlog arrives before anything newer.

Who gets a queued copy (bounded on purpose):
* Messages with <dest> tags -- direct messages, and ATAK's user-created group chats, which
  carry one <dest> per member -- go to exactly the devices named, as the live routing does.
* Team chat (chatroom named after a team colour, no <dest>) goes to the devices on that team
  that read one of the groups the sender writes to (or, for a sender without groups, the
  devices in __ANON__), which is the set the live group routing would reach. Federated-in
  events carry the groups they were sent to (target_groups) and use those instead.
* "All Chat Rooms" is not queued. It is a broadcast to every device that has ever connected,
  so queuing it would store one copy per device ever seen for every message. ATAK keeps no
  per-member list for it either.

Who it is delivered to: a row remembers the user the recipient device belonged to
(recipient_user_id). Such a row is only delivered over a connection authenticated as that user,
never over an unauthenticated one, so taking over a device uid doesn't hand over its backlog.
Team chat rows also remember which groups may read them and are only delivered if the
connecting user still reads one of them. Revoking a device's certificate drops its queue
(drop_queue()).

Connected devices: a device's row can say "Connected" for up to ~30 seconds after its connection
died (EudHandler's TCP keepalive/TCP_USER_TIMEOUT), and a message routed live in that window is
lost. So a copy is queued for every addressed device, connected or not, and euds.last_rx_at
records when the server last received data from the device. On reconnect, rows created after
(the previous last_rx_at - RX_GRACE) are delivered; older rows were sent while the device was
demonstrably still talking to the server, so they are stamped delivered without being resent.
The retention job (settle_live_deliveries) stamps rows for devices that are still connected and
have sent data more than TCP_USER_TIMEOUT after the message was queued. last_rx_at is written at
most every LAST_RX_WRITE_INTERVAL, so it can lag; that only means more messages are resent, never
fewer. ATAK files GeoChat by message uid, so a resent message replaces itself rather than
showing twice.

Messages are held for the "offline_chat" retention setting (48 hours by default, see
raven/retention.py); older rows are not delivered and are purged by the retention job.
"""

import json
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_, select, update
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
# EudHandler's TCP_USER_TIMEOUT: data written to a dead peer errors out within this long
TCP_USER_TIMEOUT = timedelta(seconds=30)
# Slack on the reconnect cut-off, for messages in flight around the last receive
RX_GRACE = timedelta(seconds=5)
# EudHandler writes euds.last_rx_at at most this often per connection
LAST_RX_WRITE_INTERVAL = 30

_STALE_RE = re.compile(r'(<event\b[^>]*?\sstale=)(["\'])[^"\']*\2', re.S)


def utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _naive(dt):
    if dt is not None and dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _read_groups(session, user_id, target_groups):
    """The group ids whose OUT members read a team chat message: the groups named by a
    federated event, else the groups the sender writes to. [] means __ANON__; None means
    nobody (a federated event naming no group that exists here)."""
    from raven.models.Group import Group
    from raven.models.GroupUser import GroupUser

    if target_groups:
        ids = (
            session.execute(select(Group.id).where(Group.name.in_(list(target_groups))))
            .scalars()
            .all()
        )
        return sorted(ids) or None
    if not user_id:
        return []
    return sorted(
        session.execute(
            select(GroupUser.group_id).filter_by(user_id=user_id, direction=Group.IN, enabled=True)
        )
        .scalars()
        .all()
    )


def _readers_where(query, read_groups):
    """Limits an EUD query to devices whose user reads one of read_groups ([] = __ANON__)."""
    from raven.models.EUD import EUD
    from raven.models.Group import Group
    from raven.models.GroupUser import GroupUser

    if read_groups:
        readers = select(GroupUser.user_id).where(
            GroupUser.group_id.in_(read_groups),
            GroupUser.direction == Group.OUT,
            GroupUser.enabled.is_(True),
        )
        return query.where(EUD.user_id.in_(readers))
    # __ANON__: devices whose user has no OUT memberships at all, and plain TCP devices
    with_groups = select(GroupUser.user_id).where(GroupUser.direction == Group.OUT)
    return query.where(or_(EUD.user_id.is_(None), EUD.user_id.not_in(with_groups)))


def _user_reads(session, user_id, read_groups):
    """Whether a connection authenticated as user_id (None for plain TCP) still reads a team
    chat message stored with read_groups."""
    from raven.models.Group import Group
    from raven.models.GroupUser import GroupUser

    if read_groups:
        if not user_id:
            return False
        return (
            session.execute(
                select(func.count())
                .select_from(GroupUser)
                .where(
                    GroupUser.user_id == user_id,
                    GroupUser.group_id.in_(read_groups),
                    GroupUser.direction == Group.OUT,
                    GroupUser.enabled.is_(True),
                )
            ).scalar()
            > 0
        )
    if not user_id:
        return True
    return (
        session.execute(
            select(func.count())
            .select_from(GroupUser)
            .where(GroupUser.user_id == user_id, GroupUser.direction == Group.OUT)
        ).scalar()
        == 0
    )


def _team_chat_recipients(session, chatroom, sender_uid, read_groups):
    from raven.models.EUD import EUD
    from raven.models.Team import Team

    if read_groups is None:
        return []
    team = session.execute(select(Team).filter_by(name=chatroom)).scalars().first()
    if not team:
        return []
    query = select(EUD).where(EUD.team_id == team.id, EUD.uid != sender_uid)
    return session.execute(_readers_where(query, read_groups)).scalars().all()


def _addressing(session, event, sender_uid, user_id=None, target_groups=None):
    """(recipients, read_groups): the euds rows a GeoChat event is addressed to (excluding the
    sender), and for team chat the group ids that may read it (None for <dest> addressing)."""
    from raven.models.EUD import EUD

    chat = event.find("__chat")
    if not chat or not event.find("remarks"):
        return [], None
    chatroom = chat.attrs.get("chatroom")
    if chat.attrs.get("id") == ALL_CHAT_ROOMS or chatroom == ALL_CHAT_ROOMS:
        return [], None

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

    read_groups = None
    if not has_dest and chatroom:
        read_groups = _read_groups(session, user_id, target_groups)
        for eud in _team_chat_recipients(session, chatroom, sender_uid, read_groups):
            recipients[eud.uid] = eud

    return [eud for uid, eud in recipients.items() if uid != sender_uid], read_groups


def queue_offline_chat(session, event, sender_uid, user_id=None, now=None, target_groups=None):
    """Stores a copy of a GeoChat event for each addressed device, connected or not (see the
    module docstring). Returns the number of rows queued. Never raises."""
    from raven.models.OfflineChatMessage import OfflineChatMessage

    try:
        message_uid = event.attrs.get("uid")
        if not message_uid or not sender_uid:
            return 0

        recipients, read_groups = _addressing(session, event, sender_uid, user_id, target_groups)
        recipients = [
            eud
            for eud in recipients
            if eud.platform not in NO_QUEUE_PLATFORMS and not eud.federated_from
        ]
        if not recipients:
            return 0

        already = set(
            session.execute(
                select(OfflineChatMessage.recipient_uid).where(
                    OfflineChatMessage.message_uid == message_uid,
                    OfflineChatMessage.recipient_uid.in_([e.uid for e in recipients]),
                )
            ).scalars()
        )
        chat = event.find("__chat")
        now = _naive(now) or utcnow_naive()
        xml = str(event)
        stored_groups = json.dumps(read_groups) if read_groups is not None else None
        queued = 0
        for eud in recipients:
            if eud.uid in already:
                continue
            session.add(
                OfflineChatMessage(
                    recipient_uid=eud.uid,
                    recipient_user_id=eud.user_id,
                    read_groups=stored_groups,
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
            logger.debug(f"Queued chat {message_uid} for {queued} device(s)")
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
        cutoff = (_naive(now) or utcnow_naive()) - timedelta(seconds=seconds)
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


def _entitled(session, message, user_id, cache):
    if message.recipient_user_id is not None and message.recipient_user_id != user_id:
        return False
    if message.read_groups is not None:
        try:
            groups = tuple(json.loads(message.read_groups))
        except (TypeError, ValueError):
            return False
        if groups not in cache:
            cache[groups] = _user_reads(session, user_id, list(groups))
        return cache[groups]
    return True


def deliver_pending(session, uid, send, now=None, user_id=None):
    """Sends the pending messages for uid with send(bytes), oldest first, stamping each one
    delivered as soon as it has been written. Stops at the first failed write; the rest stay
    queued for the next connection. Returns the number delivered.

    user_id is the user the connection is authenticated as (None for an unauthenticated one);
    messages it isn't entitled to are left queued. Messages created before the device's
    previous last_rx_at (minus RX_GRACE) were sent to it live and are stamped delivered
    without being resent."""
    from raven.models.EUD import EUD
    from raven.models.OfflineChatMessage import OfflineChatMessage

    last_rx = session.execute(select(EUD.last_rx_at).where(EUD.uid == uid)).scalar()
    if last_rx:
        session.execute(
            update(OfflineChatMessage)
            .where(
                OfflineChatMessage.recipient_uid == uid,
                OfflineChatMessage.delivered_at.is_(None),
                OfflineChatMessage.created_at < _naive(last_rx) - RX_GRACE,
            )
            .values(delivered_at=utcnow_naive())
            .execution_options(synchronize_session=False)
        )
        session.commit()
    delivered = 0
    cache = {}
    for message in pending_messages(session, uid, now):
        if not _entitled(session, message, user_id, cache):
            continue
        send(refresh_stale(message.xml).encode())
        message.delivered_at = utcnow_naive()
        session.commit()
        delivered += 1
    return delivered


def record_rx(session, uid, at=None):
    """Stamps euds.last_rx_at for a device the server just received data from."""
    from raven.models.EUD import EUD

    session.execute(
        update(EUD)
        .where(EUD.uid == uid)
        .values(last_rx_at=_naive(at) or utcnow_naive())
        .execution_options(synchronize_session=False)
    )
    session.commit()


def settle_live_deliveries(session, now=None):
    """Stamps delivered the queued rows of devices that are connected and have sent data more
    than TCP_USER_TIMEOUT after the row was queued: the live copy reached them. Returns the
    number of rows stamped."""
    from raven.models.EUD import EUD
    from raven.models.OfflineChatMessage import OfflineChatMessage

    now = _naive(now) or utcnow_naive()
    rows = session.execute(
        select(EUD.uid, EUD.last_rx_at).where(
            EUD.last_status == "Connected",
            EUD.last_rx_at.is_not(None),
            EUD.uid.in_(
                select(OfflineChatMessage.recipient_uid).where(
                    OfflineChatMessage.delivered_at.is_(None)
                )
            ),
        )
    ).all()
    settled = 0
    for uid, last_rx in rows:
        result = session.execute(
            update(OfflineChatMessage)
            .where(
                OfflineChatMessage.recipient_uid == uid,
                OfflineChatMessage.delivered_at.is_(None),
                OfflineChatMessage.created_at < _naive(last_rx) - TCP_USER_TIMEOUT,
            )
            .values(delivered_at=now)
            .execution_options(synchronize_session=False)
        )
        settled += result.rowcount or 0
    session.commit()
    return settled


def drop_queue(session, uids):
    """Deletes the undelivered messages queued for these devices (their certificate was
    revoked). Returns the number deleted. Never raises."""
    from raven.models.OfflineChatMessage import OfflineChatMessage

    uids = [u for u in uids if u]
    if not uids:
        return 0
    try:
        result = session.execute(
            delete(OfflineChatMessage)
            .where(
                OfflineChatMessage.recipient_uid.in_(uids),
                OfflineChatMessage.delivered_at.is_(None),
            )
            .execution_options(synchronize_session=False)
        )
        session.commit()
        return result.rowcount or 0
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to drop the offline chat queue of {uids}: {e}")
        return 0
