"""
Things a CoT can share with other users: data packages (b-f-t-r fileshare CoTs) and video
feeds (<__video> details). cot_parser calls these for every CoT; they live here, apart from
the cot_parser process, so they can be tested against a throwaway database.

Both used to trust the CoT alone, and any connected client can send any CoT:

* A forged fileshare naming someone else's package hash recorded the forger (or anyone they
  named) as a recipient, which grants download of that package, private or group-restricted,
  and its senderUid attribute could set the package's sender. Now recipients are only recorded
  when the user behind the sending connection may share the package -- its uploader, or for a
  public package anyone who can see it by group -- and the sender is only ever the sending
  connection's own EUD, never the senderUid in the CoT.
* A video CoT created a feed with no groups (visible to everyone), and on a uid/path collision
  rewrote the existing feed, whatever group it belonged to. Now a new feed gets the sending
  user's IN groups, as a Marti upload does, and an existing feed is only updated by someone
  who can see it.
"""

from datetime import datetime, timezone

from sqlalchemy import or_, select, update

from raven.group_isolation import assign_uploader_groups, can_see, is_admin
from raven.models.DataPackage import DataPackage
from raven.models.DataPackageRecipient import DataPackageRecipient
from raven.models.EUD import EUD
from raven.models.VideoStream import VideoStream


def parse_fileshare(event, sender_uid: str | None):
    """Pure XML extraction for a b-f-t-r (fileshare) CoT.

    Returns (sha256, fileshare_sender_uid, callsigns, uids) or None when the
    event is not a fileshare with a hash. Mission dests are ignored and the
    sender's own uid is dropped so it never gets recorded as a recipient.
    """
    if event.attrs.get("type") != "b-f-t-r":
        return None

    fileshare = event.find("fileshare")
    if not fileshare:
        return None

    sha256 = fileshare.attrs.get("sha256")
    if not sha256:
        return None

    fileshare_sender_uid = fileshare.attrs.get("senderUid") or None

    callsigns: list[str] = []
    uids: list[str] = []
    for dest in event.find_all("dest"):
        if "mission" in dest.attrs:
            continue
        callsign = dest.attrs.get("callsign")
        dest_uid = dest.attrs.get("uid")
        if callsign:
            if callsign not in callsigns:
                callsigns.append(callsign)
        elif dest_uid and dest_uid != sender_uid:
            if dest_uid not in uids:
                uids.append(dest_uid)

    return sha256, fileshare_sender_uid, callsigns, uids


def _user(session, user_id):
    if not user_id:
        return None
    from raven.models.user import User

    return session.get(User, user_id)


def _uploaded_by(session, data_package: DataPackage, user) -> bool:
    if data_package.submission_user is not None and data_package.submission_user == user.id:
        return True
    if data_package.creator_uid:
        owner = session.execute(
            select(EUD.user_id).where(EUD.uid == data_package.creator_uid)
        ).scalar()
        return owner is not None and owner == user.id
    return False


def may_share_data_package(session, data_package: DataPackage, user) -> bool:
    """Whether `user` may hand `data_package` to others with a fileshare CoT: its uploader,
    or, for a public package, anyone who can see it by group. A private package can only be
    shared on by whoever sent it."""
    if user is None or getattr(user, "id", None) is None:
        return False
    if _uploaded_by(session, data_package, user):
        return True
    if (data_package.tool or "").lower() == "private":
        return False
    return can_see(data_package, user)


def record_fileshare_recipients(session, event, uid: str | None, user_id, logger) -> None:
    """Remember who a data package was sent to, so downloads of a private one can be limited
    to the sender and the addressed recipients. `uid` and `user_id` identify the connection
    the CoT came in on (set by EudHandler), not anything in the CoT."""
    parsed = parse_fileshare(event, uid)
    if not parsed:
        return

    sha256, _fileshare_sender_uid, callsigns, uids = parsed
    if not callsigns and not uids:
        return

    data_package = session.execute(select(DataPackage).filter_by(hash=sha256)).scalar()
    if not data_package:
        # ATAK uploads before sending the CoT, so this should be rare
        logger.debug(f"No data package with hash {sha256} for fileshare CoT")
        return

    user = _user(session, user_id)
    if not may_share_data_package(session, data_package, user):
        logger.warning(
            f"Ignoring fileshare CoT from {uid} for data package {sha256}: "
            f"{user.username if user else 'an anonymous connection'} may not share it"
        )
        return

    # The download authorization relies on creator_uid to identify the sender. Only the
    # uploader's own sending EUD qualifies; the CoT's senderUid attribute is client-supplied.
    if not data_package.creator_uid and uid and data_package.submission_user == user.id:
        sender = session.execute(select(EUD).filter_by(uid=uid)).scalar()
        if sender and sender.user_id == user.id:
            data_package.creator_uid = uid

    recipients: list[tuple[str | None, str | None]] = []
    for callsign in callsigns:
        eud = session.execute(select(EUD).filter_by(callsign=callsign)).scalar()
        recipients.append((eud.uid if eud else None, callsign))
    for dest_uid in uids:
        eud = session.execute(select(EUD).filter_by(uid=dest_uid)).scalar()
        recipients.append((dest_uid, eud.callsign if eud else None))

    now = datetime.now(timezone.utc)
    for eud_uid, callsign in recipients:
        # Query first rather than relying on IntegrityError so one duplicate
        # doesn't roll back the other rows in this session
        existing = session.execute(
            select(DataPackageRecipient).filter_by(
                data_package_hash=sha256, eud_uid=eud_uid, callsign=callsign
            )
        ).scalar()
        if existing:
            continue
        session.add(
            DataPackageRecipient(
                data_package_hash=sha256,
                eud_uid=eud_uid,
                callsign=callsign,
                created_at=now,
            )
        )

    session.commit()


def may_update_video_stream(stream: VideoStream, user) -> bool:
    """Whether `user` may change an existing feed through a CoT: its owner, an administrator,
    or anyone who can see it by group (a feed with no groups is everyone's)."""
    if user is not None and stream.username and stream.username == user.username:
        return True
    if is_admin(user):
        return True
    return can_see(stream, user)


def upsert_cot_video(session, event, cot_pk, user_id, logger) -> None:
    """Adds or updates the video feed in a CoT's <__video> detail."""
    video = event.find("__video")
    if not video:
        return
    logger.debug("Got video stream")
    connection_entry = video.find("ConnectionEntry")
    if not connection_entry:
        return

    path = connection_entry.attrs["path"]
    if path.startswith("/"):
        path = path[1:]
    feed_uid = connection_entry.attrs["uid"]
    user = _user(session, user_id)

    existing = session.execute(
        select(VideoStream).where(or_(VideoStream.uid == feed_uid, VideoStream.path == path))
    ).scalars().all()

    if not existing:
        v = VideoStream()
        v.network_timeout = connection_entry.attrs["networkTimeout"]
        v.uid = feed_uid
        v.path = path
        v.protocol = connection_entry.attrs["protocol"]
        v.buffer_time = connection_entry.attrs["bufferTime"]
        v.port = connection_entry.attrs["port"]
        v.rover_port = connection_entry.attrs["roverPort"]
        v.rtsp_reliable = connection_entry.attrs["rtspReliable"]
        v.ignore_embedded_klv = connection_entry.attrs["ignoreEmbeddedKLV"].lower() == "true"
        v.alias = connection_entry.attrs["alias"]
        v.cot_id = cot_pk
        v.username = user.username if user else None
        v.generate_xml(connection_entry.attrs["address"])
        assign_uploader_groups(v, user)
        session.add(v)
        session.commit()
        logger.debug("Added video")
        return

    stream = next((s for s in existing if s.uid == feed_uid), None)
    if stream is None or any(s is not stream for s in existing):
        # The path belongs to a different feed (or the uid and path to two different ones)
        logger.warning(f"Ignoring video CoT for {path} ({feed_uid}): it collides with another feed")
        return
    if not may_update_video_stream(stream, user):
        logger.warning(
            f"Ignoring video CoT for {stream.path} ({feed_uid}) from "
            f"{user.username if user else 'an anonymous connection'}: not theirs to change"
        )
        return

    xml_source = VideoStream()
    xml_source.uid = feed_uid
    xml_source.path = path
    xml_source.port = connection_entry.attrs["port"]
    xml_source.rover_port = connection_entry.attrs["roverPort"]
    xml_source.ignore_embedded_klv = connection_entry.attrs["ignoreEmbeddedKLV"].lower() == "true"
    xml_source.alias = connection_entry.attrs["alias"]
    xml_source.buffer_time = connection_entry.attrs["bufferTime"]
    xml_source.network_timeout = connection_entry.attrs["networkTimeout"]
    xml_source.rtsp_reliable = connection_entry.attrs["rtspReliable"]
    xml_source.generate_xml(connection_entry.attrs["address"])

    session.execute(
        update(VideoStream)
        .where(VideoStream.uid == feed_uid)
        .values(
            network_timeout=connection_entry.attrs["networkTimeout"],
            protocol=connection_entry.attrs["protocol"],
            buffer_time=connection_entry.attrs["bufferTime"],
            port=connection_entry.attrs["port"],
            rover_port=connection_entry.attrs["roverPort"],
            rtsp_reliable=connection_entry.attrs["rtspReliable"],
            ignore_embedded_klv=(connection_entry.attrs["ignoreEmbeddedKLV"].lower() == "true"),
            alias=connection_entry.attrs["alias"],
            xml=xml_source.xml,
        )
    )
    session.commit()
