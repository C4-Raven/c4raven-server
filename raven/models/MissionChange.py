import datetime
import uuid
from dataclasses import dataclass
from xml.etree.ElementTree import Element, SubElement

import sqlalchemy.exc
from bs4 import BeautifulSoup
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, update
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db, logger
from raven.functions import iso8601_string_from_datetime
from raven.models.Mission import Mission
from raven.models.MissionContent import MissionContent
from raven.models.MissionUID import MissionUID


@dataclass
class MissionChange(db.Model):
    __tablename__ = "mission_changes"

    CREATE_MISSION = "CREATE_MISSION"
    DELETE_MISSION = "DELETE_MISSION"
    ADD_CONTENT = "ADD_CONTENT"
    REMOVE_CONTENT = "REMOVE_CONTENT"
    CREATE_DATA_FEED = "CREATE_DATA_FEED"
    DELETE_DATA_FEED = "DELETE_DATA_FEED"
    CHANGE = "CHANGE"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    content_uid: Mapped[str] = mapped_column(
        String(255), ForeignKey("mission_content.uid"), nullable=True
    )
    isFederatedChange: Mapped[bool] = mapped_column(Boolean)
    change_type: Mapped[str] = mapped_column(String(255))
    mission_name: Mapped[str] = mapped_column(String(255), ForeignKey("missions.name"))
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    creator_uid: Mapped[str] = mapped_column(String(255))
    server_time: Mapped[datetime] = mapped_column(DateTime)
    mission_uid: Mapped[str] = mapped_column(
        String(255), ForeignKey("mission_uids.uid", ondelete="CASCADE"), nullable=True
    )
    content_resource = relationship(
        "MissionContent", back_populates="mission_changes", uselist=False
    )
    mission = relationship("Mission", back_populates="mission_changes")
    uid = relationship("MissionUID", back_populates="mission_change", uselist=False)

    def serialize(self):
        return {
            "isFederatedChange": self.isFederatedChange,
            "change_type": self.change_type,
            "mission_name": self.mission_name,
            "timestamp": self.timestamp,
            "creator_uid": self.creator_uid,
            "server_time": self.server_time,
            "mission_uid": self.mission_uid,
            "content_uid": self.content_uid,
        }

    def to_json(self):
        json = {
            "isFederatedChange": self.isFederatedChange,
            "type": self.change_type,
            # A change adds either a file (content_uid) or a dropped marker
            # (mission_uid) -- generate_mission_change_cot() already reuses
            # the same "contentUid" tag name for both cases (see its line
            # setting <contentUid> from mission_change.mission_uid). The
            # client checks this field against the item UID it just
            # submitted, so leaving it null for marker changes reads back
            # as an "incompatibilities" rejection even though the change
            # itself was recorded correctly.
            "contentUid": self.content_uid or self.mission_uid,
            "missionName": self.mission_name,
            "timestamp": iso8601_string_from_datetime(self.timestamp),
            "creatorUid": self.creator_uid if self.creator_uid else "",
            "serverTime": iso8601_string_from_datetime(self.server_time),
            "missionGuid": self.mission.guid if self.mission else None,
        }

        if self.content_resource:
            json["contentResource"] = self.content_resource.to_json()["data"]
            # Real TAK server clients (e.g. goatak's MissionChangeDTO) carry
            # the content's hash as its own top-level field, not just nested
            # inside contentResource -- a client verifying its upload landed
            # intact would check this directly against the hash it computed
            # before uploading.
            json["contentHash"] = self.content_resource.hash

        if self.uid:
            json["details"] = self.uid.to_details_json()

        return json


def generate_mission_change_cot(
    mission_name: str,
    mission: Mission = None,
    mission_change: MissionChange = None,
    content: MissionContent | None = None,
    cot_event: BeautifulSoup | None = None,
    mission_uid: MissionUID = None,
    cot_type: str = "t-x-m-c",
) -> Element:
    if content:
        uid = content.uid
    elif cot_event:
        uid = cot_event.attrs["uid"]
    else:
        uid = str(uuid.uuid4())

    event = Element(
        "event",
        {
            "version": "2.0",
            "uid": str(uid),
            "type": cot_type,
            "how": "h-g-i-g-o",
            "start": iso8601_string_from_datetime(mission_change.timestamp),
            "time": iso8601_string_from_datetime(mission_change.timestamp),
            "stale": iso8601_string_from_datetime(
                mission_change.timestamp + datetime.timedelta(minutes=2)
            ),
            "access": "Undefined",
        },
    )
    SubElement(
        event, "point", {"ce": "9999999", "le": "9999999", "hae": "0.0", "lat": "0.0", "lon": "0.0"}
    )

    if not mission:
        mission = db.session.execute(db.session.query(Mission).filter_by(name=mission_name)).scalar()

    detail = SubElement(event, "detail")
    mission_element = SubElement(
        detail,
        "mission",
        {
            # TAK Server stamps every change notification type="CHANGE" (like CREATE/DELETE/INVITE on the
            # other t-x-m-* messages); the ADD_CONTENT/REMOVE_CONTENT kind is the <type> element below
            "type": Mission.CHANGE,
            "tool": mission.tool or "public",
            "name": mission_name,
            "guid": str(mission.guid),
            "authorUid": str(mission_change.creator_uid),
        },
    )
    mission_changes_element = SubElement(mission_element, "MissionChanges")
    mission_change_element = SubElement(mission_changes_element, "MissionChange")

    if content:
        content_resource = SubElement(mission_change_element, "contentResource")
        SubElement(content_resource, "creatorUid").text = mission_change.creator_uid
        SubElement(content_resource, "expiration").text = "-1"
        SubElement(content_resource, "groupVector").text = "0"
        SubElement(content_resource, "hash").text = content.hash
        SubElement(content_resource, "mimeType").text = content.mime_type
        SubElement(content_resource, "name").text = content.filename
        SubElement(content_resource, "size").text = str(content.size)
        SubElement(content_resource, "submissionTime").text = iso8601_string_from_datetime(
            content.submission_time
        )
        SubElement(content_resource, "submitter").text = content.submitter
        SubElement(content_resource, "uid").text = content.uid
        SubElement(mission_change_element, "contentUid").text = mission_change.content_uid

    if cot_event:
        details_tag = SubElement(
            mission_change_element, "details", {"type": cot_event.attrs["type"]}
        )

        point = cot_event.find("point")
        color = cot_event.find("color")
        callsign = cot_event.find("contact")
        icon = cot_event.find("usericon")

        if color and "argb" in color.attrs:
            details_tag.set("color", color.attrs["argb"])
        if color and "value" in color.attrs:
            details_tag.set("color", color.attrs["value"])
        # BeautifulSoup's xml parser preserves attribute case, so a <contact> with no
        # callsign or a <usericon iconsetPath=...> (as ATAK writes it) must not KeyError.
        if callsign and callsign.attrs.get("callsign"):
            details_tag.set("callsign", callsign.attrs.get("callsign"))
        if icon:
            iconset_path = icon.attrs.get("iconsetpath") or icon.attrs.get("iconsetPath")
            if iconset_path:
                details_tag.set("iconsetPath", iconset_path)

        if point and point.attrs.get("lat") is not None and point.attrs.get("lon") is not None:
            SubElement(
                details_tag, "location", {"lon": point.attrs.get("lon"), "lat": point.attrs.get("lat")}
            )
        # SubElement(mission_change_element, "contentUid").text = cot_event.attrs['uid']

    if mission_uid:
        details_tag = SubElement(mission_change_element, "details")
        if mission_uid.color:
            details_tag.set("color", str(mission_uid.color))
        if mission_uid.callsign:
            details_tag.set("callsign", mission_uid.callsign)
        if mission_uid.cot_type:
            details_tag.set("type", mission_uid.cot_type)
        if mission_uid.iconset_path:
            details_tag.set("iconsetPath", mission_uid.iconset_path)
        if mission_uid.longitude:
            SubElement(
                details_tag,
                "location",
                {"lon": str(mission_uid.longitude), "lat": str(mission_uid.latitude)},
            )

    if mission_change.mission_uid:
        SubElement(mission_change_element, "contentUid").text = mission_change.mission_uid

    SubElement(mission_change_element, "missionGuid").text = mission.guid
    SubElement(mission_change_element, "creatorUid").text = mission_change.creator_uid
    SubElement(mission_change_element, "isFederatedChange").text = str(
        mission_change.isFederatedChange
    ).lower()
    SubElement(mission_change_element, "missionName").text = mission.name
    SubElement(mission_change_element, "timestamp").text = iso8601_string_from_datetime(
        mission_change.timestamp
    )
    SubElement(mission_change_element, "type").text = mission_change.change_type

    return event


def upsert_mission_uid_and_change(
    mission_name: str,
    mission: Mission,
    item_uid: str,
    creator_uid: str | None,
    timestamp: datetime.datetime,
    cot_type: str | None = None,
    callsign: str | None = None,
    iconset_path: str | None = None,
    color: str | None = None,
    latitude: float | None = None,
    longitude: float | None = None,
) -> tuple[MissionUID, "MissionChange", Element]:
    """Upserts a single (mission, item_uid) map-item and its change record.

    This is the one place that turns "a marker was added/re-synced to a
    mission" into MissionUID + MissionChange rows and a change CoT to
    broadcast -- three call sites (add_content()'s and mission_contents()'s
    map-item handling in the Marti API, and CoTController.generate_mission_change()
    in the regular CoT ingestion path) each grew their own copy of this with
    diverging bugs (a missing WHERE clause that clobbered the whole
    mission_uids table, a fallback update that dropped mission_name and
    silently reattached a uid to the wrong mission, and an unconditional
    insert that piled up duplicate MissionChange rows for the same item on
    every re-sync). This is the single, consistent version: exactly one
    MissionUID and one MissionChange row per (mission_name, item_uid), and
    both always get refreshed and a change CoT regenerated even when they
    already existed -- a client re-syncing an item (it moved, its icon
    changed) is expected to notify subscribers again, not go silent after
    the first sighting.

    A cot_type/callsign/iconset_path/color/latitude/longitude left as None
    means "no new value from this call" and leaves the existing column
    alone (this is what lets mission_contents() insert a bare uid before
    its CoT has even arrived -- cot_parser's own parse_point fills these in
    later) -- it does not clear a previously-known value.

    Returns (mission_uid, mission_change, change_cot); publishing change_cot
    is left to the caller, since cot_parser.py holds a long-lived RabbitMQ
    channel while the Marti API opens a fresh connection per call.
    """
    mission_uid = db.session.execute(
        db.session.query(MissionUID).filter_by(uid=item_uid, mission_name=mission_name)
    ).first()
    mission_uid = mission_uid[0] if mission_uid else MissionUID()
    mission_uid.uid = item_uid
    mission_uid.mission_name = mission_name
    mission_uid.timestamp = timestamp
    mission_uid.creator_uid = creator_uid
    if cot_type is not None:
        mission_uid.cot_type = cot_type
    if callsign is not None:
        mission_uid.callsign = callsign
    if iconset_path is not None:
        mission_uid.iconset_path = iconset_path
    if color is not None:
        mission_uid.color = color
    if latitude is not None:
        mission_uid.latitude = latitude
    if longitude is not None:
        mission_uid.longitude = longitude

    try:
        db.session.add(mission_uid)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        # uid is MissionUID's sole primary key (not scoped per-mission), so
        # this collision means the uid already exists -- possibly under a
        # different mission. Reattaching it here (mission_name included
        # explicitly, since serialize() doesn't carry it) matches "adding"
        # an item that already belongs elsewhere: it moves to this mission.
        db.session.rollback()
        # Only overwrite the columns this call actually supplied -- serialize() emits
        # None for everything else, which would null out the existing row's
        # cot_type/callsign/iconset_path/color/lat/lon (see docstring).
        values = {
            "mission_name": mission_name,
            "timestamp": timestamp,
            "creator_uid": creator_uid,
        }
        for column, value in (
            ("cot_type", cot_type),
            ("callsign", callsign),
            ("iconset_path", iconset_path),
            ("color", color),
            ("latitude", latitude),
            ("longitude", longitude),
        ):
            if value is not None:
                values[column] = value
        db.session.execute(update(MissionUID).where(MissionUID.uid == item_uid).values(**values))
        db.session.commit()
        # Re-read the persistent row so the change CoT below carries the merged
        # (existing + newly supplied) values rather than the detached transient.
        mission_uid = db.session.execute(
            db.session.query(MissionUID).filter_by(uid=item_uid)
        ).scalar_one()

    # Filter on change_type too: delete_content() leaves a REMOVE_CONTENT row for
    # this uid, and reusing it here would broadcast a re-add as <type>REMOVE_CONTENT</type>.
    mission_change = db.session.execute(
        db.session.query(MissionChange).filter_by(
            mission_uid=item_uid, mission_name=mission_name, change_type=MissionChange.ADD_CONTENT
        )
    ).first()
    if mission_change:
        mission_change = mission_change[0]
    else:
        mission_change = MissionChange()
        mission_change.isFederatedChange = False
        mission_change.mission_uid = item_uid
        mission_change.mission_name = mission_name
        db.session.add(mission_change)

    mission_change.change_type = MissionChange.ADD_CONTENT
    mission_change.creator_uid = creator_uid
    mission_change.timestamp = timestamp
    mission_change.server_time = datetime.datetime.now(datetime.timezone.utc)
    db.session.commit()

    change_cot = generate_mission_change_cot(
        mission_name, mission, mission_change, mission_uid=mission_uid
    )

    return mission_uid, mission_change, change_cot
