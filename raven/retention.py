"""
Per data type retention (the admin "Data retention" tab, raven/blueprints/raven_api/retention_api.py).

Each entry in DATA_TYPES says how to count, size and purge one kind of data. How long it is kept
is stored in retention_settings (raven/models/RetentionSetting.py); a type with no row uses its
default. Every default is "keep forever", which is what the server did before this existed
(the legacy delete_old_data job is paused out of the box), except the offline chat queue, which
holds messages for 48 hours.

apply_retention() is the apply_data_retention scheduled job. It deletes in batches of
BATCH_SIZE rows with a commit after each batch, so no table is locked for long, and stops a type
after MAX_SECONDS_PER_TYPE so a large backlog is worked off over several runs instead of one
run holding everything up. Files on disk (data packages, video recordings) are only removed
after the rows that point at them are committed, so a failed commit never leaves a row whose
file is gone.

Cutoffs: almost every timestamp column is written from timezone-aware UTC datetimes
(datetime_from_iso8601_string, datetime.now(timezone.utc)), so those are compared with an aware
UTC cutoff, which Postgres converts the same way it converted the writes. Columns written as
naive UTC (audit_events, offline_chat_messages) get a naive UTC cutoff.

Device clocks: CoT, position, chat, alert, CasEvac, R&B line and device statistics times are the
device's own CoT times, and there is no server receive time to use instead. A device with a
broken clock must neither keep its rows forever (dated 2099) nor lose fresh rows on the next run
(dated 1970). So a row whose time is implausible -- before 2000, more than a day in the future,
or missing -- is aged by receive order instead (see _aged): it goes once a row with a plausible
time that was received after it (a higher id) is itself past the cutoff. Mission change logs
are aged by their server_time where they have one.

Mission data: CoTs that are Data Sync mission content (cot.mission_name, or a uid in
mission_uids that belongs to a mission) are never purged, and the latest ADD_CONTENT change of
every item still in a mission is kept so the mission's change log still says how it got there.
"""

import os
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from flask import current_app as app
from sqlalchemy import and_, delete, func, or_, select, text, union

from raven.extensions import db, logger

OFFLINE_CHAT = "offline_chat"
# Device times before this, or more than FUTURE_SLACK ahead of now, are not believed
EARLIEST_PLAUSIBLE = datetime(2000, 1, 1, tzinfo=timezone.utc)
FUTURE_SLACK = timedelta(days=1)
BATCH_SIZE = 1000
MAX_SECONDS_PER_TYPE = 120
MIN_KEEP_SECONDS = 3600
MAX_KEEP_SECONDS = 3650 * 86400
# Tables this big get Postgres' row estimate instead of an exact count(*).
EXACT_COUNT_LIMIT = 100_000


def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class DataType:
    key: str
    label: str
    description: str
    default_seconds: int | None
    # (session) -> number of rows/files
    count: Callable
    # (cutoff_aware, cutoff_naive, deadline) -> number of rows/files deleted
    purge: Callable
    # tables whose on-disk size is reported (Postgres only)
    tables: tuple = ()
    # (session) -> bytes of files on disk, for types that have them
    file_bytes: Callable | None = None
    has_files: bool = False
    extra: dict = field(default_factory=dict)


# --- helpers ---


def _count(model, *where):
    query = select(func.count()).select_from(model)
    for clause in where:
        query = query.where(clause)
    return db.session.execute(query).scalar() or 0


def _estimated_count(model, table_name):
    """count(*) for small tables; Postgres' planner estimate once a table is big, since an
    exact count of millions of CoT rows is slow. Returns (count, approximate)."""
    if db.engine.dialect.name == "postgresql":
        try:
            estimate = db.session.execute(
                text("SELECT reltuples::bigint FROM pg_class WHERE relname = :t"),
                {"t": table_name},
            ).scalar()
            if estimate is not None and estimate > EXACT_COUNT_LIMIT:
                return int(estimate), True
        except Exception:
            db.session.rollback()
    return _count(model), False


def _table_bytes(tables):
    if db.engine.dialect.name != "postgresql" or not tables:
        return None
    total = 0
    try:
        for table in tables:
            total += (
                db.session.execute(
                    text("SELECT pg_total_relation_size(to_regclass(:t))"), {"t": table}
                ).scalar()
                or 0
            )
    except Exception:
        db.session.rollback()
        return None
    return total


def _delete_in_batches(model, pk, where, deadline, before_delete=None):
    """Deletes rows of model matching where, BATCH_SIZE at a time, committing after each batch.
    before_delete(ids) may return a list of file paths; they are removed after that batch is
    committed. Returns the number of rows deleted."""
    total = 0
    while True:
        ids = db.session.execute(select(pk).where(where).limit(BATCH_SIZE)).scalars().all()
        if not ids:
            break
        files = before_delete(ids) if before_delete else []
        db.session.execute(delete(model).where(pk.in_(ids)).execution_options(synchronize_session=False))
        db.session.commit()
        total += len(ids)
        for path in files or []:
            _remove_file(path)
        if len(ids) < BATCH_SIZE or time.monotonic() > deadline:
            break
    return total


def _remove_file(path):
    try:
        if path and os.path.isfile(path) and not os.path.islink(path):
            os.remove(path)
    except OSError as e:
        logger.warning(f"Data retention: could not delete {path}: {e}")


def _not_null_ids(column):
    return select(column).where(column.is_not(None))


def _aged(column, order, cutoff, now):
    """Where clause for rows past the cutoff by a device-supplied time column. Rows with an
    implausible or missing time are aged by receive order (order: an increasing id) instead:
    they go once a row with a plausible time and a higher id is past the cutoff. The boundary
    is worked out once, before anything is deleted, since deleting changes it."""
    plausible_old = and_(column >= EARLIEST_PLAUSIBLE, column < cutoff)
    boundary = db.session.execute(select(func.max(order)).where(plausible_old)).scalar()
    if boundary is None:
        return plausible_old
    implausible = or_(
        column.is_(None), column < EARLIEST_PLAUSIBLE, column > now + FUTURE_SLACK
    )
    return or_(plausible_old, and_(implausible, order < boundary))


def _mission_cot_uids():
    from raven.models.MissionUID import MissionUID

    return select(MissionUID.uid).where(MissionUID.mission_name.is_not(None))


# --- CoT and positions ---


def _referenced_point_ids():
    from raven.models.Alert import Alert
    from raven.models.CasEvac import CasEvac
    from raven.models.CITrap import CITrap
    from raven.models.GeoChat import GeoChat
    from raven.models.Marker import Marker
    from raven.models.RBLine import RBLine

    return union(
        _not_null_ids(Marker.point_id),
        _not_null_ids(Alert.point_id),
        _not_null_ids(CasEvac.point_id),
        _not_null_ids(GeoChat.point_id),
        _not_null_ids(RBLine.point_id),
        _not_null_ids(CITrap.point_id),
    )


def _purge_cot(cutoff, cutoff_naive, deadline, now):
    """Old CoT history and positions. Rows that something kept is still built on are left
    alone: the current CoT/point of a marker, alert, CasEvac, chat message, R&B line or video
    stream (deleting those CoTs would cascade into them), and CoTs that are Data Sync mission
    content (by mission_name, or by a uid that is in a mission)."""
    from raven.models.Alert import Alert
    from raven.models.CasEvac import CasEvac
    from raven.models.CoT import CoT
    from raven.models.GeoChat import GeoChat
    from raven.models.Marker import Marker
    from raven.models.Point import Point
    from raven.models.RBLine import RBLine
    from raven.models.VideoStream import VideoStream

    referenced_points = _referenced_point_ids()
    deleted = _delete_in_batches(
        Point,
        Point.id,
        and_(
            _aged(Point.timestamp, Point.id, cutoff, now), Point.id.not_in(referenced_points)
        ),
        deadline,
    )

    referenced_cots = union(
        _not_null_ids(Marker.cot_id),
        _not_null_ids(Alert.cot_id),
        _not_null_ids(CasEvac.cot_id),
        _not_null_ids(GeoChat.cot_id),
        _not_null_ids(RBLine.cot_id),
        _not_null_ids(VideoStream.cot_id),
        select(Point.cot_id).where(
            Point.cot_id.is_not(None), Point.id.in_(_referenced_point_ids())
        ),
    )
    deleted += _delete_in_batches(
        CoT,
        CoT.id,
        and_(
            _aged(CoT.timestamp, CoT.id, cutoff, now),
            CoT.mission_name.is_(None),
            or_(CoT.uid.is_(None), CoT.uid.not_in(_mission_cot_uids())),
            CoT.id.not_in(referenced_cots),
        ),
        deadline,
    )
    return deleted


def _count_cot():
    from raven.models.CoT import CoT

    return _estimated_count(CoT, "cot")


# --- simple tables ---


def _simple(model_path, column_name, naive=False, device_time=False, order_name=None):
    """Purge by one time column. naive: written as naive UTC by the server. device_time: the
    device's own time, aged with _aged (order_name: the increasing column to age implausible
    times by, the primary key by default)."""

    def purge(cutoff, cutoff_naive, deadline, now):
        model = _model(model_path)
        column = getattr(model, column_name)
        pk = model.__mapper__.primary_key[0]
        if device_time:
            order = getattr(model, order_name) if order_name else pk
            where = _aged(column, order, cutoff, now)
        else:
            where = column < (cutoff_naive if naive else cutoff)
        return _delete_in_batches(model, pk, where, deadline)

    return purge


def _simple_count(model_path, table_name=None):
    def count():
        model = _model(model_path)
        if table_name:
            return _estimated_count(model, table_name)
        return _count(model), False

    return count


def _model(path):
    module, name = path.rsplit(":", 1)
    return getattr(__import__(module, fromlist=[name]), name)


# --- markers and R&B lines ---


def _purge_markers(cutoff, cutoff_naive, deadline, now):
    """Markers whose latest CoT is older than the cutoff (Marker.production_time is a string,
    so the CoT's timestamp is used instead), and old range & bearing lines."""
    from raven.models.CoT import CoT
    from raven.models.Marker import Marker
    from raven.models.RBLine import RBLine

    deleted = _delete_in_batches(
        Marker,
        Marker.id,
        Marker.cot_id.in_(select(CoT.id).where(_aged(CoT.timestamp, CoT.id, cutoff, now))),
        deadline,
    )
    deleted += _delete_in_batches(
        RBLine, RBLine.id, _aged(RBLine.timestamp, RBLine.id, cutoff, now), deadline
    )
    return deleted


def _count_markers():
    from raven.models.Marker import Marker
    from raven.models.RBLine import RBLine

    return _count(Marker) + _count(RBLine), False


# --- data packages ---


def _data_package_path(file_hash):
    # The hash comes from the database, but never let it name anything outside the folder
    if not file_hash or os.path.basename(file_hash) != file_hash or file_hash.startswith("."):
        return None
    return os.path.join(app.config.get("UPLOAD_FOLDER"), f"{file_hash}.zip")


def _purge_data_packages(cutoff, cutoff_naive, deadline, now):
    """Old uploaded data packages and their .zip files. Packages an admin set to install on
    enrollment or connection, and enrollment packages tied to a certificate, are kept."""
    from raven.models.Certificate import Certificate
    from raven.models.DataPackage import DataPackage
    from raven.models.DataPackageRecipient import DataPackageRecipient

    def files(ids):
        hashes = db.session.execute(
            select(DataPackage.hash).where(DataPackage.id.in_(ids))
        ).scalars()
        # Recipient rows cascade in Postgres; delete them explicitly so it doesn't matter
        db.session.execute(
            delete(DataPackageRecipient)
            .where(
                DataPackageRecipient.data_package_hash.in_(
                    select(DataPackage.hash).where(DataPackage.id.in_(ids))
                )
            )
            .execution_options(synchronize_session=False)
        )
        return [_data_package_path(h) for h in hashes]

    return _delete_in_batches(
        DataPackage,
        DataPackage.id,
        and_(
            DataPackage.submission_time < cutoff,
            or_(DataPackage.install_on_enrollment.is_(None), DataPackage.install_on_enrollment.is_(False)),
            or_(DataPackage.install_on_connection.is_(None), DataPackage.install_on_connection.is_(False)),
            DataPackage.id.not_in(_not_null_ids(Certificate.data_package_id)),
        ),
        deadline,
        before_delete=files,
    )


def _data_package_bytes():
    from raven.models.DataPackage import DataPackage

    return db.session.execute(select(func.coalesce(func.sum(DataPackage.size), 0))).scalar() or 0


# --- video recordings ---


def _purge_video_recordings(cutoff, cutoff_naive, deadline, now):
    """Finished recordings older than the cutoff, with their segment file and thumbnail.
    segment_path comes from the MediaMTX webhook, so a file is only removed if it resolves to
    somewhere inside the recordings folder; the row of one that doesn't is still deleted."""
    from raven.models.VideoRecording import VideoRecording
    from raven.recordings import contained_recording_path

    def files(ids):
        paths = []
        for segment in db.session.execute(
            select(VideoRecording.segment_path).where(VideoRecording.id.in_(ids))
        ).scalars():
            if not segment:
                continue
            for candidate in (segment, segment + ".png"):
                resolved = contained_recording_path(candidate)
                if resolved:
                    paths.append(resolved)
                elif candidate == segment:
                    logger.warning(
                        f"Data retention: not deleting {segment!r}, it is outside the "
                        "recordings folder"
                    )
        return paths

    return _delete_in_batches(
        VideoRecording,
        VideoRecording.id,
        and_(
            or_(VideoRecording.in_progress.is_(None), VideoRecording.in_progress.is_(False)),
            func.coalesce(VideoRecording.stop_time, VideoRecording.start_time) < cutoff,
        ),
        deadline,
        before_delete=files,
    )


def _video_bytes():
    from raven.models.VideoRecording import VideoRecording

    return (
        db.session.execute(select(func.coalesce(func.sum(VideoRecording.file_size), 0))).scalar()
        or 0
    )


# --- mission change logs ---


def _purge_mission_changes(cutoff, cutoff_naive, deadline, now):
    """Old mission change log entries, aged by server_time (timestamp for rows without one).
    The latest ADD_CONTENT change of each item still in a mission is kept."""
    from raven.models.MissionChange import MissionChange
    from raven.models.MissionContent import MissionContent
    from raven.models.MissionContentMission import MissionContentMission
    from raven.models.MissionUID import MissionUID

    added = MissionChange.change_type == MissionChange.ADD_CONTENT
    still_in_mission_content = (
        select(func.max(MissionChange.id))
        .join(MissionContent, MissionContent.uid == MissionChange.content_uid)
        .join(
            MissionContentMission,
            and_(
                MissionContentMission.mission_content_id == MissionContent.id,
                MissionContentMission.mission_name == MissionChange.mission_name,
            ),
        )
        .where(added)
        .group_by(MissionChange.mission_name, MissionChange.content_uid)
    )
    still_in_mission_uids = (
        select(func.max(MissionChange.id))
        .join(
            MissionUID,
            and_(
                MissionUID.uid == MissionChange.mission_uid,
                MissionUID.mission_name == MissionChange.mission_name,
            ),
        )
        .where(added)
        .group_by(MissionChange.mission_name, MissionChange.mission_uid)
    )
    keep = union(still_in_mission_content, still_in_mission_uids)
    when = func.coalesce(MissionChange.server_time, MissionChange.timestamp)
    return _delete_in_batches(
        MissionChange,
        MissionChange.id,
        and_(_aged(when, MissionChange.id, cutoff, now), MissionChange.id.not_in(keep)),
        deadline,
    )


# --- error logs ---


def _rotated_log_files():
    """(path, mtime, size) of rotated log files only; the file a process is writing to is
    never touched (log rotation's own RAVEN_BACKUP_COUNT limit still applies too)."""
    from raven.blueprints.raven_api.error_log_api import LOG_FILE_RE

    folder = os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs")
    out = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for name in names:
        match = LOG_FILE_RE.match(name)
        if not match or not match.group("suffix"):
            continue
        path = os.path.join(folder, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        out.append((path, st.st_mtime, st.st_size))
    return out


def _log_files():
    folder = os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs")
    total = 0
    count = 0
    try:
        for entry in os.scandir(folder):
            if entry.is_file(follow_symlinks=False) and ".log" in entry.name:
                total += entry.stat().st_size
                count += 1
    except OSError:
        pass
    return count, total


def _purge_error_logs(cutoff, cutoff_naive, deadline, now):
    deleted = 0
    for path, mtime, _ in _rotated_log_files():
        if mtime < cutoff.timestamp():
            try:
                os.remove(path)
                deleted += 1
            except OSError as e:
                logger.warning(f"Data retention: could not delete {path}: {e}")
    return deleted


DATA_TYPES = [
    DataType(
        "cot",
        "CoT history and positions",
        "Every CoT message received and the position history of devices. The latest position "
        "of anything still kept (a marker, alert, CasEvac, chat message) and Data Sync mission "
        "content are never removed by this setting.",
        None,
        _count_cot,
        _purge_cot,
        tables=("cot", "points"),
    ),
    DataType(
        "geochat",
        "Chat messages",
        "GeoChat messages and direct messages stored on the server.",
        None,
        _simple_count("raven.models.GeoChat:GeoChat"),
        _simple("raven.models.GeoChat:GeoChat", "timestamp", device_time=True, order_name="cot_id"),
        tables=("geochat",),
    ),
    DataType(
        "alerts",
        "Alerts",
        "Emergency alerts (911, ring the bell, in contact...).",
        None,
        _simple_count("raven.models.Alert:Alert"),
        _simple("raven.models.Alert:Alert", "start_time", device_time=True),
        tables=("alerts",),
    ),
    DataType(
        "casevac",
        "CasEvac requests",
        "9-line MEDEVAC requests.",
        None,
        _simple_count("raven.models.CasEvac:CasEvac"),
        _simple("raven.models.CasEvac:CasEvac", "timestamp", device_time=True),
        tables=("casevac",),
    ),
    DataType(
        "markers",
        "Markers and R&B lines",
        "Map markers and range & bearing lines, by when they were last updated. Removing them "
        "here does not remove them from devices' maps.",
        None,
        _count_markers,
        _purge_markers,
        tables=("markers", "rb_lines"),
    ),
    DataType(
        "data_packages",
        "Data packages",
        "Uploaded data packages and their files on disk. Packages set to install on enrollment "
        "or connection, and enrollment packages, are kept.",
        None,
        _simple_count("raven.models.DataPackage:DataPackage"),
        _purge_data_packages,
        file_bytes=_data_package_bytes,
        has_files=True,
    ),
    DataType(
        "video_recordings",
        "Video recordings",
        "Finished video recordings and their files on disk. Recordings in progress are kept.",
        None,
        _simple_count("raven.models.VideoRecording:VideoRecording"),
        _purge_video_recordings,
        file_bytes=_video_bytes,
        has_files=True,
    ),
    DataType(
        "eud_stats",
        "Device statistics",
        "Battery, memory and network statistics reported by devices.",
        None,
        _simple_count("raven.models.EUDStats:EUDStats", "eud_stats"),
        _simple("raven.models.EUDStats:EUDStats", "timestamp", device_time=True),
        tables=("eud_stats",),
    ),
    DataType(
        "audit_events",
        "Security audit events",
        "Sign-in, enrollment and administration events shown in the Security Audit tab.",
        None,
        _simple_count("raven.models.AuditEvent:AuditEvent"),
        _simple("raven.models.AuditEvent:AuditEvent", "timestamp", naive=True),
        tables=("audit_events",),
    ),
    DataType(
        "error_logs",
        "Rotated log files",
        "Older server log files. The log files currently being written are never deleted, and "
        "log rotation still keeps at most RAVEN_BACKUP_COUNT old files per log.",
        None,
        lambda: (_log_files()[0], False),
        _purge_error_logs,
        file_bytes=lambda: _log_files()[1],
        has_files=True,
    ),
    DataType(
        "mission_changes",
        "Mission change logs",
        "The change history of Data Sync missions. The change that added each item still in a "
        "mission is kept.",
        None,
        _simple_count("raven.models.MissionChange:MissionChange"),
        _purge_mission_changes,
        tables=("mission_changes",),
    ),
    DataType(
        OFFLINE_CHAT,
        "Offline chat queue",
        "Chat messages and direct messages held for devices that were offline when they were "
        "sent. They are delivered when the device reconnects within this time, and dropped "
        "after it.",
        48 * 3600,
        _simple_count("raven.models.OfflineChatMessage:OfflineChatMessage"),
        _simple("raven.models.OfflineChatMessage:OfflineChatMessage", "created_at", naive=True),
        tables=("offline_chat_messages",),
    ),
]

DATA_TYPES_BY_KEY = {t.key: t for t in DATA_TYPES}


# --- settings ---


def _rows():
    from raven.models.RetentionSetting import RetentionSetting

    return {r.data_type: r for r in db.session.execute(select(RetentionSetting)).scalars()}


def keep_seconds(key, session=None):
    """The configured retention of one type in seconds, or None for keep forever."""
    from raven.models.RetentionSetting import RetentionSetting

    session = session or db.session
    row = session.get(RetentionSetting, key)
    if row is not None and row.customized:
        return row.keep_seconds
    return DATA_TYPES_BY_KEY[key].default_seconds


def validate_keep_seconds(value):
    """Returns (seconds or None, error message or None)."""
    if value is None:
        return None, None
    if isinstance(value, bool) or not isinstance(value, int):
        return None, "keep_seconds must be a whole number of seconds or null"
    if value < MIN_KEEP_SECONDS or value > MAX_KEEP_SECONDS:
        return None, f"keep_seconds must be between {MIN_KEEP_SECONDS} and {MAX_KEEP_SECONDS}"
    return value, None


def update_settings(changes: dict, actor: str | None):
    """changes: {data_type: keep_seconds or None}, already validated. Returns the list of
    (data_type, old, new) that actually changed."""
    from raven.models.RetentionSetting import RetentionSetting

    rows = _rows()
    changed = []
    now = utcnow_naive()
    for key, seconds in changes.items():
        old = keep_seconds(key)
        row = rows.get(key)
        if row is None:
            row = RetentionSetting(data_type=key)
            db.session.add(row)
        if row.customized and row.keep_seconds == seconds:
            continue
        row.keep_seconds = seconds
        row.customized = True
        row.updated_at = now
        row.updated_by = actor
        if old != seconds:
            changed.append((key, old, seconds))
    db.session.commit()
    return changed


def describe_seconds(seconds):
    if seconds is None:
        return "forever"
    if seconds % 86400 == 0:
        days = seconds // 86400
        return f"{days} day" if days == 1 else f"{days} days"
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    return f"{seconds} seconds"


def report():
    """Settings, current size and last purge of every type, for the admin API."""
    rows = _rows()
    out = []
    for data_type in DATA_TYPES:
        row = rows.get(data_type.key)
        try:
            count, approximate = data_type.count()
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Data retention: could not count {data_type.key}: {e}")
            count, approximate = None, False
        size = None
        try:
            if data_type.file_bytes:
                size = data_type.file_bytes()
            else:
                size = _table_bytes(data_type.tables)
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Data retention: could not size {data_type.key}: {e}")
        customized = bool(row and row.customized)
        out.append(
            {
                "key": data_type.key,
                "label": data_type.label,
                "description": data_type.description,
                "keep_seconds": row.keep_seconds if customized else data_type.default_seconds,
                "default_seconds": data_type.default_seconds,
                "customized": customized,
                "has_files": data_type.has_files,
                "count": count,
                "count_approximate": approximate,
                "size_bytes": size,
                "updated_at": _iso(row.updated_at) if row else None,
                "updated_by": row.updated_by if row else None,
                "last_purge_at": _iso(row.last_purge_at) if row else None,
                "last_purge_count": row.last_purge_count if row else None,
                "last_purge_error": row.last_purge_error if row else None,
            }
        )
    return out


def _iso(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat() if dt else None


# --- the purge job ---


def apply_retention(now: datetime | None = None, only: list[str] | None = None):
    """Deletes everything older than its type's retention. Returns {data_type: deleted}.
    One type failing is logged and recorded on its row; the others still run."""
    from raven.models.RetentionSetting import RetentionSetting

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    results = {}
    if not only or OFFLINE_CHAT in only:
        # Whatever the offline chat retention, stop holding messages connected devices
        # demonstrably got live (raven/offline_chat.py)
        try:
            from raven import offline_chat

            offline_chat.settle_live_deliveries(db.session, now)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Data retention: could not settle offline chat deliveries: {e}")
    for data_type in DATA_TYPES:
        if only and data_type.key not in only:
            continue
        seconds = keep_seconds(data_type.key)
        if seconds is None:
            continue
        cutoff = now - timedelta(seconds=seconds)
        cutoff_naive = cutoff.astimezone(timezone.utc).replace(tzinfo=None)
        deadline = time.monotonic() + MAX_SECONDS_PER_TYPE
        error = None
        deleted = 0
        try:
            deleted = data_type.purge(cutoff, cutoff_naive, deadline, now)
        except Exception as e:
            db.session.rollback()
            error = str(e)[:2000]
            logger.error(f"Data retention: purging {data_type.key} failed: {e}")
            logger.debug(traceback.format_exc())
        results[data_type.key] = deleted

        try:
            row = db.session.get(RetentionSetting, data_type.key)
            if row is None:
                row = RetentionSetting(data_type=data_type.key, customized=False)
                db.session.add(row)
            row.last_purge_at = now.astimezone(timezone.utc).replace(tzinfo=None)
            row.last_purge_count = deleted
            row.last_purge_error = error
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Data retention: could not record the purge of {data_type.key}: {e}")

        if deleted:
            logger.info(
                f"Data retention: deleted {deleted} {data_type.label.lower()} older than "
                f"{describe_seconds(seconds)}"
            )
        if deleted and data_type.key == "audit_events":
            # Removing part of the audit trail is itself worth a line in it
            from raven.audit import record_audit_event

            record_audit_event(
                "retention",
                "audit_events_purged",
                actor="system",
                details=f"Deleted {deleted} audit event(s) older than {describe_seconds(seconds)}",
            )
    return results
