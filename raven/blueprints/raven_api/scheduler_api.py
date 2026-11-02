from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.jobstores.base import JobLookupError
from apscheduler.triggers.combining import AndTrigger, OrTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from flask import Blueprint, jsonify, request
from flask_apscheduler import api
from flask_apscheduler.json import jsonify as scheduler_jsonify
from flask_apscheduler.utils import job_to_dict
from flask_security import roles_accepted

from raven.extensions import apscheduler

scheduler_api_blueprint = Blueprint("schedule_api_blueprint", __name__)

# Plain-English explanations shown next to each job in the admin UI, keyed by job id.
JOB_DESCRIPTIONS = {
    "delete_video_recordings": (
        "Deletes every video recording: clears the recordings list in the database and asks "
        "MediaMTX to delete all recorded video segments from disk. It does not look at age, so "
        "each run wipes all recordings."
    ),
    "purge_data": (
        "Wipes all operational data from the database: CoT history, markers, points, alerts, "
        "CasEvacs, range & bearing lines, chats and chatrooms, data packages, video streams and "
        "recordings, issued certificate records, missions, EUDs and teams. User accounts and "
        "groups are kept."
    ),
    "delete_old_data": (
        "Legacy, superseded by the per-type settings on the Data Retention tab (Apply data "
        "retention). Deletes data older than the configured retention period (the "
        "RAVEN_DELETE_OLD_DATA_* settings). Old markers, alerts and range & bearing lines are also removed from "
        "connected devices' maps; old chat messages, mission changes, EUD records, points and "
        "CoT history are deleted from the database."
    ),
    "reconcile_eud_status": (
        "Marks a device as Disconnected if it still shows as Connected but hasn't sent anything "
        "for 3 minutes, so the connection status stays correct even if the connection handler "
        "died without reporting the disconnect."
    ),
    "expire_group_memberships": (
        "Removes group memberships whose expiry date has passed (a per-member expiry set on the "
        "Groups page, or a group's default membership duration). Affected devices are "
        "unsubscribed from the group straight away and each removal is recorded in the "
        "Security Audit log."
    ),
    "record_metrics_sample": (
        "Saves a snapshot of the message counters (messages and bytes in and out, connected "
        "devices) for the Dashboard's message rate chart, and deletes snapshots older than 24 "
        "hours. Pausing it stops the chart; the Prometheus counters keep counting."
    ),
    "apply_data_retention": (
        "Deletes data older than the retention set for each type on the Data Retention tab "
        "(CoT history, chats, alerts, markers, data packages and video files, statistics, "
        "audit events, old log files...), in small batches. Also drops chat messages held for "
        "offline devices once they are older than the offline chat retention (48 hours by "
        "default). Types set to keep forever are left alone."
    ),
    "refresh_crl": (
        "Regenerates the certificate revocation list (CRL) when it's missing or within 30 days of "
        "expiring. nginx and the SSL streaming port reject every client certificate once the CRL "
        "has expired, so this keeps devices able to connect. Revoking a certificate regenerates "
        "the CRL straight away regardless."
    ),
    "get_airplanes_live_data": (
        "Legacy placeholder that does nothing. It only exists so old saved job entries still load."
    ),
}

ONE_OFF_SEPARATOR = "__once__"
REPEAT_MODES = ("once", "minutes", "hourly", "daily", "weekly")
MAX_INTERVAL_MINUTES = 10080  # one week

_DAY_KEYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_DAY_NAMES = {
    "mon": "Monday",
    "tue": "Tuesday",
    "wed": "Wednesday",
    "thu": "Thursday",
    "fri": "Friday",
    "sat": "Saturday",
    "sun": "Sunday",
}


def _plural(count, unit):
    return f"{count} {unit}" if count == 1 else f"{count} {unit}s"


def _short_datetime(dt):
    return f"{dt.day} {dt.strftime('%b %H:%M')}"


def _cron_fields(trigger):
    return {field.name: str(field) for field in trigger.fields}


def _is_wild(value):
    return value in (None, "*", "None")


def _simple_daily_or_weekly(trigger):
    """("daily"|"weekly", hour, minute, day_of_week) for a plain daily/weekly cron, else None."""
    fields = _cron_fields(trigger)
    hour, minute, second = fields.get("hour", ""), fields.get("minute", ""), fields.get("second", "0")
    if not (hour.isdigit() and minute.isdigit() and second == "0"):
        return None
    if not all(_is_wild(fields.get(name)) for name in ("year", "month", "week", "day")):
        return None
    dow = fields.get("day_of_week")
    if _is_wild(dow):
        return "daily", int(hour), int(minute), None
    if dow in _DAY_NAMES:
        return "weekly", int(hour), int(minute), dow
    if dow.isdigit() and 0 <= int(dow) <= 6:
        return "weekly", int(hour), int(minute), _DAY_KEYS[int(dow)]
    return None


def _admin_set_start(trigger):
    # Interval triggers always carry a start_date (the creation time when none was given, which
    # has sub-second precision). Admin-set start times come from a minute picker, so only those
    # are worth showing.
    start = getattr(trigger, "start_date", None)
    if start is not None and start.second == 0 and start.microsecond == 0:
        return start
    return None


def describe_trigger(trigger):
    """Short human description of an APScheduler trigger, e.g. "Every minute"."""
    if isinstance(trigger, IntervalTrigger):
        total = int(trigger.interval.total_seconds())
        text = None
        for unit, size in (("week", 604800), ("day", 86400), ("hour", 3600), ("minute", 60)):
            if total == size:
                text = f"Every {unit}"
        if text is None:
            parts = []
            for unit, size in (
                ("week", 604800),
                ("day", 86400),
                ("hour", 3600),
                ("minute", 60),
                ("second", 1),
            ):
                count, total = divmod(total, size)
                if count:
                    parts.append(_plural(count, unit))
            text = "Every " + " ".join(parts) if parts else "Continuously"
        start = _admin_set_start(trigger)
        if start is not None:
            text += f" from {_short_datetime(start)}"
        return text

    if isinstance(trigger, CronTrigger):
        simple = _simple_daily_or_weekly(trigger)
        if simple:
            kind, hour, minute, dow = simple
            if kind == "daily":
                return f"Daily at {hour:02d}:{minute:02d}"
            return f"Weekly on {_DAY_NAMES[dow]} at {hour:02d}:{minute:02d}"
        fields = _cron_fields(trigger)
        minute, second = fields.get("minute", ""), fields.get("second", "0")
        hour, day, dow = fields.get("hour", ""), fields.get("day"), fields.get("day_of_week")
        if second == "0" and all(_is_wild(fields.get(n)) for n in ("year", "month", "week")):
            if hour.isdigit() and minute.isdigit() and day and day.isdigit() and _is_wild(dow):
                return f"Monthly on day {day} at {int(hour):02d}:{int(minute):02d}"
            if _is_wild(day) and _is_wild(dow) and _is_wild(hour):
                if minute == "*":
                    return "Every minute"
                if minute.isdigit():
                    return f"Hourly at :{int(minute):02d}"
        spec = ", ".join(
            f"{field.name}={field}" for field in trigger.fields if not field.is_default
        )
        return f"Cron ({spec})" if spec else "Cron"

    if isinstance(trigger, DateTrigger):
        return f"Once at {_short_datetime(trigger.run_date)}"

    return str(trigger)


def describe_repeat(trigger):
    """(repeat, interval_minutes) in the vocabulary used by POST /api/scheduler/job/schedule."""
    if isinstance(trigger, DateTrigger):
        return "once", None
    if isinstance(trigger, IntervalTrigger):
        total = int(trigger.interval.total_seconds())
        if total == 3600:
            return "hourly", None
        if total % 60 == 0 and 1 <= total // 60 <= MAX_INTERVAL_MINUTES:
            return "minutes", total // 60
        return "custom", None
    if isinstance(trigger, CronTrigger):
        simple = _simple_daily_or_weekly(trigger)
        if simple:
            return simple[0], None
    return "custom", None


def is_one_off_job_id(job_id):
    return ONE_OFF_SEPARATOR in (job_id or "")


def serialize_job(job, scheduled_runs=None):
    data = job_to_dict(job)
    # Pending jobs (scheduler not started) have no next_run_time key; paused jobs have None.
    data.setdefault("next_run_time", None)
    base_id = job.id.split(ONE_OFF_SEPARATOR, 1)[0]
    data["description"] = JOB_DESCRIPTIONS.get(base_id, "")
    try:
        data["schedule"] = describe_trigger(job.trigger)
    except Exception:
        data["schedule"] = str(job.trigger)
    try:
        repeat, interval_minutes = describe_repeat(job.trigger)
    except Exception:
        repeat, interval_minutes = "custom", None
    data["repeat"] = repeat
    data["interval_minutes"] = interval_minutes
    if not is_one_off_job_id(job.id):
        data["scheduled_runs"] = scheduled_runs or []
    return data


@scheduler_api_blueprint.route("/api/scheduler/jobs", strict_slashes=False)
@roles_accepted("administrator")
def get_jobs():
    all_jobs = apscheduler.get_jobs()
    runs = {}
    for job in all_jobs:
        if is_one_off_job_id(job.id):
            parent = job.id.split(ONE_OFF_SEPARATOR, 1)[0]
            run_at = getattr(job.trigger, "run_date", None)
            runs.setdefault(parent, []).append({"id": job.id, "run_at": run_at})
    for parent_runs in runs.values():
        parent_runs.sort(key=lambda r: (r["run_at"] is None, r["run_at"] or 0))

    jobs = [
        serialize_job(job, runs.get(job.id))
        for job in all_jobs
        if not is_one_off_job_id(job.id)
    ]
    return scheduler_jsonify(jobs)


def _parse_run_at(value):
    if not isinstance(value, str) or not value:
        raise ValueError("run_at is required")
    try:
        run_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("run_at must be an ISO 8601 date and time")
    if run_at.tzinfo is None or run_at.utcoffset() is None:
        raise ValueError("run_at must include a UTC offset, e.g. 2026-11-01T02:00:00+10:00")
    return run_at


def _ensure_scheduler_running():
    #  0 == STATE_STOPPED
    if apscheduler.state == 0:
        apscheduler.start()
    #  2 == STATE_PAUSED
    elif apscheduler.state == 2:
        apscheduler.resume()


def _error(message, status=400):
    return jsonify({"success": False, "error": message}), status


@scheduler_api_blueprint.route("/api/scheduler/job/schedule", methods=["POST"], strict_slashes=False)
@roles_accepted("administrator")
def schedule_job():
    body = request.get_json(silent=True) or {}
    job_id = body.get("job_id")
    if not job_id or not isinstance(job_id, str):
        return _error("Please provide a job_id")
    if is_one_off_job_id(job_id):
        return _error("One-off runs can't be rescheduled; cancel it and schedule a new one")
    job = apscheduler.get_job(job_id)
    if job is None:
        return _error(f"No such job: {job_id}", 404)

    try:
        run_at = _parse_run_at(body.get("run_at"))
    except ValueError as e:
        return _error(str(e))

    # Prefer the browser's IANA zone so daily/weekly runs follow daylight-saving changes;
    # fall back to the fixed offset carried by run_at.
    tz_name = body.get("timezone")
    if isinstance(tz_name, str) and tz_name:
        try:
            run_at = run_at.astimezone(ZoneInfo(tz_name))
        except (ZoneInfoNotFoundError, ValueError):
            return _error(f"Unknown timezone: {tz_name}")

    repeat = body.get("repeat")
    if repeat not in REPEAT_MODES:
        return _error(f"repeat must be one of: {', '.join(REPEAT_MODES)}")

    resume = body.get("resume", True)
    if not isinstance(resume, bool):
        return _error("resume must be true or false")

    try:
        if repeat == "once":
            if run_at <= datetime.now(timezone.utc):
                return _error("run_at is in the past")
            # A DateTrigger on the built-in job itself would delete it after it fires, so run a
            # separate one-off copy instead and leave the regular schedule alone.
            once_id = f"{job_id}{ONE_OFF_SEPARATOR}{int(run_at.timestamp())}"
            _ensure_scheduler_running()
            once = apscheduler.scheduler.add_job(
                job.func_ref,
                trigger=DateTrigger(run_date=run_at),
                args=job.args,
                kwargs=job.kwargs,
                id=once_id,
                name=f"{job.name} (one-off)",
                replace_existing=True,
            )
            once = apscheduler.get_job(once_id) or once
            return jsonify({"success": True, "job": _json_safe(serialize_job(once))})

        if repeat == "minutes":
            minutes = body.get("interval_minutes")
            if isinstance(minutes, bool) or not isinstance(minutes, int):
                return _error("interval_minutes must be a whole number of minutes")
            if not 1 <= minutes <= MAX_INTERVAL_MINUTES:
                return _error(f"interval_minutes must be between 1 and {MAX_INTERVAL_MINUTES}")
            trigger = IntervalTrigger(minutes=minutes, start_date=run_at, timezone=run_at.tzinfo)
        elif repeat == "hourly":
            trigger = IntervalTrigger(hours=1, start_date=run_at, timezone=run_at.tzinfo)
        elif repeat == "daily":
            trigger = CronTrigger(
                hour=run_at.hour, minute=run_at.minute, start_date=run_at, timezone=run_at.tzinfo
            )
        else:  # weekly
            trigger = CronTrigger(
                day_of_week=_DAY_KEYS[run_at.weekday()],
                hour=run_at.hour,
                minute=run_at.minute,
                start_date=run_at,
                timezone=run_at.tzinfo,
            )

        if resume:
            _ensure_scheduler_running()
            apscheduler.scheduler.reschedule_job(job_id, trigger=trigger)
        elif job.next_run_time is None:
            # Paused: swap the trigger but leave next_run_time empty so it stays paused.
            apscheduler.scheduler.modify_job(job_id, trigger=trigger)
        else:
            apscheduler.scheduler.reschedule_job(job_id, trigger=trigger)
        return jsonify({"success": True, "job": _json_safe(serialize_job(apscheduler.get_job(job_id)))})
    except Exception as e:
        return _error(str(e))


@scheduler_api_blueprint.route("/api/scheduler/job/cancel", methods=["POST"], strict_slashes=False)
@roles_accepted("administrator")
def cancel_job():
    body = request.get_json(silent=True) or {}
    job_id = body.get("job_id")
    if not job_id or not isinstance(job_id, str):
        return _error("Please provide a job_id")
    if not is_one_off_job_id(job_id):
        return _error("Only one-off scheduled runs can be cancelled; pause a regular job instead")
    try:
        apscheduler.remove_job(job_id)
    except JobLookupError:
        return _error(f"No such scheduled run: {job_id}", 404)
    return jsonify({"success": True})


def _json_safe(data):
    """Datetimes -> ISO strings so plain flask.jsonify gives the same output as the jobs list."""
    if isinstance(data, dict):
        return {k: _json_safe(v) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [_json_safe(v) for v in data]
    if isinstance(data, datetime):
        return data.isoformat()
    return data


@scheduler_api_blueprint.route("/api/scheduler/job/pause", methods=["POST"], strict_slashes=False)
@roles_accepted("administrator")
def pause_job():
    if "job_id" not in request.json:
        return (
            {"success": False, "error": "Please provide a job_id"},
            400,
            {"Content-Type": "application/json"},
        )
    try:
        return api.pause_job(request.json["job_id"])
    except BaseException as e:
        return {"success": False, "error": str(e)}, 400, {"Content-Type": "application/json"}


@scheduler_api_blueprint.route("/api/scheduler/job/resume", methods=["POST"], strict_slashes=False)
@roles_accepted("administrator")
def resume_job():
    if "job_id" not in request.json:
        return (
            {"success": False, "error": "Please provide a job_id"},
            400,
            {"Content-Type": "application/json"},
        )
    try:
        #  0 == STATE_STOPPED
        if apscheduler.state == 0:
            apscheduler.start()
        #  2 == STATE_PAUSED
        elif apscheduler.state == 2:
            apscheduler.resume()

        return api.resume_job(request.json["job_id"])
    except BaseException as e:
        return {"success": False, "error": str(e)}, 400, {"Content-Type": "application/json"}


@scheduler_api_blueprint.route("/api/scheduler/job/run", methods=["POST"], strict_slashes=False)
@roles_accepted("administrator")
def run_job():
    if "job_id" not in request.json:
        return (
            {"success": False, "error": "Please provide a job_id"},
            400,
            {"Content-Type": "application/json"},
        )
    try:
        return api.run_job(request.json["job_id"])
    except BaseException as e:
        return {"success": False, "error": str(e)}, 400, {"Content-Type": "application/json"}


@scheduler_api_blueprint.route("/api/scheduler/job/modify", methods=["POST"], strict_slashes=False)
@roles_accepted("administrator")
def modify_job():
    if "job_id" not in request.json:
        return (
            {"success": False, "error": "Please provide a job_id"},
            400,
            {"Content-Type": "application/json"},
        )
    try:
        job_id = request.json.pop("job_id")
        trigger = request.json.pop("trigger")
        job = apscheduler.get_job(job_id)
        if trigger == "interval":
            trigger = IntervalTrigger(**request.json)
        elif trigger == "cron":
            trigger = CronTrigger(**request.json)
        elif trigger == "date":
            trigger = DateTrigger(**request.json)
        elif trigger == "and":
            trigger = AndTrigger(**request.json)
        elif trigger == "or":
            trigger = OrTrigger(**request.json)
        else:
            return jsonify({"success": False, "error": "Invalid trigger: {}".format(trigger)}), 400

        job.modify(trigger=trigger)
        return jsonify({"success": True})
    except BaseException as e:
        return {"success": False, "error": str(e)}, 400, {"Content-Type": "application/json"}
