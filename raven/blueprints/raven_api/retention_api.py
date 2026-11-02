"""
Admin API for per data type retention (raven/retention.py).

GET /api/retention  -> {"types": [...], "job": {...}}  every type's setting, size and last purge
PUT /api/retention  {"settings": {"<type>": <keep_seconds or null>, ...}}  change some types

keep_seconds null means keep forever. Every change is recorded in the Security Audit log.
The purge itself is the apply_data_retention scheduled job; the UI's "Purge now" runs it
through the scheduler API.
"""

from flask import Blueprint, jsonify, request
from flask_babel import gettext
from flask_login import current_user
from flask_security import roles_accepted

from raven import retention
from raven.audit import record_audit_event
from raven.extensions import apscheduler, logger

# Imported so the tables are registered wherever this blueprint is (migrations, create_all)
from raven.models.OfflineChatMessage import OfflineChatMessage  # noqa: F401
from raven.models.RetentionSetting import RetentionSetting  # noqa: F401

retention_api_blueprint = Blueprint("retention_api_blueprint", __name__)

JOB_ID = "apply_data_retention"


def _job():
    try:
        job = apscheduler.get_job(JOB_ID)
    except Exception:
        job = None
    if job is None:
        return {"id": JOB_ID, "exists": False, "next_run_time": None}
    next_run = job.next_run_time
    return {
        "id": JOB_ID,
        "exists": True,
        "next_run_time": next_run.isoformat() if next_run else None,
    }


def _response():
    return jsonify(
        {
            "types": retention.report(),
            "job": _job(),
            "min_keep_seconds": retention.MIN_KEEP_SECONDS,
            "max_keep_seconds": retention.MAX_KEEP_SECONDS,
        }
    )


@retention_api_blueprint.route("/api/retention", methods=["GET"], strict_slashes=False)
@roles_accepted("administrator")
def get_retention():
    return _response()


@retention_api_blueprint.route("/api/retention", methods=["PUT"], strict_slashes=False)
@roles_accepted("administrator")
def put_retention():
    body = request.get_json(silent=True) or {}
    settings = body.get("settings")
    if not isinstance(settings, dict) or not settings:
        return jsonify({"success": False, "error": gettext("No settings were given")}), 400

    changes = {}
    for key, value in settings.items():
        if key not in retention.DATA_TYPES_BY_KEY:
            return (
                jsonify({"success": False, "error": gettext("Unknown data type: %(key)s", key=key)}),
                400,
            )
        if isinstance(value, dict):
            value = value.get("keep_seconds")
        seconds, error = retention.validate_keep_seconds(value)
        if error:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "%(label)s: keep for between 1 hour and 10 years, or forever",
                            label=retention.DATA_TYPES_BY_KEY[key].label,
                        ),
                    }
                ),
                400,
            )
        changes[key] = seconds

    actor = getattr(current_user, "username", None)
    try:
        changed = retention.update_settings(changes, actor)
    except Exception as e:
        logger.error(f"Failed to save retention settings: {e}")
        return jsonify({"success": False, "error": gettext("Failed to save retention settings")}), 500

    for key, old, new in changed:
        record_audit_event(
            "retention",
            "retention_changed",
            actor=actor,
            details=f"{retention.DATA_TYPES_BY_KEY[key].label}: "
            f"{retention.describe_seconds(old)} -> {retention.describe_seconds(new)}",
        )

    return _response()
