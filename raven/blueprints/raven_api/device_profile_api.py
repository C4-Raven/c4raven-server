import traceback

from flask import Blueprint, jsonify, request
from flask_babel import gettext
from flask_login import current_user
from flask_security import auth_required, roles_accepted, roles_required
from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError

from raven.audit import record_audit_event
from raven.blueprints.raven_api.api import paginate, search
from raven.device_profiles import (
    MAX_NAME_LENGTH,
    ProfileValidationError,
    apply_profile_input,
    profile_to_dict,
    profiles_to_dicts,
    validate_profile_input,
)
from raven.extensions import db, logger
from raven.forms.device_profile_form import DeviceProfileForm
from raven.models.DeviceProfileSet import DeviceProfileSet
from raven.models.DeviceProfiles import DeviceProfiles

device_profile_api_blueprint = Blueprint("device_profile_api_blueprint", __name__)


@device_profile_api_blueprint.route("/api/profiles")
@roles_required("administrator")
def get_device_profiles():
    query = db.session.query(DeviceProfiles)
    query = search(query, DeviceProfiles, "preference_key")
    query = search(query, DeviceProfiles, "preference_value")
    query = search(query, DeviceProfiles, "tool")
    return paginate(query)


@device_profile_api_blueprint.route("/api/profiles", methods=["POST"])
@auth_required()
@roles_required("administrator")
def add_device_profile():
    form = DeviceProfileForm()
    if not form.validate():
        return jsonify({"success": False, "errors": form.errors}), 400

    device_profile = DeviceProfiles()
    device_profile.from_wtf(form)

    existing_profile = db.session.execute(
        db.session.query(DeviceProfiles).filter_by(
            preference_key=device_profile.preference_key, eud_uid=device_profile.eud_uid
        )
    ).first()
    if existing_profile:
        existing_profile = existing_profile[0]

        db.session.execute(
            update(DeviceProfiles)
            .where(DeviceProfiles.preference_key == existing_profile.preference_key)
            .where(DeviceProfiles.eud_uid == existing_profile.eud_uid)
            .values(**device_profile.serialize())
        )
        db.session.commit()

    else:
        db.session.add(device_profile)
        db.session.commit()

    return jsonify({"success": True})


@device_profile_api_blueprint.route("/api/profiles", methods=["DELETE"])
@roles_required("administrator")
def delete_device_profile():
    preference_key = request.args.get("preference_key")
    eud_uid = request.args.get("eud_uid")
    if not preference_key:
        return (
            jsonify({"success": False, "error": gettext("Please specify the preference_key")}),
            400,
        )
    try:
        query = db.session.query(DeviceProfiles)
        query = search(query, DeviceProfiles, "preference_key")
        query = search(query, DeviceProfiles, "eud_uid")
        preference = db.session.execute(query).first()
        if not preference:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": gettext(
                            "Unknown preference_key: %(preference_key)s",
                            preference_key=preference_key,
                        ),
                    }
                ),
                404,
            )

        db.session.delete(preference[0])
        db.session.commit()
        return jsonify({"success": True})
    except BaseException as e:
        logger.error(f"Failed to delete device profile: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 400


# --- Device profiles: named, targeted sets of settings (raven/device_profiles.py) ---
# The /api/profiles endpoints above are the old per-key API, kept for back-compat. They write the
# device_profiles table, which devices no longer receive since the move to device_profile_sets.


def _profile_error(message, status=400):
    return jsonify({"success": False, "error": message}), status


def _audit_details(profile: DeviceProfileSet, extra: str | None = None) -> str:
    audience = ["everyone"] if profile.target_everyone else []
    audience += [f"{t.kind} {t.value}" for t in profile.targets]
    phases = [
        phase
        for phase, on in (
            ("enrollment", profile.apply_on_enrollment),
            ("connection", profile.apply_on_connection),
        )
        if on
    ]
    # Keys only: values can be passwords
    keys = ", ".join(s.key for s in profile.settings)
    parts = [
        f"Profile: {profile.name}",
        f"Enabled: {'yes' if profile.enabled else 'no'}",
        f"Audience: {', '.join(audience) or 'nobody'}",
        f"When: {', '.join(phases) or 'never'}",
        f"Settings ({len(profile.settings)}): {keys}" if keys else "Settings: none",
    ]
    if extra:
        parts.insert(1, extra)
    return " · ".join(parts)[:4000]


def _audit(action, profile, extra=None):
    record_audit_event(
        "device_profiles",
        action,
        actor=getattr(current_user, "username", None),
        details=_audit_details(profile, extra),
    )


def _get_profile(profile_id):
    return db.session.get(DeviceProfileSet, profile_id)


@device_profile_api_blueprint.route("/api/device-profiles", methods=["GET"])
@auth_required()
@roles_accepted("administrator")
def list_profile_sets():
    profiles = db.session.query(DeviceProfileSet).order_by(func.lower(DeviceProfileSet.name)).all()
    return jsonify(profiles_to_dicts(profiles))


@device_profile_api_blueprint.route("/api/device-profiles", methods=["POST"])
@auth_required()
@roles_accepted("administrator")
def create_profile_set():
    try:
        cleaned = validate_profile_input(request.get_json(silent=True))
    except ProfileValidationError as e:
        return _profile_error(str(e))
    profile = apply_profile_input(DeviceProfileSet(), cleaned)
    db.session.add(profile)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _profile_error(gettext("A profile with that name already exists"))
    _audit("profile_created", profile)
    return jsonify({"success": True, "profile": profile_to_dict(profile)})


@device_profile_api_blueprint.route("/api/device-profiles/<int:profile_id>", methods=["PUT"])
@auth_required()
@roles_accepted("administrator")
def update_profile_set(profile_id):
    profile = _get_profile(profile_id)
    if not profile:
        return _profile_error(gettext("Profile not found"), 404)
    old_name = profile.name
    try:
        cleaned = validate_profile_input(request.get_json(silent=True), profile_id=profile.id)
    except ProfileValidationError as e:
        return _profile_error(str(e))
    try:
        apply_profile_input(profile, cleaned)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _profile_error(gettext("A profile with that name already exists"))
    _audit(
        "profile_updated",
        profile,
        f"Renamed from: {old_name}" if old_name != profile.name else None,
    )
    return jsonify({"success": True, "profile": profile_to_dict(profile)})


@device_profile_api_blueprint.route("/api/device-profiles/<int:profile_id>", methods=["DELETE"])
@auth_required()
@roles_accepted("administrator")
def delete_profile_set(profile_id):
    profile = _get_profile(profile_id)
    if not profile:
        return _profile_error(gettext("Profile not found"), 404)
    details = _audit_details(profile)
    db.session.delete(profile)
    db.session.commit()
    record_audit_event(
        "device_profiles",
        "profile_deleted",
        actor=getattr(current_user, "username", None),
        details=details,
    )
    return jsonify({"success": True})


@device_profile_api_blueprint.route(
    "/api/device-profiles/<int:profile_id>/duplicate", methods=["POST"]
)
@auth_required()
@roles_accepted("administrator")
def duplicate_profile_set(profile_id):
    source = _get_profile(profile_id)
    if not source:
        return _profile_error(gettext("Profile not found"), 404)

    taken = {name.lower() for (name,) in db.session.query(DeviceProfileSet.name).all()}
    base = f"{source.name} (copy)"
    name, n = base, 2
    while name.lower() in taken:
        name = f"{source.name} (copy {n})"
        n += 1
    if len(name) > MAX_NAME_LENGTH:
        return _profile_error(gettext("The profile name is too long to copy"))

    copy = DeviceProfileSet()
    cleaned = {
        "name": name,
        "description": source.description,
        "enabled": source.enabled,
        "apply_on_enrollment": source.apply_on_enrollment,
        "apply_on_connection": source.apply_on_connection,
        "target_everyone": source.target_everyone,
        "targets": [{"kind": t.kind, "value": t.value} for t in source.targets],
        "settings": [s.to_json() for s in source.settings],
    }
    apply_profile_input(copy, cleaned)
    db.session.add(copy)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _profile_error(gettext("A profile with that name already exists"))
    _audit("profile_duplicated", copy, f"Copied from: {source.name}")
    return jsonify({"success": True, "profile": profile_to_dict(copy)})
