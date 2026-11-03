import traceback

from flask import Blueprint, jsonify, request, send_file
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
    add_profile_file,
    apply_profile_input,
    copy_profile_files,
    delete_stored_files,
    file_limits,
    file_to_dict,
    profile_to_dict,
    profiles_to_dicts,
    validate_profile_input,
)
from raven.extensions import db, logger
from raven.forms.device_profile_form import DeviceProfileForm
from raven.models.DeviceProfileFile import DeviceProfileFile
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
    if profile.tool:
        phases = [f"tool {profile.tool}"]
    # Keys only: values can be passwords
    keys = ", ".join(s.key for s in profile.settings)
    files = ", ".join(f.zip_path for f in profile.files)
    parts = [
        f"Profile: {profile.name}",
        f"Enabled: {'yes' if profile.enabled else 'no'}",
        f"Audience: {', '.join(audience) or 'nobody'}",
        f"When: {', '.join(phases) or 'never'}",
        f"Settings ({len(profile.settings)}): {keys}" if keys else "Settings: none",
        f"Files ({len(profile.files)}): {files}" if files else "Files: none",
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
    stored_names = [f.stored_name for f in profile.files]
    db.session.delete(profile)
    db.session.commit()
    delete_stored_files(stored_names)
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
        "tool": source.tool,
        "targets": [{"kind": t.kind, "value": t.value} for t in source.targets],
        "settings": [s.to_json() for s in source.settings],
    }
    apply_profile_input(copy, cleaned)
    try:
        copy_profile_files(source, copy)
    except OSError as e:
        logger.error(f"Failed to copy device profile files: {e}")
        delete_stored_files([f.stored_name for f in copy.files])
        return _profile_error(gettext("Could not copy the profile's files"), 500)
    db.session.add(copy)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        delete_stored_files([f.stored_name for f in copy.files])
        return _profile_error(gettext("A profile with that name already exists"))
    _audit("profile_duplicated", copy, f"Copied from: {source.name}")
    return jsonify({"success": True, "profile": profile_to_dict(copy)})


# --- Files in a profile: shipped in its data package next to preference.pref ---


@device_profile_api_blueprint.route("/api/device-profiles/files/limits", methods=["GET"])
@auth_required()
@roles_accepted("administrator")
def profile_file_limits():
    return jsonify(file_limits())


@device_profile_api_blueprint.route(
    "/api/device-profiles/<int:profile_id>/files", methods=["POST"]
)
@auth_required()
@roles_accepted("administrator")
def upload_profile_files(profile_id):
    """Multipart: one or more "file" parts, and an optional "folder" (where they go in the zip,
    top level if empty). A file at a path the profile already has replaces it."""
    profile = _get_profile(profile_id)
    if not profile:
        return _profile_error(gettext("Profile not found"), 404)
    uploads = [f for f in request.files.getlist("file") if f and f.filename]
    if not uploads:
        return _profile_error(gettext("Choose a file to upload"))

    actor = getattr(current_user, "username", None)
    # stored: every file written by this request, for cleanup if it fails
    added, stored, replaced_names = [], [], []
    try:
        for upload in uploads:
            row, replaced = add_profile_file(
                profile,
                upload.stream,
                upload.filename,
                folder=request.form.get("folder"),
                content_type=upload.mimetype,
                actor=actor,
            )
            stored.append(row.stored_name)
            if replaced is not None:
                replaced_names.append(replaced.stored_name)
                # The same path twice in one upload: the later file wins and the earlier row
                # never gets an id, so it isn't reported
                added = [a for a in added if a is not replaced]
            added.append(row)
        db.session.commit()
    except (ProfileValidationError, IntegrityError, OSError) as e:
        db.session.rollback()
        delete_stored_files(stored)
        if isinstance(e, ProfileValidationError):
            return _profile_error(str(e))
        logger.error(f"Failed to store a device profile file: {e}")
        logger.debug(traceback.format_exc())
        return _profile_error(gettext("Could not store that file"), 500)
    delete_stored_files(replaced_names)

    _audit(
        "profile_file_added",
        profile,
        "Uploaded: "
        + ", ".join(
            f"{row.zip_path} ({row.size} bytes, sha256 {row.sha256[:12]})" for row in added
        ),
    )
    return jsonify(
        {
            "success": True,
            "files": [file_to_dict(row) for row in added],
            "profile": profile_to_dict(profile),
        }
    )


def _get_profile_file(profile_id, file_id):
    row = db.session.get(DeviceProfileFile, file_id)
    if not row or row.profile_id != profile_id:
        return None
    return row


@device_profile_api_blueprint.route(
    "/api/device-profiles/<int:profile_id>/files/<int:file_id>", methods=["GET"]
)
@auth_required()
@roles_accepted("administrator")
def download_profile_file(profile_id, file_id):
    from raven.device_profiles import stored_file_path

    row = _get_profile_file(profile_id, file_id)
    if not row:
        return _profile_error(gettext("File not found"), 404)
    try:
        return send_file(
            stored_file_path(row),
            as_attachment=True,
            download_name=row.filename,
            mimetype="application/octet-stream",
        )
    except FileNotFoundError:
        return _profile_error(gettext("File not found"), 404)


@device_profile_api_blueprint.route(
    "/api/device-profiles/<int:profile_id>/files/<int:file_id>", methods=["DELETE"]
)
@auth_required()
@roles_accepted("administrator")
def delete_profile_file(profile_id, file_id):
    from raven.models.DeviceProfileSet import utcnow

    row = _get_profile_file(profile_id, file_id)
    if not row:
        return _profile_error(gettext("File not found"), 404)
    profile = row.profile
    zip_path, stored_name = row.zip_path, row.stored_name
    profile.files.remove(row)
    profile.updated_at = utcnow()
    db.session.commit()
    delete_stored_files([stored_name])
    _audit("profile_file_removed", profile, f"Removed: {zip_path}")
    return jsonify({"success": True, "profile": profile_to_dict(profile)})
