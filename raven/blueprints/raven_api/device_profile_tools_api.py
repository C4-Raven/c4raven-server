"""
Device profile helper endpoints: preview, export, import and extras (admin only).

- GET  /api/device-profiles/preview  what a given user/device would receive for a phase (or,
  with phase=tool&tool=<name>, from /Marti/api/device/profile/tool/<name>)
- GET  /api/device-profiles/<id>/export  a profile as an ATAK .pref file
- POST /api/device-profiles/import  parse an ATAK .pref/.xml (or a data package .zip holding
  .pref files) into settings. Nothing is saved; secrets, the server connection list and device
  identity are skipped and reported.
- GET  /api/device-profiles/extras  data packages and plugins sent on enrollment/connection
"""

import io
import re
import zipfile
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring

from flask import Blueprint, Response, jsonify, request
from flask_security import auth_required, roles_accepted

from raven import remote_clear
from raven.device_profiles import (
    ProfileValidationError,
    profile_to_dict,
    resolve_files,
    resolve_settings,
    username_for_eud,
    validate_setting,
)
from raven.extensions import db, logger
from raven.models.DeviceProfileSet import DeviceProfileSet
from raven.models.DataPackage import DataPackage
from raven.models.Packages import Packages

device_profile_tools_api_blueprint = Blueprint("device_profile_tools_api_blueprint", __name__)

# Same preference name create_profile_zip uses for preference.pref
PREFERENCE_NAME = "com.atakmap.app_preferences"

ALLOWED_VALUE_CLASSES = {
    "class java.lang.String",
    "class java.lang.Boolean",
    "class java.lang.Integer",
    "class java.lang.Long",
    "class java.lang.Float",
}

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ZIP_ENTRIES = 200
MAX_PREF_BYTES = 2 * 1024 * 1024  # per .pref file inside a zip (uncompressed)
MAX_ZIP_TOTAL_BYTES = 10 * 1024 * 1024  # all .pref files inside a zip (uncompressed)
MAX_SETTINGS = 2000

# Preference groups that hold the device's server connections (one per server, with creds)
CONNECTION_PREFERENCE_NAMES = {"cot_streams"}

SECRET_KEY_RE = re.compile(
    r"password|passwd|passphrase|secret|certificate|truststore|keystore|privatekey|private_key"
    r"|apikey|api_key|authtoken|auth_token|accesstoken|access_token|refreshtoken|credential"
    r"|calocation|clientcert",
    re.IGNORECASE,
)
CONNECTION_KEY_RE = re.compile(
    r"^(?:(?:connectstring|caLocation|caPassword|clientPassword|certificateLocation"
    r"|enrollForCertificate\w*|useAuth|cacheCreds|expiration)\d*"
    r"|(?:description|enabled|compress)\d+|count)$",
    re.IGNORECASE,
)
DEVICE_IDENTITY_KEYS = {
    "bestdeviceuid",
    "locationuid",
    "locationcallsign",
    "deviceid",
    "device_uid",
    "deviceuid",
}
# Keys the server writes into every profile itself (create_profile_zip). Classes on imported
# entries are kept exactly as found: ATAK stores most number-looking settings as String.
SERVER_MANAGED_KEYS = {
    "appmgmtenableupdateserver",
    "atakupdateserverurl",
    "updateservercalocation",
    "updateservercapassword",
    "repostartupsync",
    "deviceprofileenableonconnect",
    "prefs_enable_channels",
    remote_clear.SERVER_PUBKEY_PREF_KEY.lower(),
}


class PrefImportError(ValueError):
    pass


def skip_reason(key: str, preference_name: str | None = None) -> str | None:
    """Why a key from an imported file must not go into a profile, or None if it's fine."""
    lower = key.lower()
    if SECRET_KEY_RE.search(key):
        return "Looks like a password, key or certificate"
    if preference_name in CONNECTION_PREFERENCE_NAMES or CONNECTION_KEY_RE.match(key):
        return "Server connection list (device-specific, managed by enrollment)"
    if lower in DEVICE_IDENTITY_KEYS:
        return "Device identity (must be unique per device)"
    if lower in SERVER_MANAGED_KEYS or lower.startswith("prefs_enable_channels_host-"):
        return "Set automatically by this server"
    return None


def _check_xml_safe(data: bytes):
    # xml.etree expands internal entities; a DOCTYPE is never needed in an ATAK pref file, so
    # refuse any file with one rather than risk entity expansion / external entities.
    head = data.lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise PrefImportError(
            "Preference files with a DOCTYPE or ENTITY declaration are not accepted"
        )
    # UTF-16/32 encoded files would hide the markers above from a byte search
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in data[:200]:
        raise PrefImportError("Preference file must be UTF-8 encoded")


def parse_pref_xml(data: bytes, settings: dict, skipped: dict):
    """Parse one ATAK preference file into settings (key -> {key,value,value_class}) and skipped
    (key -> reason). Later files/entries win for duplicate keys."""
    _check_xml_safe(data)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise PrefImportError(f"Not a valid preference file: {e}")

    if root.tag == "preferences":
        preference_groups = root.findall("preference")
    elif root.tag == "preference":
        preference_groups = [root]
    else:
        raise PrefImportError("Not an ATAK preference file (expected <preferences>)")

    for group in preference_groups:
        group_name = group.get("name")
        for entry in group.findall("entry"):
            key = (entry.get("key") or "").strip()
            if not key:
                continue
            value_class = (entry.get("class") or "").strip()
            value = entry.text or ""

            reason = skip_reason(key, group_name)
            cleaned = None
            if reason is None:
                if value_class not in ALLOWED_VALUE_CLASSES:
                    reason = f"Unsupported value type ({value_class or 'none'})"
                else:
                    # Same checks a profile save does, so everything returned can be saved
                    try:
                        cleaned = validate_setting(
                            {"key": key, "value": value, "value_class": value_class}
                        )
                    except ProfileValidationError as e:
                        reason = str(e)

            if reason:
                settings.pop(key, None)
                skipped[key] = reason
                continue

            skipped.pop(key, None)
            settings[key] = cleaned
            if len(settings) > MAX_SETTINGS:
                raise PrefImportError(f"Too many settings (more than {MAX_SETTINGS})")


def _safe_zip_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return not (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or ".." in normalized.split("/")
    )


def parse_pref_zip(data: bytes, settings: dict, skipped: dict):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise PrefImportError("Not a valid zip file")

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise PrefImportError(f"Zip has too many files (more than {MAX_ZIP_ENTRIES})")

        found = 0
        total = 0
        for info in infos:
            if info.is_dir() or not info.filename.lower().endswith(".pref"):
                continue
            if not _safe_zip_name(info.filename):
                raise PrefImportError(f"Unsafe path in zip: {info.filename}")
            if info.file_size > MAX_PREF_BYTES:
                raise PrefImportError(f"{info.filename} is too large")
            # Don't trust the header's size: read at most the limit + 1
            with zf.open(info) as f:
                content = f.read(MAX_PREF_BYTES + 1)
            if len(content) > MAX_PREF_BYTES:
                raise PrefImportError(f"{info.filename} is too large")
            total += len(content)
            if total > MAX_ZIP_TOTAL_BYTES:
                raise PrefImportError("Preference files in the zip are too large")
            parse_pref_xml(content, settings, skipped)
            found += 1

        if not found:
            raise PrefImportError("No .pref files found in the zip")


def parse_import(data: bytes, filename: str = "") -> dict:
    settings: dict = {}
    skipped: dict = {}
    if data[:4] == b"PK\x03\x04" or filename.lower().endswith(".zip"):
        parse_pref_zip(data, settings, skipped)
    else:
        parse_pref_xml(data, settings, skipped)
    return {
        "settings": list(settings.values()),
        "skipped": [{"key": k, "reason": r} for k, r in skipped.items()],
    }


def build_pref_xml(settings) -> bytes:
    """ATAK preference file, same structure as create_profile_zip's preference.pref."""
    prefs = Element("preferences")
    pref = SubElement(prefs, "preference", {"version": "1", "name": PREFERENCE_NAME})
    for s in settings:
        entry = SubElement(pref, "entry", {"key": s["key"], "class": s["value_class"]})
        entry.text = s["value"] if s["value"] is not None else ""
    return b"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n" + tostring(
        prefs, encoding="utf-8", xml_declaration=False
    )


def safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", name or "").strip(" ._")
    return (cleaned[:100] or "device-profile") + ".pref"


def _extras_for_phase(phase: str):
    column = "install_on_enrollment" if phase == "enrollment" else "install_on_connection"
    data_packages = (
        db.session.query(DataPackage)
        .filter(getattr(DataPackage, column).is_(True))
        .order_by(DataPackage.filename)
        .all()
    )
    plugins = (
        db.session.query(Packages)
        .filter(getattr(Packages, column).is_(True))
        .order_by(Packages.name)
        .all()
    )
    return data_packages, plugins


@device_profile_tools_api_blueprint.route("/api/device-profiles/import", methods=["POST"])
@auth_required()
@roles_accepted("administrator")
def import_device_profile():
    if request.content_length and request.content_length > MAX_UPLOAD_BYTES + 64 * 1024:
        return jsonify({"success": False, "error": "File is too large (max 5 MB)"}), 413
    upload = request.files.get("file")
    if not upload:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    data = upload.stream.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        return jsonify({"success": False, "error": "File is too large (max 5 MB)"}), 413
    if not data:
        return jsonify({"success": False, "error": "The file is empty"}), 400

    try:
        return jsonify(parse_import(data, upload.filename or ""))
    except PrefImportError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Failed to import preference file: {e}")
        return jsonify({"success": False, "error": "Could not read that file"}), 400


@device_profile_tools_api_blueprint.route("/api/device-profiles/<int:profile_id>/export")
@auth_required()
@roles_accepted("administrator")
def export_device_profile(profile_id):
    profile = db.session.get(DeviceProfileSet, profile_id)
    if not profile:
        return jsonify({"success": False, "error": "Profile not found"}), 404

    data = profile_to_dict(profile)
    body = build_pref_xml(data.get("settings") or [])
    return Response(
        body,
        mimetype="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{safe_filename(data["name"])}"'},
    )


@device_profile_tools_api_blueprint.route("/api/device-profiles/preview")
@auth_required()
@roles_accepted("administrator")
def preview_device_profile():
    phase = request.args.get("phase", "enrollment")
    if phase not in ("enrollment", "connection", "tool"):
        return (
            jsonify({"success": False, "error": "phase must be enrollment, connection or tool"}),
            400,
        )
    tool = (request.args.get("tool") or "").strip() or None
    if phase == "tool" and not tool:
        return jsonify({"success": False, "error": "Choose a tool to preview"}), 400
    username = request.args.get("username") or None
    eud_uid = request.args.get("eud_uid") or None
    if not username and eud_uid:
        # Like a connection request: the device's bound user decides user/group profiles
        username = username_for_eud(eud_uid)

    settings = resolve_settings(phase, username, eud_uid, tool)
    files = [
        {k: f[k] for k in ("id", "filename", "zip_path", "size", "profile_id", "profile_name")}
        for f in resolve_files(phase, username, eud_uid, tool)
    ]
    # A tool profile's zip carries only its own settings and files
    data_packages, plugins = ([], []) if phase == "tool" else _extras_for_phase(phase)
    return jsonify(
        {
            "username": username,
            "settings": settings,
            "files": files,
            "data_packages": [{"name": dp.filename} for dp in data_packages],
            "plugins": [{"name": p.name} for p in plugins],
        }
    )


@device_profile_tools_api_blueprint.route("/api/device-profiles/extras")
@auth_required()
@roles_accepted("administrator")
def device_profile_extras():
    data_packages = (
        db.session.query(DataPackage)
        .filter(
            (DataPackage.install_on_enrollment.is_(True))
            | (DataPackage.install_on_connection.is_(True))
        )
        .order_by(DataPackage.filename)
        .all()
    )
    plugins = (
        db.session.query(Packages)
        .filter(
            (Packages.install_on_enrollment.is_(True)) | (Packages.install_on_connection.is_(True))
        )
        .order_by(Packages.name)
        .all()
    )
    return jsonify(
        {
            "data_packages": [
                {
                    "name": dp.filename,
                    "install_on_enrollment": bool(dp.install_on_enrollment),
                    "install_on_connection": bool(dp.install_on_connection),
                }
                for dp in data_packages
            ],
            "plugins": [
                {
                    "name": p.name,
                    "install_on_enrollment": bool(p.install_on_enrollment),
                    "install_on_connection": bool(p.install_on_connection),
                }
                for p in plugins
            ],
        }
    )
