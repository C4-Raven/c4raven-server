"""
Device profiles: named bundles of ATAK settings and files sent to devices at enrollment and/or
on connection, or on request for a tool (models: raven/models/DeviceProfileSet.py,
DeviceProfileTarget.py, DeviceProfileSetting.py, DeviceProfileFile.py; admin API:
raven/blueprints/raven_api/device_profile_api.py; delivered by
raven/blueprints/marti_api/device_profile_marti_api.py).

resolve_settings() / resolve_files() are the one place that decides what a device gets:
take the enabled profiles for the phase whose targets match the request (everyone, one of the
user's groups, the user, the device uid), then merge with precedence
device > user > group > everyone. Within the same precedence the most recently updated profile
wins. A profile that matches the request in several ways counts at its most specific match.
Settings merge by key; files merge by their path in the zip, so a more specific profile can
replace e.g. a group's maps/basemap.xml with its own.

Phases: "enrollment" and "connection" take the profiles without a tool name that have that flag
on; "tool" takes the profiles whose tool name matches (as official TAK Server's
/Marti/api/device/profile/tool/{toolName}), whatever their enrollment/connection flags.
"""

import datetime
import hashlib
import math
import os
import re
import uuid

from sqlalchemy import func, or_

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime
from raven.models.DeviceProfileFile import DeviceProfileFile
from raven.models.DeviceProfileSet import DeviceProfileSet, utcnow
from raven.models.DeviceProfileSetting import DeviceProfileSetting
from raven.models.DeviceProfileTarget import TARGET_KINDS, DeviceProfileTarget

PHASES = ("enrollment", "connection", "tool")

STRING = "class java.lang.String"
BOOLEAN = "class java.lang.Boolean"
INTEGER = "class java.lang.Integer"
LONG = "class java.lang.Long"
FLOAT = "class java.lang.Float"
VALUE_CLASSES = (STRING, BOOLEAN, INTEGER, LONG, FLOAT)

# Precedence of a match, lowest first
EVERYONE, GROUP, USER, DEVICE = 0, 1, 2, 3

MAX_NAME_LENGTH = 255
MAX_KEY_LENGTH = 255
MAX_VALUE_LENGTH = 10000
MAX_TARGET_LENGTH = 255
MAX_TOOL_LENGTH = 255
MAX_FILENAME_LENGTH = 255
MAX_ZIP_PATH_LENGTH = 512
MAX_FOLDER_DEPTH = 4

# Tool names go in a URL path segment; keep them to what official TAK's tools use
_TOOL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# Zip folders the server writes itself (create_profile_zip): the manifest, and the folder holding
# preference.pref, the truststore and the enrollment/connection data packages and plugins
SERVER_ZIP_FOLDER = "5c2bfcae3d98c9f4d262172df99ebac5"
RESERVED_ZIP_FOLDERS = {"manifest", SERVER_ZIP_FOLDER}
FILES_FOLDER_NAME = "device_profile_files"

_INT_RANGES = {INTEGER: (-(2**31), 2**31 - 1), LONG: (-(2**63), 2**63 - 1)}

# Characters XML 1.0 can't carry (control characters other than tab/newline/CR, lone
# surrogates, U+FFFE/U+FFFF). ElementTree writes them anyway, and ATAK then fails to parse the
# whole preference.pref, losing every setting in it.
_XML_ILLEGAL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
# What both Python's float() and Java's Float.parseFloat accept (float() also takes "1_0", "nan")
_FLOAT_RE = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")


class ProfileValidationError(ValueError):
    """Bad ProfileInput. str(e) is a message fit for the API response."""


# --- values ---


def normalize_value_class(value_class) -> str | None:
    """Returns the full ATAK form of value_class ("Boolean", "java.lang.Boolean" and
    "class java.lang.Boolean" are all accepted), or None if it isn't one of the allowed ones."""
    if not isinstance(value_class, str):
        return None
    short = value_class.strip().split(".")[-1].split(" ")[-1]
    for allowed in VALUE_CLASSES:
        if allowed.rsplit(".", 1)[-1].lower() == short.lower():
            return allowed
    return None


def coerce_value(value, value_class: str) -> str:
    """Returns value as the string ATAK expects for value_class, or raises
    ProfileValidationError. value_class must already be one of VALUE_CLASSES."""
    if value is None:
        value = ""
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (int, float)):
        value = repr(value) if isinstance(value, float) else str(value)
    elif not isinstance(value, str):
        raise ProfileValidationError("Setting values must be strings")

    if _XML_ILLEGAL_RE.search(value):
        raise ProfileValidationError("Setting values can't contain control characters")

    if value_class == STRING:
        if len(value) > MAX_VALUE_LENGTH:
            raise ProfileValidationError(
                f"Setting values can be at most {MAX_VALUE_LENGTH} characters"
            )
        return value

    text = value.strip()
    if value_class == BOOLEAN:
        if text.lower() in ("true", "false"):
            return text.lower()
        raise ProfileValidationError(f'"{value}" is not true or false')

    if value_class in _INT_RANGES:
        body = text[1:] if text[:1] in ("-", "+") else text
        if not body or not body.isascii() or not body.isdigit():
            raise ProfileValidationError(f'"{value}" is not a whole number')
        number = int(text)
        low, high = _INT_RANGES[value_class]
        if not low <= number <= high:
            raise ProfileValidationError(f'"{value}" is out of range')
        return str(number)

    if value_class == FLOAT:
        if not _FLOAT_RE.fullmatch(text):
            raise ProfileValidationError(f'"{value}" is not a number')
        number = float(text)
        if not math.isfinite(number):
            raise ProfileValidationError(f'"{value}" is not a number')
        return text

    raise ProfileValidationError(f"Unknown value_class {value_class}")


def validate_setting(setting) -> dict:
    """{key, value, value_class} -> the same with key stripped, value_class in full form and
    value coerced. Raises ProfileValidationError."""
    if not isinstance(setting, dict):
        raise ProfileValidationError("Each setting must be an object with key, value and value_class")
    key = setting.get("key")
    if not isinstance(key, str) or not key.strip():
        raise ProfileValidationError("Every setting needs a key")
    key = key.strip()
    if (
        len(key) > MAX_KEY_LENGTH
        or any(c.isspace() for c in key)
        or _XML_ILLEGAL_RE.search(key)
    ):
        raise ProfileValidationError(f'"{key[:50]}" is not a valid setting key')
    value_class = normalize_value_class(setting.get("value_class") or STRING)
    if not value_class:
        raise ProfileValidationError(
            f'Setting "{key}": value_class must be one of {", ".join(VALUE_CLASSES)}'
        )
    try:
        value = coerce_value(setting.get("value"), value_class)
    except ProfileValidationError as e:
        raise ProfileValidationError(f'Setting "{key}": {e}') from None
    return {"key": key, "value": value, "value_class": value_class}


# --- profile input ---


def validate_tool(tool) -> str | None:
    """A tool name ("mission", "com.example.plugin"...) or None for an enrollment/connection
    profile. Raises ProfileValidationError."""
    if tool is None:
        return None
    if not isinstance(tool, str):
        raise ProfileValidationError("tool must be a string")
    tool = tool.strip()
    if not tool:
        return None
    if len(tool) > MAX_TOOL_LENGTH or not _TOOL_RE.fullmatch(tool):
        raise ProfileValidationError(
            "Tool names can only use letters, numbers, dots, dashes and underscores"
        )
    return tool


def _bool_field(data: dict, name: str, default: bool) -> bool:
    value = data.get(name, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ProfileValidationError(f"{name} must be true or false")
    return value


def find_user(username: str):
    from raven.models.user import User

    if not username:
        return None
    return (
        db.session.query(User).filter(func.lower(User.username) == username.lower()).one_or_none()
    )


def validate_profile_input(data, profile_id: int | None = None) -> dict:
    """Validates a ProfileInput (see the device profiles contract) and returns it cleaned up:
    {name, description, enabled, apply_on_enrollment, apply_on_connection, target_everyone,
    tool, targets:[{kind, value}], settings:[{key, value, value_class}]}. Files are managed by
    their own endpoints, not through ProfileInput.

    Groups and users must exist (usernames are stored as the account's own spelling); device uids
    needn't, so a profile can be set up before the device first connects.
    :param profile_id: The profile being updated, so its own name doesn't count as taken
    """
    from raven.models.Group import Group

    if not isinstance(data, dict):
        raise ProfileValidationError("Expected a JSON object")

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ProfileValidationError("Name is required")
    name = name.strip()
    if len(name) > MAX_NAME_LENGTH:
        raise ProfileValidationError(f"Name can be at most {MAX_NAME_LENGTH} characters")
    taken = db.session.query(DeviceProfileSet).filter(
        func.lower(DeviceProfileSet.name) == name.lower()
    )
    if profile_id is not None:
        taken = taken.filter(DeviceProfileSet.id != profile_id)
    if taken.first():
        raise ProfileValidationError(f'A profile named "{name}" already exists')

    description = data.get("description")
    if description is not None and not isinstance(description, str):
        raise ProfileValidationError("description must be a string")
    description = (description or "").strip() or None
    if description and len(description) > MAX_VALUE_LENGTH:
        raise ProfileValidationError("description is too long")

    cleaned = {
        "name": name,
        "description": description,
        "enabled": _bool_field(data, "enabled", True),
        "apply_on_enrollment": _bool_field(data, "apply_on_enrollment", True),
        "apply_on_connection": _bool_field(data, "apply_on_connection", False),
        "target_everyone": _bool_field(data, "target_everyone", False),
        "tool": validate_tool(data.get("tool")),
    }

    targets_in = data.get("targets") or []
    if not isinstance(targets_in, list):
        raise ProfileValidationError("targets must be a list")
    targets, seen_targets = [], set()
    for target in targets_in:
        if not isinstance(target, dict):
            raise ProfileValidationError("Each target must be an object with kind and value")
        kind = target.get("kind")
        value = target.get("value")
        if kind not in TARGET_KINDS:
            raise ProfileValidationError(f"Target kind must be one of {', '.join(TARGET_KINDS)}")
        if not isinstance(value, str) or not value.strip():
            raise ProfileValidationError(f"Every {kind} target needs a value")
        value = value.strip()
        if len(value) > MAX_TARGET_LENGTH:
            raise ProfileValidationError(f'"{value[:50]}" is too long')
        if kind == "group":
            if not db.session.query(Group).filter_by(name=value).first():
                raise ProfileValidationError(f'Group "{value}" does not exist')
        elif kind == "user":
            user = find_user(value)
            if not user:
                raise ProfileValidationError(f'User "{value}" does not exist')
            value = user.username
        marker = (kind, value.lower() if kind == "user" else value)
        if marker in seen_targets:
            continue
        seen_targets.add(marker)
        targets.append({"kind": kind, "value": value})
    if not targets and not cleaned["target_everyone"]:
        raise ProfileValidationError("Choose who gets this profile: everyone, or at least one group, user or device")
    cleaned["targets"] = targets

    settings_in = data.get("settings") or []
    if not isinstance(settings_in, list):
        raise ProfileValidationError("settings must be a list")
    settings, seen_keys = [], set()
    for setting in settings_in:
        setting = validate_setting(setting)
        if setting["key"] in seen_keys:
            raise ProfileValidationError(f'Setting "{setting["key"]}" is listed more than once')
        seen_keys.add(setting["key"])
        settings.append(setting)
    cleaned["settings"] = settings
    return cleaned


def apply_profile_input(profile: DeviceProfileSet, cleaned: dict) -> DeviceProfileSet:
    """Writes validate_profile_input() output onto profile (new or existing), replacing its
    targets and settings. Doesn't commit."""
    for field in (
        "name",
        "description",
        "enabled",
        "apply_on_enrollment",
        "apply_on_connection",
        "target_everyone",
        "tool",
    ):
        setattr(profile, field, cleaned.get(field))
    now = utcnow()
    if profile.created_at is None:
        profile.created_at = now
    profile.updated_at = now

    profile.targets = [DeviceProfileTarget(kind=t["kind"], value=t["value"]) for t in cleaned["targets"]]
    # Flush the deletes of replaced settings before inserting new ones with the same keys, so
    # unique(profile_id, key) can't trip on the old rows.
    if profile.id is not None and profile.settings:
        profile.settings = []
        db.session.flush()
    profile.settings = [
        DeviceProfileSetting(key=s["key"], value=s["value"], value_class=s["value_class"])
        for s in cleaned["settings"]
    ]
    return profile


# --- output ---


def _target_label(target: DeviceProfileTarget, callsigns: dict) -> str:
    if target.kind == "device":
        return callsigns.get(target.value) or target.value
    return target.value


def _callsigns_for(uids) -> dict:
    from raven.models.EUD import EUD

    uids = [uid for uid in set(uids) if uid]
    if not uids:
        return {}
    rows = db.session.query(EUD.uid, EUD.callsign).filter(EUD.uid.in_(uids)).all()
    return {uid: callsign for uid, callsign in rows if callsign}


def profile_to_dict(profile: DeviceProfileSet, callsigns: dict | None = None) -> dict:
    """The contract's Profile shape. Device target labels are the EUD's callsign when known.
    :param callsigns: {eud uid: callsign}, to avoid a query per profile when listing"""
    if callsigns is None:
        callsigns = _callsigns_for(t.value for t in profile.targets if t.kind == "device")
    return {
        "id": profile.id,
        "name": profile.name,
        "description": profile.description or "",
        "enabled": bool(profile.enabled),
        "apply_on_enrollment": bool(profile.apply_on_enrollment),
        "apply_on_connection": bool(profile.apply_on_connection),
        "target_everyone": bool(profile.target_everyone),
        "tool": profile.tool or None,
        "targets": [
            {"kind": t.kind, "value": t.value, "label": _target_label(t, callsigns)}
            for t in profile.targets
        ],
        "settings": [s.to_json() for s in profile.settings],
        "files": [file_to_dict(f) for f in profile.files],
        "created_at": iso8601_string_from_datetime(profile.created_at) if profile.created_at else None,
        "updated_at": iso8601_string_from_datetime(profile.updated_at) if profile.updated_at else None,
    }


def profiles_to_dicts(profiles) -> list[dict]:
    profiles = list(profiles)
    callsigns = _callsigns_for(
        t.value for p in profiles for t in p.targets if t.kind == "device"
    )
    return [profile_to_dict(p, callsigns) for p in profiles]


# --- resolution ---


def user_group_names(username: str | None) -> set[str]:
    """Names of the groups the user is currently in (enabled, unexpired memberships, either
    direction)."""
    from raven.models.Group import Group
    from raven.models.GroupUser import GroupUser

    user = find_user(username) if username else None
    if not user:
        return set()
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    rows = (
        db.session.query(Group.name)
        .join(GroupUser, GroupUser.group_id == Group.id)
        .filter(GroupUser.user_id == user.id)
        .filter(or_(GroupUser.enabled.is_(None), GroupUser.enabled.is_(True)))
        .filter(or_(GroupUser.expires_at.is_(None), GroupUser.expires_at > now))
        .all()
    )
    return {name for (name,) in rows}


def match_level(profile: DeviceProfileSet, username, groups, eud_uid) -> int | None:
    """The most specific way profile matches the request (DEVICE/USER/GROUP/EVERYONE), or None."""
    best = EVERYONE if profile.target_everyone else None
    lowered = username.lower() if username else None
    for target in profile.targets:
        level = None
        if target.kind == "device" and eud_uid and target.value == eud_uid:
            level = DEVICE
        elif target.kind == "user" and lowered and target.value.lower() == lowered:
            level = USER
        elif target.kind == "group" and target.value in groups:
            level = GROUP
        if level is not None and (best is None or level > best):
            best = level
    return best


def matching_profiles(
    phase: str, username: str | None, eud_uid: str | None, tool: str | None = None
):
    """[(level, profile)] for the enabled profiles of phase that match, least specific first
    (so later entries win). phase "tool" needs tool."""
    if phase not in PHASES:
        raise ValueError(f"phase must be one of {PHASES}")
    query = db.session.query(DeviceProfileSet).filter(DeviceProfileSet.enabled.is_(True))
    if phase == "tool":
        if not tool:
            return []
        query = query.filter(func.lower(DeviceProfileSet.tool) == tool.strip().lower())
    else:
        # A tool profile only ever goes out through the tool endpoint
        query = query.filter(
            or_(DeviceProfileSet.tool.is_(None), DeviceProfileSet.tool == "")
        )
        if phase == "enrollment":
            query = query.filter(DeviceProfileSet.apply_on_enrollment.is_(True))
        else:
            query = query.filter(DeviceProfileSet.apply_on_connection.is_(True))

    groups = user_group_names(username)
    matches = []
    for profile in query.all():
        level = match_level(profile, username, groups, eud_uid)
        if level is not None:
            matches.append((level, profile))
    epoch = datetime.datetime.min
    matches.sort(key=lambda m: (m[0], m[1].updated_at or epoch, m[1].id))
    return matches


def resolve_settings(
    phase: str, username: str | None, eud_uid: str | None, tool: str | None = None
) -> list[dict]:
    """What a device gets for phase ("enrollment", "connection" or "tool"), after merging:
    [{key, value, value_class, profile_id, profile_name}], sorted by key."""
    merged = {}
    for _level, profile in matching_profiles(phase, username, eud_uid, tool):
        for setting in profile.settings:
            merged[setting.key] = {
                "key": setting.key,
                "value": setting.value if setting.value is not None else "",
                "value_class": setting.value_class or STRING,
                "profile_id": profile.id,
                "profile_name": profile.name,
            }
    return [merged[key] for key in sorted(merged)]


def resolve_files(
    phase: str, username: str | None, eud_uid: str | None, tool: str | None = None
) -> list[dict]:
    """The profile files a device gets for phase, merged by zip path with the same precedence
    as settings: [{id, filename, zip_path, size, sha256, path (on disk), profile_id,
    profile_name}], sorted by zip path."""
    merged = {}
    for _level, profile in matching_profiles(phase, username, eud_uid, tool):
        for f in profile.files:
            merged[f.zip_path.lower()] = {
                "id": f.id,
                "filename": f.filename,
                "zip_path": f.zip_path,
                "size": f.size,
                "sha256": f.sha256,
                "path": stored_file_path(f),
                "profile_id": profile.id,
                "profile_name": profile.name,
            }
    return [merged[key] for key in sorted(merged)]


# --- files ---


def file_to_dict(f: DeviceProfileFile) -> dict:
    return {
        "id": f.id,
        "filename": f.filename,
        "zip_path": f.zip_path,
        "size": f.size,
        "sha256": f.sha256,
        "content_type": f.content_type,
        "uploaded_by": f.uploaded_by,
        "created_at": iso8601_string_from_datetime(f.created_at) if f.created_at else None,
    }


def files_folder() -> str:
    """Where profile files are stored, next to the data packages' uploads folder."""
    from flask import current_app

    folder = os.path.join(current_app.config.get("RAVEN_DATA_FOLDER"), FILES_FOLDER_NAME)
    os.makedirs(folder, exist_ok=True)
    return folder


def stored_file_path(f: DeviceProfileFile) -> str:
    return os.path.join(files_folder(), f.stored_name)


def safe_file_name(name) -> str:
    """A filename safe on disk and in a zip: no directories, ASCII letters/numbers/._- only
    (werkzeug's secure_filename), keeping the extension where it can. Raises
    ProfileValidationError if nothing usable is left."""
    from werkzeug.utils import secure_filename

    if not isinstance(name, str):
        name = ""
    # Browsers on Windows may send the full path
    name = secure_filename(name.replace("\\", "/").rsplit("/", 1)[-1])
    if not name or name.startswith("."):
        raise ProfileValidationError("That file needs a name made of letters and numbers")
    if len(name) > MAX_FILENAME_LENGTH:
        stem, ext = os.path.splitext(name)
        name = stem[: MAX_FILENAME_LENGTH - len(ext)] + ext
    return name


def safe_zip_folder(folder) -> str:
    """The folder a file goes in inside the zip ("" for the top level): relative, each part
    cleaned like a filename, no "..", at most MAX_FOLDER_DEPTH deep and not one of the folders
    the server writes itself. Raises ProfileValidationError."""
    from werkzeug.utils import secure_filename

    if folder is None:
        return ""
    if not isinstance(folder, str):
        raise ProfileValidationError("folder must be a string")
    raw_parts = [p for p in folder.replace("\\", "/").split("/") if p.strip()]
    parts = []
    for raw in raw_parts:
        if raw.strip() in (".", ".."):
            raise ProfileValidationError("The folder can't contain . or ..")
        part = secure_filename(raw)
        if not part:
            raise ProfileValidationError(f'"{raw[:50]}" is not a valid folder name')
        parts.append(part)
    if len(parts) > MAX_FOLDER_DEPTH:
        raise ProfileValidationError(f"Folders can be at most {MAX_FOLDER_DEPTH} levels deep")
    if parts and parts[0].lower() in RESERVED_ZIP_FOLDERS:
        raise ProfileValidationError(f'The "{parts[0]}" folder is reserved for the server')
    return "/".join(parts)


def file_limits() -> dict:
    from flask import current_app

    config = current_app.config
    mb = 1024 * 1024
    return {
        "max_file_bytes": int(config.get("RAVEN_DEVICE_PROFILE_MAX_FILE_MB", 100)) * mb,
        "max_total_bytes": int(config.get("RAVEN_DEVICE_PROFILE_MAX_TOTAL_MB", 500)) * mb,
        "max_files": int(config.get("RAVEN_DEVICE_PROFILE_MAX_FILES", 50)),
    }


def _megabytes(size: int) -> str:
    return f"{size / (1024 * 1024):.0f} MB"


def add_profile_file(
    profile: DeviceProfileSet, stream, filename, folder=None, content_type=None, actor=None
) -> tuple[DeviceProfileFile, DeviceProfileFile | None]:
    """Stores stream (a file-like object) as a file of profile and returns (the new row, the row
    it replaced or None), added to the session but not committed. A file already at the same zip
    path is replaced (remove the old bytes once the caller commits, see delete_stored_files()).
    Bumps the profile's updated_at so connected devices fetch it again. Raises
    ProfileValidationError (nothing is left on disk then)."""
    filename = safe_file_name(filename)
    folder = safe_zip_folder(folder)
    zip_path = f"{folder}/{filename}" if folder else filename
    if len(zip_path) > MAX_ZIP_PATH_LENGTH:
        raise ProfileValidationError("That file's path is too long")

    limits = file_limits()
    replacing = next((f for f in profile.files if f.zip_path.lower() == zip_path.lower()), None)
    others = [f for f in profile.files if f is not replacing]
    if len(others) >= limits["max_files"]:
        raise ProfileValidationError(
            f"A profile can have at most {limits['max_files']} files"
        )
    room = limits["max_total_bytes"] - sum(f.size or 0 for f in others)
    cap = min(limits["max_file_bytes"], room)

    stored_name = uuid.uuid4().hex
    path = os.path.join(files_folder(), stored_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "xb") as out:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > cap:
                    if size > limits["max_file_bytes"]:
                        raise ProfileValidationError(
                            f"Files can be at most {_megabytes(limits['max_file_bytes'])}"
                        )
                    raise ProfileValidationError(
                        f"A profile's files can add up to at most "
                        f"{_megabytes(limits['max_total_bytes'])}"
                    )
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise ProfileValidationError("That file is empty")
    except BaseException:
        try:
            os.remove(path)
        except OSError:
            pass
        raise

    if replacing is not None:
        profile.files.remove(replacing)
        # Delete the old row before inserting one with the same (profile_id, zip_path)
        db.session.flush()
    row = DeviceProfileFile(
        filename=filename,
        zip_path=zip_path,
        stored_name=stored_name,
        size=size,
        sha256=digest.hexdigest(),
        content_type=(content_type or "")[:255] or None,
        uploaded_by=actor,
        created_at=utcnow(),
    )
    profile.files.append(row)
    profile.updated_at = utcnow()
    return row, replacing


def delete_stored_files(stored_names) -> None:
    """Removes profile files from disk. Call after the commit that dropped their rows."""
    from raven.extensions import logger

    folder = files_folder()
    for name in stored_names:
        if not name or "/" in name or "\\" in name or name.startswith("."):
            continue
        try:
            os.remove(os.path.join(folder, name))
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning(f"Could not remove device profile file {name}: {e}")


def copy_profile_files(source: DeviceProfileSet, target: DeviceProfileSet) -> None:
    """Gives target its own copy of each of source's files (so deleting one profile's file
    can't remove the other's bytes). Doesn't commit."""
    import shutil

    for f in source.files:
        stored_name = uuid.uuid4().hex
        shutil.copyfile(stored_file_path(f), os.path.join(files_folder(), stored_name))
        target.files.append(
            DeviceProfileFile(
                filename=f.filename,
                zip_path=f.zip_path,
                stored_name=stored_name,
                size=f.size,
                sha256=f.sha256,
                content_type=f.content_type,
                uploaded_by=f.uploaded_by,
                created_at=utcnow(),
            )
        )


def username_for_eud(eud_uid: str | None) -> str | None:
    """The username of the account the EUD is bound to, if any."""
    from raven.models.EUD import EUD

    if not eud_uid:
        return None
    eud = db.session.query(EUD).filter_by(uid=eud_uid).one_or_none()
    if eud and eud.user:
        return eud.user.username
    return None
