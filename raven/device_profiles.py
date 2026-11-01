"""
Device profiles: named bundles of ATAK settings sent to devices at enrollment and/or on
connection (models: raven/models/DeviceProfileSet.py, DeviceProfileTarget.py,
DeviceProfileSetting.py; admin API: raven/blueprints/raven_api/device_profile_api.py; delivered
by raven/blueprints/marti_api/device_profile_marti_api.py).

resolve_settings() is the one place that decides what a device gets:
take the enabled profiles for the phase whose targets match the request (everyone, one of the
user's groups, the user, the device uid), then merge by key with precedence
device > user > group > everyone. Within the same precedence the most recently updated profile
wins. A profile that matches the request in several ways counts at its most specific match.
"""

import datetime
import math
import re

from sqlalchemy import func, or_

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime
from raven.models.DeviceProfileSet import DeviceProfileSet, utcnow
from raven.models.DeviceProfileSetting import DeviceProfileSetting
from raven.models.DeviceProfileTarget import TARGET_KINDS, DeviceProfileTarget

PHASES = ("enrollment", "connection")

STRING = "class java.lang.String"
BOOLEAN = "class java.lang.Boolean"
INTEGER = "class java.lang.Integer"
LONG = "class java.lang.Long"
FLOAT = "class java.lang.Float"
VALUE_CLASSES = (STRING, BOOLEAN, INTEGER, LONG, FLOAT)

# Precedence of a match, lowest first
EVERYONE, GROUP, USER, DEVICE = 0, 1, 2, 3
MATCH_NAMES = {EVERYONE: "everyone", GROUP: "group", USER: "user", DEVICE: "device"}

MAX_NAME_LENGTH = 255
MAX_KEY_LENGTH = 255
MAX_VALUE_LENGTH = 10000
MAX_TARGET_LENGTH = 255

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
    targets:[{kind, value}], settings:[{key, value, value_class}]}.

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
    ):
        setattr(profile, field, cleaned[field])
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
        "targets": [
            {"kind": t.kind, "value": t.value, "label": _target_label(t, callsigns)}
            for t in profile.targets
        ],
        "settings": [s.to_json() for s in profile.settings],
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


def matching_profiles(phase: str, username: str | None, eud_uid: str | None):
    """[(level, profile)] for the enabled profiles of phase that match, least specific first
    (so later entries win)."""
    if phase not in PHASES:
        raise ValueError(f"phase must be one of {PHASES}")
    query = db.session.query(DeviceProfileSet).filter(DeviceProfileSet.enabled.is_(True))
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


def resolve_settings(phase: str, username: str | None, eud_uid: str | None) -> list[dict]:
    """What a device gets for phase ("enrollment" or "connection"), after merging:
    [{key, value, value_class, profile_id, profile_name}], sorted by key."""
    merged = {}
    for _level, profile in matching_profiles(phase, username, eud_uid):
        for setting in profile.settings:
            merged[setting.key] = {
                "key": setting.key,
                "value": setting.value if setting.value is not None else "",
                "value_class": setting.value_class or STRING,
                "profile_id": profile.id,
                "profile_name": profile.name,
            }
    return [merged[key] for key in sorted(merged)]


def username_for_eud(eud_uid: str | None) -> str | None:
    """The username of the account the EUD is bound to, if any."""
    from raven.models.EUD import EUD

    if not eud_uid:
        return None
    eud = db.session.query(EUD).filter_by(uid=eud_uid).one_or_none()
    if eud and eud.user:
        return eud.user.username
    return None
