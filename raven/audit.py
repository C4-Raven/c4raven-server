"""
Security audit trail (see raven/blueprints/raven_api/security_audit_api.py).

record_audit_event() is the only writer. It is called from request handlers
that have already done their real work, so it must never raise or disturb the
caller's database session: the row goes in on its own connection and
transaction (db.engine.begin()), not db.session, and any failure is logged and
swallowed. A failed login that never commits db.session is still recorded, and
a failed audit insert can't roll back the request that triggered it.

init_audit(app) wires the Flask-Security / Flask-Login signals, the failed
login hook and the admin action hook. create_app() calls it; tests that build a
minimal app call it too.

The admin action hook (_audit_admin_action) is the one central place that logs
every state-changing web API request (POST/PUT/PATCH/DELETE under /api/) as an
"admin" category event: who, what endpoint, the target identifiers and a
redacted copy of the request's top-level fields, the HTTP status and whether it
worked. Endpoints don't need to do anything for it. Endpoints that record their
own, more specific events keep doing so; the admin row names them under "Also
logged" instead of being skipped, so the Admin actions view stays one row per
request and the Security Audit view (which hides "admin") is unchanged.
"""

import ipaddress
import re
import traceback
from datetime import datetime, timezone

from flask import g, has_request_context, request, session

from raven.extensions import db, logger

# Actions, by category. Kept here so the audit API and the hooks agree.
WEB_LOGIN_ACTIONS = ("web_login", "ldap_login")
FAILED_LOGIN_ACTIONS = ("web_login_failed", "ldap_login_failed", "tfa_failed")
ENROLLMENT_METHODS = {
    "enroll_qr": "qr",
    "enroll_zip": "zip",
    "enroll_credentials": "credentials",
    "onboard_package_download": "vpn_qr",
}

ADMIN_CATEGORY = "admin"

_LENGTHS = {
    "category": 32,
    "action": 64,
    "username": 255,
    "actor": 255,
    "ip": 64,
    "user_agent": 512,
    "summary": 255,
}


def _is_local(ip) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def client_ip():
    """The client's address. In production nginx proxies everything and
    create_app() wraps the app in ProxyFix(x_for=1), so remote_addr is already
    the X-Forwarded-For client. Without ProxyFix (tests, a direct local hop)
    remote_addr is loopback; then fall back to the headers nginx sets, which
    only a local process could have supplied."""
    if not has_request_context():
        return None
    ip = request.remote_addr
    if not ip or _is_local(ip):
        forwarded = request.headers.get("X-Real-IP") or (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        )
        if forwarded:
            ip = forwarded
    return ip


def record_audit_event(
    category: str,
    action: str,
    username: str | None = None,
    actor: str | None = None,
    success: bool = True,
    details: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    summary: str | None = None,
) -> bool:
    """Records one audit event. Never raises; returns False if it couldn't.

    :param username: The account the event is about
    :param actor: The admin who did it. Dropped when it's the same as username.
    :param ip/user_agent: Default to the current request's
    :param summary: One readable line, e.g. "Created group: Ops" (admin events)
    """
    try:
        from raven.models.AuditEvent import AuditEvent

        if has_request_context():
            if ip is None:
                ip = client_ip()
            if user_agent is None:
                user_agent = request.headers.get("User-Agent")
            if category != ADMIN_CATEGORY:
                # Named in this request's admin row, see _audit_admin_action
                try:
                    g.setdefault("_audit_recorded", []).append(f"{category}/{action}")
                except BaseException:
                    pass

        if actor and username and str(actor).lower() == str(username).lower():
            actor = None

        values = {
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None),
            "category": category,
            "action": action,
            "username": username,
            "actor": actor,
            "ip": ip,
            "user_agent": user_agent,
            "success": bool(success),
            "details": details,
            "summary": summary,
        }
        for key, length in _LENGTHS.items():
            if values[key] is not None:
                values[key] = str(values[key])[:length]

        with db.engine.begin() as connection:
            connection.execute(AuditEvent.__table__.insert().values(**values))
        return True
    except BaseException as e:
        logger.error(f"Failed to record audit event {category}/{action} for {username}: {e}")
        logger.debug(traceback.format_exc())
        return False


def current_username():
    """The logged-in web user's username, or None. Never raises."""
    try:
        from flask_security import current_user

        if current_user and current_user.is_authenticated:
            return current_user.username
    except BaseException:
        pass
    return None


def _attempted_username():
    """The username a login request tried, without touching the password."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = request.form
        for field in ("username", "email", "identity"):
            if data.get(field):
                return str(data.get(field))
    except BaseException:
        pass
    return None


def _response_errors(response):
    try:
        if not response.is_json:
            return None
        body = response.get_json(silent=True) or {}
        resp = body.get("response", body) if isinstance(body, dict) else {}
        errors = list(resp.get("errors") or [])
        for field, messages in (resp.get("field_errors") or {}).items():
            errors.extend(messages if isinstance(messages, list) else [messages])
        return "; ".join(str(e) for e in errors) or None
    except BaseException:
        return None


# --- Admin actions (see _audit_admin_action in init_audit) ---

ADMIN_AUDITED_METHODS = frozenset(("POST", "PUT", "PATCH", "DELETE"))

# View functions under /api/ that aren't admin actions: logins (covered by the auth events),
# machine-to-machine auth callbacks and a per-user UI preference
ADMIN_SKIPPED_VIEWS = frozenset(
    (
        "ldap_login",
        "cloudtak_oauth_token",
        "rabbitmq_auth",
        "external_auth",
        "set_language",
    )
)

# Readable labels by view function name, optionally by method. Anything missing falls back to
# "METHOD /path". Stored as written, in English, so the trail reads the same for every viewer.
ADMIN_ACTION_LABELS = {
    # Users
    "create_user": "Created user",
    "delete_user": "Deleted user",
    "activate_user": "Activated user",
    "deactivate_user": "Deactivated user",
    "set_user_role": "Changed user role",
    "admin_reset_password": "Reset user password",
    "issue_temp_password": "Issued temporary password",
    "force_password_reset": "Forced password change",
    "grant_site_access": "Granted web access",
    "revoke_site_access": "Revoked web access",
    "assign_eud_to_user": "Assigned device to user",
    "clear_user_content": "Cleared user content",
    "send_file_to_user": "Sent file to user",
    "set_certificate_validity": "Changed certificate validity",
    "add_user_to_groups": "Changed user groups",
    "create_user_filter": "Created user filter",
    "add_user_to_filter": "Added user to filter",
    "remove_user_from_filter": "Removed user from filter",
    "delete_user_filter": "Deleted user filter",
    # Groups
    "add_group": "Created group",
    "delete_group": "Deleted group",
    "add_user_to_group": "Added user to group",
    "remove_user_from_group": "Removed user from group",
    "update_group_member": "Changed group member access",
    "update_group_policy": "Changed group policy",
    "apply_group_auto_join": "Applied group auto-join",
    "set_user_visibility": "Changed user visibility",
    "remove_user_visibility": "Removed user visibility",
    # Enrollment and certificates
    "new_atak_qr_string": "Created ATAK enrollment QR code",
    "new_vpn_qr_string": "Created VPN enrollment QR code",
    "delete_token": "Deleted enrollment QR code",
    "certificate": "Generated certificate package",
    "revoke_certificate": "Revoked certificate",
    "revoke_certificate_by_serial": "Revoked certificate by serial",
    "revoke_all_user_certificates": "Revoked all user certificates",
    # Not in this tree yet: the name the certificates work is expected to give its re-enroll view
    "allow_device_reenrollment": "Allowed device to enroll again",
    # Data packages, documents, app packages and plugins
    "upload_data_package": "Uploaded data package",
    "edit_data_package": "Edited data package",
    "delete_data_package": "Deleted data package",
    "edit_data_package_groups": "Changed data package groups",
    "upload_supporting_document": "Uploaded supporting document",
    "delete_supporting_document": "Deleted supporting document",
    "add_package": "Uploaded app package",
    "edit_package": "Edited app package",
    "delete_package": "Deleted app package",
    "upload_plugin": "Uploaded server plugin",
    "enable_plugin": "Enabled server plugin",
    "disable_plugin": "Disabled server plugin",
    "download_plugin": "Downloaded tak.gov plugin",
    "unlink_tak_gov_account": "Unlinked tak.gov account",
    "get_new_tak_gov_token": "Refreshed tak.gov token",
    # Device profiles
    "create_profile_set": "Created device profile",
    "update_profile_set": "Updated device profile",
    "delete_profile_set": "Deleted device profile",
    "duplicate_profile_set": "Duplicated device profile",
    "import_device_profile": "Imported device profile",
    "add_device_profile": "Added device profile setting",
    "delete_device_profile": "Deleted device profile setting",
    "upload_profile_files": "Uploaded device profile file",
    "delete_profile_file": "Deleted device profile file",
    # Video
    "add_update_stream": {"POST": "Added video stream", "PATCH": "Updated video stream"},
    "delete_stream": "Deleted video stream",
    "edit_video_stream_groups": "Changed video stream groups",
    "download_recording": {"DELETE": "Deleted video recording"},
    # Missions, markers, CASEVAC
    "create_edit_mission": {"POST": "Created mission", "PUT": "Edited mission"},
    "delete_mission": "Deleted mission",
    "invite_eud": "Invited device to mission",
    "add_marker": "Added marker",
    "delete_marker": "Deleted marker",
    "add_casevac": "Added CASEVAC",
    "delete_casevac": "Deleted CASEVAC",
    # Meshtastic
    "create_channel": "Created Meshtastic channel",
    "delete_channel": "Deleted Meshtastic channel",
    # Scheduler
    "schedule_job": "Scheduled job",
    "modify_job": "Modified scheduled job",
    "run_job": "Ran scheduled job",
    "pause_job": "Paused scheduled job",
    "resume_job": "Resumed scheduled job",
    "cancel_job": "Cancelled scheduled job",
    # Federation
    "save_policy": "Saved federation policy",
    "save_core_policy": "Saved federation core policy",
    "save_plugins_policy": "Saved federation plugin policy",
    "save_view_policy": "Saved federation view policy",
    "activate_federation_policy": "Activated federation policy",
    "delete_federation_policy": "Deleted federation policy",
    "add_ca_group": "Added federation CA group",
    "update_ca_group_nickname": "Renamed federation CA group",
    "delete_ca_group": "Deleted federation CA group",
    "update_connection_groups": "Changed federation connection groups",
    "disconnect_connection": "Disconnected federation connection",
    "restart_broker": "Restarted federation broker",
    "verify_admin_cert_2fa": "Verified federation admin certificate",
    # Data retention
    "put_retention": "Changed data retention settings",
}

# Request fields shown as the event's target, first present wins (after any URL parameters)
_TARGET_FIELDS = (
    "username",
    "name",
    "group_name",
    "filter_name",
    "callsign",
    "uid",
    "eud_uid",
    "mission_name",
    "plugin_name",
    "package_name",
    "path",
    "hash",
    "serial",
    "id",
    "job_id",
    "filter_id",
    "connection_id",
)

# Field names whose values are never written to the trail. Matched against the name's words
# ("new_password" -> new, password) and, for the compound ones, the whole squashed name.
_REDACTED_WORDS = frozenset(
    (
        "password",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "secret",
        "token",
        "tokens",
        "credential",
        "credentials",
        "cookie",
        "session",
        "authorization",
        "bearer",
        "salt",
        "psk",
        "otp",
        "totp",
        "hotp",
        "nonce",
        "signature",
        "truststore",
        "keystore",
        "privkey",
        "private",
        "jwt",
        "hmac",
    )
)
_REDACTED_EXACT = frozenset(("key", "code", "auth", "sig", "pin"))
_REDACTED_SQUASHED = (
    "password",
    "passphrase",
    "secret",
    "token",
    "privatekey",
    "apikey",
    "accesskey",
    "passphrase",
)
# A name ending in "key" (client_key, sshKey, encryption_key) is key material, except these
# names of a key rather than for one
_NON_SECRET_KEY_PREFIXES = frozenset(
    ("preference", "pref", "setting", "settings", "sort", "lookup", "map", "group", "public")
)
# Request shapes that carry a setting as a name field and a value field, e.g. the device profile
# API's {"preference_key": "caPassword0", "preference_value": "..."}. When the name field names a
# secret, the value field is redacted too.
_PAIR_FIELDS = (
    ("preference_key", "preference_value"),
    ("key", "value"),
    ("name", "value"),
)
# Certificate / key material: redacted unless the value is a plain number or flag
# (e.g. certificate_validity days)
_MATERIAL_WORDS = frozenset(
    ("cert", "certs", "certificate", "certificates", "pem", "p12", "pkcs12", "pfx", "csr", "crt")
)
_REDACTED = "[redacted]"
_URL_USERINFO = re.compile(r"([a-z][a-z0-9+.\-]*://)[^/@\s]+@", re.IGNORECASE)
# name=value parameters in a URL query string inside a value (srt://h?passphrase=..., rtsp://...?token=)
_URL_QUERY_PARAM = re.compile(r"([?&;])([^=&;#\s?]+)=([^&;#\s]*)")
_MAX_VALUE = 120
_MAX_LIST_ITEMS = 5
_MAX_DETAILS = 2000


def _key_words(key):
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key)).lower()
    return [w for w in re.split(r"[^a-z0-9]+", key) if w]


def is_sensitive_key(key, value=None) -> bool:
    words = _key_words(key)
    squashed = "".join(words)
    if squashed in _REDACTED_EXACT or any(w in _REDACTED_WORDS for w in words):
        return True
    if any(part in squashed for part in _REDACTED_SQUASHED):
        return True
    if len(words) > 1 and words[-1] in ("key", "keys") and words[-2] not in _NON_SECRET_KEY_PREFIXES:
        return True
    if any(w in _MATERIAL_WORDS for w in words):
        return not isinstance(value, (bool, int, float)) or value is None
    return False


def _mask_query_param(match):
    if is_sensitive_key(match.group(2)):
        return f"{match.group(1)}{match.group(2)}=***"
    return match.group(0)


def _safe_scalar(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    if "-----BEGIN" in text:
        return _REDACTED
    text = _URL_USERINFO.sub(r"\1***@", text)
    if "=" in text:
        text = _URL_QUERY_PARAM.sub(_mask_query_param, text)
    text = text.replace("\n", " ").replace("\r", " ")
    if len(text) > _MAX_VALUE:
        text = text[: _MAX_VALUE - 1] + "…"
    return text


def _safe_value(key, value):
    """A short, secret-free rendering of one top-level request field."""
    if is_sensitive_key(key, value):
        return _REDACTED
    if isinstance(value, dict):
        # Nested objects (device profile settings, policies...) can carry secrets under keys
        # that aren't recognisable here, so only their size is logged
        return f"{{{len(value)} fields}}"
    if isinstance(value, (list, tuple)):
        if any(isinstance(v, (dict, list, tuple)) for v in value):
            return f"[{len(value)} items]"
        items = [str(_safe_scalar(v)) for v in value[:_MAX_LIST_ITEMS]]
        more = f", +{len(value) - _MAX_LIST_ITEMS}" if len(value) > _MAX_LIST_ITEMS else ""
        return "[" + ", ".join(items) + more + "]"
    return _safe_scalar(value)


def _redact_pairs(source, fields):
    """Redacts the value half of a name/value pair whose name is a secret's (see _PAIR_FIELDS)."""
    try:
        for name_field, value_field in _PAIR_FIELDS:
            if value_field not in fields or name_field not in source:
                continue
            name = source.get(name_field)
            if isinstance(name, str) and name and is_sensitive_key(name):
                fields[value_field] = _REDACTED
    except BaseException:
        for _, value_field in _PAIR_FIELDS:
            if value_field in fields:
                fields[value_field] = _REDACTED


def admin_request_fields():
    """The current request's URL parameters, query string, JSON/form fields and uploaded file
    names, as {name: safe value}, secrets redacted. Never raises."""
    fields = {}
    try:
        for key, value in (request.view_args or {}).items():
            fields[key] = _safe_value(key, value)
        for key in request.args:
            values = request.args.getlist(key)
            fields.setdefault(key, _safe_value(key, values[0] if len(values) == 1 else values))
        data = request.get_json(silent=True) if request.is_json else None
        if isinstance(data, dict):
            for key, value in data.items():
                fields.setdefault(key, _safe_value(key, value))
            _redact_pairs(data, fields)
        elif isinstance(data, list):
            fields.setdefault("body", f"[{len(data)} items]")
        elif request.mimetype in ("multipart/form-data", "application/x-www-form-urlencoded"):
            for key in request.form:
                values = request.form.getlist(key)
                fields.setdefault(key, _safe_value(key, values[0] if len(values) == 1 else values))
            _redact_pairs(request.form, fields)
            for key, storage in request.files.items(multi=True):
                fields.setdefault(key, f"<file {_safe_scalar(storage.filename) or '?'}>")
    except BaseException as e:
        logger.debug(f"Admin audit: couldn't read request fields: {e}")
    return fields


def admin_action_label(view, method):
    label = ADMIN_ACTION_LABELS.get(view)
    if isinstance(label, dict):
        label = label.get(method)
    return label


def _admin_target(fields):
    for key in list((request.view_args or {}).keys()) + list(_TARGET_FIELDS):
        value = fields.get(key)
        if value not in (None, "", _REDACTED) and not str(value).startswith(("[", "{", "<")):
            return str(value)
    return None


def _response_failed(response):
    """True for an error status, or a 2xx JSON body that says {"success": false}."""
    if response.status_code >= 400:
        return True
    try:
        if response.is_json and not response.direct_passthrough:
            body = response.get_json(silent=True)
            if isinstance(body, dict) and body.get("success") is False:
                return True
    except BaseException:
        pass
    return False


def _response_error_text(response):
    errors = _response_errors(response)
    if errors:
        return errors
    try:
        body = response.get_json(silent=True) if response.is_json else None
        if isinstance(body, dict):
            for key in ("error", "message"):
                if body.get(key):
                    return str(body.get(key))
    except BaseException:
        pass
    return None


def record_admin_action(response):
    """Writes the admin row for the current request (see _audit_admin_action). Never raises."""
    try:
        view = (request.endpoint or "").rsplit(".", 1)[-1]
        method = request.method
        actor = current_username()
        fields = admin_request_fields()

        target = _admin_target(fields)
        label = admin_action_label(view, method)
        if label:
            summary = f"{label}: {target}" if target else label
        else:
            summary = f"{method} {request.path}"

        failed = _response_failed(response)
        parts = [f"{method} {request.path}", f"HTTP {response.status_code}"]
        if fields:
            parts.append(", ".join(f"{k}={v}" for k, v in fields.items()))
        if failed:
            error = _response_error_text(response)
            if error:
                parts.append(f"Error: {_safe_scalar(error)}")
        also = list(dict.fromkeys(g.get("_audit_recorded") or []))
        if also:
            parts.append("Also logged: " + ", ".join(also))
        details = " · ".join(parts)
        if len(details) > _MAX_DETAILS:
            details = details[: _MAX_DETAILS - 1] + "…"

        username = fields.get("username")
        if not isinstance(username, str) or username == _REDACTED or username.startswith("["):
            username = None

        return record_audit_event(
            ADMIN_CATEGORY,
            view or method.lower(),
            username=username,
            actor=actor,
            success=not failed,
            details=details,
            summary=summary,
        )
    except BaseException as e:
        logger.error(f"Admin action audit error: {e}")
        logger.debug(traceback.format_exc())
        return False


def _is_admin_auditable(app):
    if request.method not in ADMIN_AUDITED_METHODS or not request.endpoint:
        return False
    path = request.path
    if not (path.startswith("/api/") or path == "/api"):
        return False
    # Flask-Security's own views (login, logout, password change, 2FA...) are auth events
    if request.blueprint == (app.config.get("SECURITY_BLUEPRINT_NAME") or "security"):
        return False
    if request.endpoint.rsplit(".", 1)[-1] in ADMIN_SKIPPED_VIEWS:
        return False
    # Only authenticated users: anonymous rejections are noise, failed logins are auth events
    return current_username() is not None


def _is_csrf_rejection(response):
    """A request CSRFProtect refused before the view ran (the UI fetches a token and retries)."""
    try:
        if response.status_code != 400 or g.get("csrf_valid", False):
            return False
        if response.direct_passthrough:
            return False
        return "csrf" in response.get_data(as_text=True)[:1000].lower()
    except BaseException:
        return False


def init_audit(app):
    """Connects the audit hooks to app. Safe to call once per app."""
    from flask_login.signals import user_logged_out
    from flask_security.signals import (
        password_changed,
        password_reset,
        tf_disabled,
        tf_profile_changed,
        user_authenticated,
        user_registered,
        wan_deleted,
        wan_registered,
    )

    @user_authenticated.connect_via(app)
    def _audit_login(sender, user, authn_via=None, **extra):
        authn_via = list(authn_via or [])
        # change_user_password() re-logs the user in; that's a password_change event
        if "change" in authn_via:
            return
        action = "ldap_login" if "ldap" in authn_via else "web_login"
        record_audit_event(
            "auth",
            action,
            username=user.username,
            details=f"via {', '.join(authn_via) or 'unknown'}",
        )

    @user_logged_out.connect_via(app)
    def _audit_logout(sender, user=None, **extra):
        record_audit_event("auth", "logout", username=getattr(user, "username", None))

    @password_changed.connect_via(app)
    def _audit_password_changed(sender, user, **extra):
        # admin_change_password() (user_api: admin reset / temp password) fires this too
        actor = current_username()
        if actor and actor.lower() != user.username.lower():
            record_audit_event(
                "user_admin",
                "password_reset_by_admin",
                username=user.username,
                actor=actor,
                details="Password set by an administrator (user must change it at next login)",
            )
        else:
            record_audit_event("auth", "password_change", username=user.username)

    @password_reset.connect_via(app)
    def _audit_password_reset(sender, user, **extra):
        record_audit_event(
            "auth", "password_reset", username=user.username, details="Reset via emailed link"
        )

    @tf_profile_changed.connect_via(app)
    def _audit_tf_changed(sender, user, method=None, **extra):
        record_audit_event(
            "auth", "tfa_change", username=user.username, details=f"2FA method: {method}"
        )

    @tf_disabled.connect_via(app)
    def _audit_tf_disabled(sender, user, **extra):
        record_audit_event("auth", "tfa_disabled", username=user.username)

    @wan_registered.connect_via(app)
    def _audit_passkey_added(sender, user, name=None, **extra):
        record_audit_event(
            "auth", "passkey_added", username=user.username, details=f"Passkey: {name}"
        )

    @wan_deleted.connect_via(app)
    def _audit_passkey_removed(sender, user, name=None, **extra):
        record_audit_event(
            "auth", "passkey_removed", username=user.username, details=f"Passkey: {name}"
        )

    @user_registered.connect_via(app)
    def _audit_registered(sender, user, **extra):
        record_audit_event(
            "user_admin", "user_registered", username=user.username, details="Self-registration"
        )

    @app.after_request
    def _audit_failed_login(response):
        try:
            if request.method != "POST" or response.status_code < 400:
                return response

            prefix = app.config.get("SECURITY_URL_PREFIX") or ""
            login_url = prefix + (app.config.get("SECURITY_LOGIN_URL") or "/login")
            tf_url = prefix + (
                app.config.get("SECURITY_TWO_FACTOR_TOKEN_VALIDATION_URL") or "/tf-validate"
            )
            path = request.path.rstrip("/") or "/"

            if path == login_url:
                action, username = "web_login_failed", _attempted_username()
            elif path == "/api/ldap_login":
                action, username = "ldap_login_failed", _attempted_username()
            elif path == tf_url:
                action, username = "tfa_failed", None
                uniquifier = session.get("tf_user_id")
                if uniquifier:
                    user = app.security.datastore.find_user(fs_uniquifier=uniquifier)
                    username = user.username if user else None
            else:
                return response

            errors = _response_errors(response)
            record_audit_event(
                "auth",
                action,
                username=username,
                success=False,
                details=f"HTTP {response.status_code}" + (f": {errors}" if errors else ""),
            )
        except BaseException as e:
            logger.error(f"Failed login audit hook error: {e}")
        return response

    @app.after_request
    def _audit_admin_action(response):
        try:
            if _is_admin_auditable(app) and not _is_csrf_rejection(response):
                record_admin_action(response)
        except BaseException as e:
            logger.error(f"Admin action audit hook error: {e}")
        return response
