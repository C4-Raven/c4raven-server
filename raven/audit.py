"""
Security audit trail (see raven/blueprints/raven_api/security_audit_api.py).

record_audit_event() is the only writer. It is called from request handlers
that have already done their real work, so it must never raise or disturb the
caller's database session: the row goes in on its own connection and
transaction (db.engine.begin()), not db.session, and any failure is logged and
swallowed. A failed login that never commits db.session is still recorded, and
a failed audit insert can't roll back the request that triggered it.

init_audit(app) wires the Flask-Security / Flask-Login signals and the failed
login hook. create_app() calls it; tests that build a minimal app call it too.
"""

import ipaddress
import traceback
from datetime import datetime, timezone

from flask import has_request_context, request, session

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

_LENGTHS = {
    "category": 32,
    "action": 64,
    "username": 255,
    "actor": 255,
    "ip": 64,
    "user_agent": 512,
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
) -> bool:
    """Records one audit event. Never raises; returns False if it couldn't.

    :param username: The account the event is about
    :param actor: The admin who did it. Dropped when it's the same as username.
    :param ip/user_agent: Default to the current request's
    """
    try:
        from raven.models.AuditEvent import AuditEvent

        if has_request_context():
            if ip is None:
                ip = client_ip()
            if user_agent is None:
                user_agent = request.headers.get("User-Agent")

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
