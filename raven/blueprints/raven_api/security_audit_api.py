"""
Admin Security Audit: account posture, computed findings and the audit_events trail (written by
raven.audit.record_audit_event from the login, enrollment, certificate and user admin code paths).

GET /api/security/audit?days=30&category=&search=&limit=1000  -> JSON report
GET /api/security/audit/download?days=30&format=txt|csv       -> report .txt, or its events .csv
GET /api/security/audit/events?category=admin&...             -> just the events (Admin actions)
GET /api/security/audit/events/download?format=csv|txt&...    -> those events as a file

Event filters, on all four: days (window, default 30) or start/end (ISO dates or datetimes; a
bare end date includes that whole day), category (comma separated), actor, action (comma
separated), success (true/false), search (free text). Without a category the security report
leaves out the "admin" rows; those are the Admin actions view's.
"""

import csv
import datetime
import io
import traceback
from collections import defaultdict

from flask import Blueprint, Response
from flask import current_app as app
from flask import jsonify, request
from flask_security import roles_accepted, verify_password
from sqlalchemy import and_, func, or_

from raven.audit import (
    ADMIN_CATEGORY,
    ENROLLMENT_METHODS,
    FAILED_LOGIN_ACTIONS,
    WEB_LOGIN_ACTIONS,
)
from raven.extensions import db, logger
from raven.functions import iso8601_string_from_datetime
from raven.models.AuditEvent import AuditEvent
from raven.models.Certificate import Certificate
from raven.models.EUD import EUD
from raven.models.Token import Token
from raven.models.user import User
from raven.models.WebAuthn import WebAuthn

security_audit_api_blueprint = Blueprint("security_audit_api_blueprint", __name__)

# Failed authentications (web, LDAP, 2FA, device enrollment) from one IP or against one username
# in the window before it's reported, and when it becomes high severity
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_HIGH_THRESHOLD = 20
# Distinct attempted usernames from one IP that look like password spraying
SPRAY_THRESHOLD = 5
# Distinct IPs a single account logged in from in the window
MANY_IPS_THRESHOLD = 5
STALE_ACCOUNT_DAYS = 90
CERT_EXPIRY_WARNING_DAYS = 14
MANY_ADMINS_THRESHOLD = 3
# Default password create_app() gives the first administrator account
DEFAULT_PASSWORD = "password"

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
FAILED_AUTH_ACTIONS = FAILED_LOGIN_ACTIONS + ("enroll_failed", "oauth_token_failed")


def _iso(value):
    return iso8601_string_from_datetime(value) if value else None


def _int_arg(name, default, minimum, maximum):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _names(items, limit=10):
    items = sorted(items, key=lambda x: str(x).lower())
    text = ", ".join(str(i) for i in items[:limit])
    if len(items) > limit:
        text += f" and {len(items) - limit} more"
    return text


def _now():
    # Naive UTC, like audit_events.timestamp and Flask-Security's trackable columns
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _users(now):
    users = db.session.query(User).order_by(User.username).all()

    passkeys = dict(
        db.session.query(WebAuthn.user_id, func.count(WebAuthn.id)).group_by(WebAuthn.user_id).all()
    )

    certificates = defaultdict(list)
    for cert in db.session.query(Certificate).all():
        if cert.username:
            certificates[cert.username.lower()].append(cert)

    devices = defaultdict(list)
    for eud in db.session.query(EUD).filter(EUD.user_id.isnot(None)).all():
        devices[eud.user_id].append(eud)

    methods = defaultdict(set)
    rows = (
        db.session.query(AuditEvent.username, AuditEvent.action)
        .filter(
            AuditEvent.action.in_(list(ENROLLMENT_METHODS.keys())), AuditEvent.success.is_(True)
        )
        .filter(AuditEvent.username.isnot(None))
        .distinct()
        .all()
    )
    for username, action in rows:
        methods[username.lower()].add(ENROLLMENT_METHODS[action])

    result = []
    for user in users:
        key = user.username.lower()
        user_methods = set(methods.get(key, set()))
        user_certs = certificates.get(key, [])
        # Certs from before audit logging: a cert data package was issued, or a device enrolled
        # through signClient (QR token or credentials -- which one wasn't recorded)
        if any(c.data_package_id for c in user_certs) and "zip" not in user_methods:
            user_methods.add("cert_package")
        if any(c.eud_uid and c.csr for c in user_certs) and not user_methods & {
            "qr",
            "credentials",
        }:
            user_methods.add("csr")

        result.append(
            {
                "user": user,
                "certs": user_certs,
                "json": {
                    "username": user.username,
                    "roles": [role.name for role in user.roles],
                    "active": bool(user.active),
                    "site_access": bool(user.site_access),
                    "last_login_at": _iso(user.last_login_at),
                    "last_login_ip": user.last_login_ip,
                    "current_login_at": _iso(user.current_login_at),
                    "current_login_ip": user.current_login_ip,
                    "login_count": user.login_count or 0,
                    "tfa_enabled": bool(user.tf_primary_method),
                    "passkeys": int(passkeys.get(user.id, 0)),
                    "certificates": len(user_certs),
                    "devices": [
                        {"uid": e.uid, "callsign": e.callsign, "last_seen": _iso(e.last_event_time)}
                        for e in sorted(devices.get(user.id, []), key=lambda e: e.uid)
                    ],
                    "enrollment_methods": sorted(user_methods),
                },
            }
        )
    return result


def _findings(users, cutoff, now):
    findings = []

    def add(severity, title, detail):
        findings.append({"severity": severity, "title": title, "detail": detail})

    protected = {u.lower() for u in (app.config.get("RAVEN_PROTECTED_USERNAMES") or [])}
    admins = [u for u in users if "administrator" in u["json"]["roles"]]
    active_admins = [u for u in admins if u["json"]["active"]]

    # --- Accounts ---
    no_2fa = [u["json"]["username"] for u in active_admins if not u["json"]["tfa_enabled"]]
    if no_2fa:
        add(
            "high",
            f"{len(no_2fa)} administrator account(s) without two-factor authentication",
            f"{_names(no_2fa)}. An administrator password alone can issue certificates for any "
            "user and wipe devices; enable 2FA under the account's security settings.",
        )

    default_pw = []
    for u in active_admins:
        try:
            if u["user"].password and verify_password(DEFAULT_PASSWORD, u["user"].password):
                default_pw.append(u["json"]["username"])
        except Exception:
            pass
    if default_pw:
        add(
            "high",
            "Administrator account still using the default password",
            f"{_names(default_pw)} accept the install-time default password. Change it now.",
        )

    if len(active_admins) > MANY_ADMINS_THRESHOLD:
        add(
            "low",
            f"{len(active_admins)} active administrator accounts",
            f"{_names([u['json']['username'] for u in active_admins])}. Keep the administrator "
            "role to the people who need it.",
        )

    pending = [
        u["json"]["username"]
        for u in users
        if u["json"]["active"] and u["user"].force_password_change
    ]
    if pending:
        add(
            "medium",
            f"{len(pending)} account(s) still on an administrator-set password",
            f"{_names(pending)} must change their password at next login, so the password an "
            "administrator set or relayed is still the live one.",
        )

    unused = [
        u["json"]["username"]
        for u in users
        if u["json"]["active"]
        and not u["json"]["login_count"]
        and not u["json"]["devices"]
        and not u["certs"]
        and u["json"]["username"].lower() not in protected
    ]
    if unused:
        add(
            "low",
            f"{len(unused)} account(s) never used",
            f"{_names(unused)} have never logged in to the web UI and have no devices or "
            "certificates. Deactivate or delete accounts nobody uses.",
        )

    stale_cutoff = now - datetime.timedelta(days=STALE_ACCOUNT_DAYS)
    stale = [
        u["json"]["username"]
        for u in users
        if u["json"]["active"]
        and u["json"]["site_access"]
        and u["user"].current_login_at
        and u["user"].current_login_at < stale_cutoff
        and not any(e.last_event_time and e.last_event_time >= stale_cutoff for e in u["user"].euds)
    ]
    if stale:
        add(
            "low",
            f"{len(stale)} account(s) inactive for over {STALE_ACCOUNT_DAYS} days",
            f"{_names(stale)}: no web login and no device activity in {STALE_ACCOUNT_DAYS} days.",
        )

    non_admins = [
        u for u in users if u["json"]["active"] and "administrator" not in u["json"]["roles"]
    ]
    site = [u["json"]["username"] for u in non_admins if u["json"]["site_access"]]
    if site:
        add(
            "info",
            f"{len(site)} of {len(non_admins)} non-administrator account(s) can sign in to the web UI",
            "Web access is granted by default. Revoke it for device-only users "
            f"({_names(site)}).",
        )

    # --- Certificates ---
    expired, expiring, disabled_with_certs = [], [], defaultdict(int)
    soon = now + datetime.timedelta(days=CERT_EXPIRY_WARNING_DAYS)
    for u in users:
        for cert in u["certs"]:
            if not cert.expiration_date:
                continue
            if cert.expiration_date < now:
                if cert.eud_uid:
                    expired.append(f"{u['json']['username']}/{cert.callsign or cert.eud_uid}")
            elif not u["json"]["active"]:
                disabled_with_certs[u["json"]["username"]] += 1
            elif cert.expiration_date < soon:
                expiring.append(
                    f"{u['json']['username']}/{cert.callsign or cert.eud_uid or 'package'}"
                )
    if disabled_with_certs:
        add(
            "low",
            f"{len(disabled_with_certs)} deactivated account(s) still hold unexpired certificates",
            f"{_names(disabled_with_certs.keys())}. Raven has no certificate revocation; the "
            "streaming port refuses deactivated users, so re-activating the account makes these "
            "certificates usable again. Delete the account if it shouldn't come back.",
        )
    if expired:
        add(
            "low",
            f"{len(expired)} expired certificate(s) still linked to devices",
            f"{_names(expired)}. These devices need to re-enroll to connect.",
        )
    if expiring:
        add(
            "info",
            f"{len(expiring)} certificate(s) expire within {CERT_EXPIRY_WARNING_DAYS} days",
            _names(expiring),
        )

    # --- Enrollment tokens ---
    open_tokens = (
        db.session.query(Token)
        .filter(Token.expiration.is_(None), Token.max_uses.is_(None))
        .filter(or_(Token.disabled.is_(None), Token.disabled.is_(False)))
        .all()
    )
    if open_tokens:
        add(
            "medium",
            f"{len(open_tokens)} enrollment QR token(s) never expire and have no use limit",
            f"Users: {_names([t.username for t in open_tokens])}. Anyone with a photo of the QR "
            "can enroll a device as that user indefinitely. Regenerate with an expiry or max uses, "
            "or delete the token.",
        )

    ownerless = (
        db.session.query(EUD.uid).filter(EUD.user_id.is_(None), EUD.federated_from.is_(None)).all()
    )
    if ownerless:
        add(
            "low",
            f"{len(ownerless)} device(s) not linked to any user",
            f"{_names([r[0] for r in ownerless])}. Unowned devices can't be traced to a person; "
            "assign or remove them.",
        )

    # --- Authentication activity in the window ---
    failures = (
        db.session.query(AuditEvent.ip, func.count(AuditEvent.id))
        .filter(AuditEvent.timestamp >= cutoff, AuditEvent.action.in_(FAILED_AUTH_ACTIONS))
        .filter(AuditEvent.ip.isnot(None))
        .group_by(AuditEvent.ip)
        .all()
    )
    noisy_ips = {ip: count for ip, count in failures if count >= BRUTE_FORCE_THRESHOLD}
    if noisy_ips:
        worst = max(noisy_ips.values())
        add(
            "high" if worst >= BRUTE_FORCE_HIGH_THRESHOLD else "medium",
            f"Repeated failed logins from {len(noisy_ips)} IP address(es)",
            "Possible brute force: "
            + _names(
                [
                    f"{ip} ({count} failures)"
                    for ip, count in sorted(noisy_ips.items(), key=lambda x: -x[1])
                ]
            )
            + ". Consider blocking these addresses at the firewall.",
        )

        sprays = (
            db.session.query(AuditEvent.ip, func.count(func.distinct(AuditEvent.username)))
            .filter(AuditEvent.timestamp >= cutoff, AuditEvent.action.in_(FAILED_AUTH_ACTIONS))
            .filter(AuditEvent.ip.in_(list(noisy_ips.keys())))
            .group_by(AuditEvent.ip)
            .all()
        )
        sprays = {ip: n for ip, n in sprays if n >= SPRAY_THRESHOLD}
        if sprays:
            add(
                "high",
                "Password spraying: many usernames tried from one IP",
                _names([f"{ip} ({n} usernames)" for ip, n in sprays.items()]),
            )

        breached = (
            db.session.query(AuditEvent.ip, AuditEvent.username)
            .filter(AuditEvent.timestamp >= cutoff, AuditEvent.action.in_(WEB_LOGIN_ACTIONS))
            .filter(AuditEvent.success.is_(True), AuditEvent.ip.in_(list(noisy_ips.keys())))
            .distinct()
            .all()
        )
        if breached:
            add(
                "high",
                "Successful login from an IP with repeated failures",
                _names([f"{username} from {ip}" for ip, username in breached])
                + ". Confirm these logins were the real account holders.",
            )

    user_failures = (
        db.session.query(AuditEvent.username, func.count(AuditEvent.id))
        .filter(AuditEvent.timestamp >= cutoff, AuditEvent.action.in_(FAILED_AUTH_ACTIONS))
        .filter(AuditEvent.username.isnot(None))
        .group_by(AuditEvent.username)
        .all()
    )
    targeted = {name: n for name, n in user_failures if n >= BRUTE_FORCE_THRESHOLD}
    if targeted:
        add(
            "medium",
            f"Repeated failed logins against {len(targeted)} account(s)",
            _names(
                [
                    f"{name} ({n} failures)"
                    for name, n in sorted(targeted.items(), key=lambda x: -x[1])
                ]
            ),
        )

    login_ips = (
        db.session.query(AuditEvent.username, func.count(func.distinct(AuditEvent.ip)))
        .filter(AuditEvent.timestamp >= cutoff, AuditEvent.action.in_(WEB_LOGIN_ACTIONS))
        .filter(AuditEvent.success.is_(True), AuditEvent.username.isnot(None))
        .group_by(AuditEvent.username)
        .all()
    )
    roaming = {name: n for name, n in login_ips if n >= MANY_IPS_THRESHOLD}
    if roaming:
        add(
            "medium",
            f"{len(roaming)} account(s) logged in from many different IP addresses",
            _names([f"{name} ({n} IPs)" for name, n in roaming.items()])
            + ". Could be a shared or leaked password.",
        )

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return findings


def _summary(users, cutoff, findings):
    counts = dict(
        db.session.query(AuditEvent.action, func.count(AuditEvent.id))
        .filter(AuditEvent.timestamp >= cutoff, AuditEvent.success.is_(True))
        .group_by(AuditEvent.action)
        .all()
    )
    failed = (
        db.session.query(func.count(AuditEvent.id))
        .filter(AuditEvent.timestamp >= cutoff, AuditEvent.action.in_(FAILED_LOGIN_ACTIONS))
        .scalar()
    )

    # Accounts with a web login or device activity in the window
    active = {
        r[0].lower()
        for r in db.session.query(AuditEvent.username)
        .filter(AuditEvent.timestamp >= cutoff, AuditEvent.action.in_(WEB_LOGIN_ACTIONS))
        .filter(AuditEvent.success.is_(True), AuditEvent.username.isnot(None))
        .distinct()
        .all()
    }
    for u in users:
        user = u["user"]
        if (user.current_login_at and user.current_login_at >= cutoff) or any(
            e.last_event_time and e.last_event_time >= cutoff for e in user.euds
        ):
            active.add(user.username.lower())

    return {
        "web_logins": sum(counts.get(a, 0) for a in WEB_LOGIN_ACTIONS),
        "failed_logins": failed or 0,
        "qr_enrollments": counts.get("enroll_qr", 0),
        "zip_enrollments": counts.get("enroll_zip", 0),
        "credential_enrollments": counts.get("enroll_credentials", 0),
        "active_users": len(active),
        "certificates_revoked": counts.get("cert_revoked", 0),
        "findings": len(findings),
    }


def _list_arg(name):
    values = []
    for raw in request.args.getlist(name):
        values.extend(v.strip() for v in str(raw).split(",") if v.strip())
    return values or None


def _datetime_arg(name, end_of_day=False):
    """An ISO date or datetime query arg as naive UTC, or None. A bare date with end_of_day is
    the start of the next day, so end=2026-11-02 includes all of the 2nd."""
    raw = (request.args.get(name) or "").strip()
    if not raw:
        return None
    try:
        value = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    if end_of_day and len(raw) == 10:
        value += datetime.timedelta(days=1)
    return value


def _bool_arg(name):
    raw = (request.args.get(name) or "").strip().lower()
    if raw in ("true", "1", "yes"):
        return True
    if raw in ("false", "0", "no"):
        return False
    return None


def event_filters(default_category=None):
    """The event filters from the query string, see the module docstring."""
    category = _list_arg("category") or ([default_category] if default_category else None)
    return {
        "category": category,
        "search": (request.args.get("search") or "").strip() or None,
        "actor": (request.args.get("actor") or "").strip() or None,
        "action": _list_arg("action"),
        "success": _bool_arg("success"),
        "start": _datetime_arg("start"),
        "end": _datetime_arg("end", end_of_day=True),
    }


def _events_query(
    cutoff,
    category=None,
    search=None,
    actor=None,
    action=None,
    success=None,
    start=None,
    end=None,
):
    query = db.session.query(AuditEvent)
    query = query.filter(AuditEvent.timestamp >= (start or cutoff))
    if end:
        query = query.filter(AuditEvent.timestamp < end)
    if category:
        if isinstance(category, str):
            category = [category]
        query = query.filter(AuditEvent.category.in_(list(category)))
    else:
        # The admin action rows have their own view; without them the security trail reads as
        # it always has
        query = query.filter(AuditEvent.category != ADMIN_CATEGORY)
    if actor:
        like = f"%{actor}%"
        # record_audit_event drops actor when it's the account itself, so "actor" here is
        # whoever did it: the actor, or the user when there's no separate actor
        query = query.filter(
            or_(
                AuditEvent.actor.ilike(like),
                and_(AuditEvent.actor.is_(None), AuditEvent.username.ilike(like)),
            )
        )
    if action:
        if isinstance(action, str):
            action = [action]
        query = query.filter(AuditEvent.action.in_(list(action)))
    if success is not None:
        query = query.filter(AuditEvent.success.is_(bool(success)))
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                AuditEvent.username.ilike(like),
                AuditEvent.actor.ilike(like),
                AuditEvent.ip.ilike(like),
                AuditEvent.action.ilike(like),
                AuditEvent.category.ilike(like),
                AuditEvent.details.ilike(like),
                AuditEvent.summary.ilike(like),
                AuditEvent.user_agent.ilike(like),
            )
        )
    return query


def _events(cutoff, category=None, search=None, limit=1000, **filters):
    query = _events_query(cutoff, category=category, search=search, **filters)
    return query.order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()).limit(limit).all()


def build_report(days, category=None, search=None, limit=1000, **filters):
    now = _now()
    cutoff = now - datetime.timedelta(days=days)
    users = _users(now)
    findings = _findings(users, cutoff, now)
    return {
        "generated_at": _iso(now),
        "days": days,
        "summary": _summary(users, cutoff, findings),
        "findings": findings,
        "users": [u["json"] for u in users],
        "events": [e.to_json() for e in _events(cutoff, category, search, limit, **filters)],
    }


@security_audit_api_blueprint.route("/api/security/audit")
@roles_accepted("administrator")
def security_audit():
    try:
        report = build_report(
            _int_arg("days", 30, 1, 3650),
            limit=_int_arg("limit", 1000, 1, 10000),
            **event_filters(),
        )
        return jsonify(report)
    except BaseException as e:
        logger.error(f"Failed to build security audit: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": "Failed to build security audit"}), 500


def _table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  ".join("{:<%d}" % w for w in widths)
    out = [line.format(*headers).rstrip(), "  ".join("-" * w for w in widths)]
    out += [line.format(*row).rstrip() for row in rows]
    return out


def render_text_report(report):
    s = report["summary"]
    out = [
        "C4 Raven Security Audit",
        "=" * 23,
        f"Generated: {report['generated_at']}",
        f"Window:    last {report['days']} days",
        "",
        "SUMMARY",
        "-------",
        f"Web logins:              {s['web_logins']}",
        f"Failed logins:           {s['failed_logins']}",
        f"QR enrollments:          {s['qr_enrollments']}",
        f"ZIP enrollments:         {s['zip_enrollments']}",
        f"Credential enrollments:  {s['credential_enrollments']}",
        f"Active users:            {s['active_users']}",
        f"Certificates revoked:    {s['certificates_revoked']}",
        f"Findings:                {s['findings']}",
        "",
        "FINDINGS",
        "--------",
    ]
    if not report["findings"]:
        out.append("None.")
    for f in report["findings"]:
        out.append(f"[{f['severity'].upper()}] {f['title']}")
        out.append(f"    {f['detail']}")
    out += ["", "USERS", "-----"]

    def short(ts):
        return ts[:16].replace("T", " ") if ts else "-"

    out += _table(
        [
            "USERNAME",
            "ROLES",
            "ACTIVE",
            "WEB",
            "2FA",
            "KEYS",
            "LOGINS",
            "LAST LOGIN",
            "LAST IP",
            "CERTS",
            "DEVICES",
            "ENROLLMENT",
        ],
        [
            [
                u["username"],
                ",".join(u["roles"]) or "-",
                "yes" if u["active"] else "no",
                "yes" if u["site_access"] else "no",
                "yes" if u["tfa_enabled"] else "no",
                str(u["passkeys"]),
                str(u["login_count"]),
                short(u["current_login_at"]),
                u["current_login_ip"] or "-",
                str(u["certificates"]),
                ",".join(d["callsign"] or d["uid"] for d in u["devices"]) or "-",
                ",".join(u["enrollment_methods"]) or "-",
            ]
            for u in report["users"]
        ],
    )
    out += ["", f"EVENT LOG ({len(report['events'])} events, newest first)", "---------"]
    out += _table(
        ["TIME (UTC)", "CATEGORY", "ACTION", "OK", "USER", "ACTOR", "IP", "DETAILS"],
        [
            [
                e["timestamp"][:19].replace("T", " ") if e["timestamp"] else "-",
                e["category"],
                e["action"],
                "yes" if e["success"] else "NO",
                e["username"] or "-",
                e["actor"] or "-",
                e["ip"] or "-",
                (e["details"] or "").replace("\n", " "),
            ]
            for e in report["events"]
        ],
    )
    return "\n".join(out) + "\n"


EVENT_CSV_COLUMNS = (
    "timestamp",
    "category",
    "action",
    "summary",
    "success",
    "username",
    "actor",
    "ip",
    "user_agent",
    "details",
)


def _csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    # Keep spreadsheets from evaluating a logged value as a formula
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def render_events_csv(events):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(EVENT_CSV_COLUMNS)
    for e in events:
        writer.writerow([_csv_cell(e.get(c)) for c in EVENT_CSV_COLUMNS])
    return out.getvalue()


def render_events_text(events, title, generated_at, window):
    out = [title, "=" * len(title), f"Generated: {generated_at}", f"Window:    {window}", ""]
    out.append(f"{len(events)} events, newest first")
    out.append("")
    out += _table(
        ["TIME (UTC)", "ACTION", "OK", "ACTOR", "USER", "IP", "SUMMARY", "DETAILS"],
        [
            [
                e["timestamp"][:19].replace("T", " ") if e["timestamp"] else "-",
                e["action"],
                "yes" if e["success"] else "NO",
                e["actor"] or (e["username"] if e["category"] == ADMIN_CATEGORY else None) or "-",
                (e["username"] if e["actor"] else None) or "-",
                e["ip"] or "-",
                (e.get("summary") or "-").replace("\n", " "),
                (e["details"] or "").replace("\n", " "),
            ]
            for e in events
        ],
    )
    return "\n".join(out) + "\n"


def _attachment(body, filename, mimetype):
    return Response(
        body,
        mimetype=mimetype,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def _window_text(days, filters):
    if filters.get("start") or filters.get("end"):
        start = _iso(filters.get("start")) or "-"
        end = _iso(filters.get("end")) or "now"
        return f"{start} to {end}"
    return f"last {days} days"


@security_audit_api_blueprint.route("/api/security/audit/download")
@roles_accepted("administrator")
def security_audit_download():
    try:
        days = _int_arg("days", 30, 1, 3650)
        limit = _int_arg("limit", 10000, 1, 100000)
        filters = event_filters()
        stamp = _now().strftime("%Y%m%d-%H%M")
        if (request.args.get("format") or "txt").lower() == "csv":
            cutoff = _now() - datetime.timedelta(days=days)
            events = [e.to_json() for e in _events(cutoff, limit=limit, **filters)]
            return _attachment(
                render_events_csv(events), f"security-audit-{stamp}.csv", "text/csv"
            )
        report = build_report(days, limit=limit, **filters)
        return _attachment(
            render_text_report(report), f"security-audit-{stamp}.txt", "text/plain"
        )
    except BaseException as e:
        logger.error(f"Failed to build security audit download: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": "Failed to build security audit"}), 500


@security_audit_api_blueprint.route("/api/security/audit/events")
@roles_accepted("administrator")
def security_audit_events():
    """Events only, without the posture report: the Admin actions view (category=admin by
    default). Also returns the actors and actions seen in the window for its filter menus."""
    try:
        days = _int_arg("days", 30, 1, 3650)
        limit = _int_arg("limit", 1000, 1, 10000)
        filters = event_filters(default_category=ADMIN_CATEGORY)
        now = _now()
        cutoff = now - datetime.timedelta(days=days)

        events = _events(cutoff, limit=limit, **filters)
        total = _events_query(cutoff, **filters).order_by(None).count()

        # Filter menus: everything in the window and category, ignoring the other filters
        scope = _events_query(
            cutoff, category=filters["category"], start=filters["start"], end=filters["end"]
        )
        actors = set()
        pairs = scope.with_entities(AuditEvent.actor, AuditEvent.username).distinct()
        for actor, username in pairs:
            if actor or username:
                actors.add(actor or username)
        actions = {}
        pairs = scope.with_entities(AuditEvent.action, AuditEvent.summary).distinct()
        for action, summary in pairs:
            # The summary minus its target ("Created group: Ops" -> "Created group")
            if action not in actions or not actions[action]:
                actions[action] = (summary or "").split(": ", 1)[0] or None

        return jsonify(
            {
                "generated_at": _iso(now),
                "days": days,
                "total": total,
                "events": [e.to_json() for e in events],
                "actors": sorted(actors, key=str.lower),
                "actions": [
                    {"action": a, "label": label}
                    for a, label in sorted(actions.items(), key=lambda x: (x[1] or x[0]).lower())
                ],
            }
        )
    except BaseException as e:
        logger.error(f"Failed to list audit events: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": "Failed to list audit events"}), 500


@security_audit_api_blueprint.route("/api/security/audit/events/download")
@roles_accepted("administrator")
def security_audit_events_download():
    try:
        days = _int_arg("days", 30, 1, 3650)
        filters = event_filters(default_category=ADMIN_CATEGORY)
        now = _now()
        cutoff = now - datetime.timedelta(days=days)
        limit = _int_arg("limit", 10000, 1, 100000)
        events = [e.to_json() for e in _events(cutoff, limit=limit, **filters)]
        name = "admin-actions" if filters["category"] == [ADMIN_CATEGORY] else "audit-events"
        stamp = now.strftime("%Y%m%d-%H%M")
        if (request.args.get("format") or "csv").lower() == "txt":
            title = (
                "C4 Raven Admin Actions"
                if filters["category"] == [ADMIN_CATEGORY]
                else "C4 Raven Audit Events"
            )
            body = render_events_text(events, title, _iso(now), _window_text(days, filters))
            return _attachment(body, f"{name}-{stamp}.txt", "text/plain")
        return _attachment(render_events_csv(events), f"{name}-{stamp}.csv", "text/csv")
    except BaseException as e:
        logger.error(f"Failed to build audit events download: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": "Failed to build audit events download"}), 500
