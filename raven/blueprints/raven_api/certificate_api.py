"""
Admin API for listing and revoking client certificates (see raven/cert_revocation.py).

Revoking a cert puts its serial in the CA's CRL, drops any live streaming connection using it and
records a "cert_revoked" audit event. The user's account is left active on purpose, so they can
enroll a replacement device straight away. The device the cert was issued to (its EUD uid) is
blocked from enrolling again (EnrollmentBlock) until an admin allows it, so a lost phone can't just
enroll for a new cert with the user's saved credentials; the admin can also reset the user's
password at the same time ("reset_password"), which stops the saved credentials working at all.

This blueprint also rejects requests nginx proxies with a revoked client cert in X-Ssl-Cert
(reject_revoked_client_cert), so a revocation takes effect on 8443 even before nginx has reloaded
its CRL.
"""

import datetime
import functools
import os
import secrets
import traceback

from cryptography.x509.oid import NameOID
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_security import admin_change_password, current_user, roles_accepted

from raven import cert_revocation, offline_chat
from raven.audit import record_audit_event
from raven.blueprints.raven_api.user_api import _protected_user_response
from raven.certificate_authority import CertificateAuthority
from raven.extensions import db, logger
from raven.models.Certificate import Certificate
from raven.models.EnrollmentBlock import EnrollmentBlock

certificate_api_blueprint = Blueprint("certificate_api_blueprint", __name__)

NOTE_MAX_LENGTH = 500
# Serials up to this came from the old randint(10000, 100000) in CertificateAuthority.sign_csr and
# can be shared by several certs: revoking one revokes all of them (the CRL is by serial).
LEGACY_SERIAL_MAX = 100000


@functools.lru_cache(maxsize=256)
def _forwarded_serial(header_value):
    return cert_revocation.forwarded_cert_serial(header_value)


@certificate_api_blueprint.before_app_request
def reject_revoked_client_cert():
    header = request.headers.get(app.config.get("RAVEN_SSL_CERT_HEADER") or "X-Ssl-Cert")
    if not header:
        return None
    serial = _forwarded_serial(header)
    if serial and cert_revocation.is_revoked(app.config.get("RAVEN_CA_FOLDER"), serial):
        logger.warning(
            "Rejected {} {} from {}: client cert serial {} is revoked".format(
                request.method, request.path, request.remote_addr, serial
            )
        )
        return (
            jsonify({"success": False, "error": gettext("This client certificate has been revoked")}),
            403,
        )
    return None


def _protected_cert_response(cert):
    """403 if this cert belongs to a protected account (RAVEN_PROTECTED_USERNAMES) and the
    caller isn't that account. Checks the common name as well as the username: rows without a
    username (legacy, or a by-serial revoke of one) still carry the identity in their CN."""
    for name in dict.fromkeys(n for n in (cert.username, cert.common_name) if n):
        response = _protected_user_response(name)
        if response:
            return response
    return None


def _shared_serial_response(certs, body):
    """409 if revoking these rows' serial(s) would also revoke certs for someone else.

    Old certs got serials from randint(10000, 100000), so two certs can share one, and the CRL
    can only revoke a serial (every cert with it). Unless the admin confirms with
    "confirm_shared_serial": true, refuse when a legacy serial matches more than one row."""
    if body.get("confirm_shared_serial") is True:
        return None
    for serial in {c.serial_number for c in certs if c.serial_number}:
        try:
            if int(serial, 16) > LEGACY_SERIAL_MAX:
                continue
        except ValueError:
            continue
        sharing = db.session.query(Certificate).filter(Certificate.serial_number == serial).all()
        if len(sharing) > 1:
            holders = sorted({c.username or c.common_name or "?" for c in sharing})
            return (
                jsonify(
                    {
                        "success": False,
                        "shared_serial": serial,
                        "certificates": [c.revocation_json() for c in sharing],
                        "error": gettext(
                            "Serial %(serial)s is an old, short serial number shared by %(count)s "
                            "certificates (%(holders)s). Revoking it revokes all of them. Send "
                            "confirm_shared_serial to revoke them all anyway.",
                            serial=serial,
                            count=len(sharing),
                            holders=", ".join(holders),
                        ),
                    }
                ),
                409,
            )
    return None


def _local_to_utc(value):
    """Certificate.expiration_date is a naive local time (datetime.today() + days)."""
    if value is None:
        return None
    return value.astimezone(datetime.timezone.utc)


def _serial_from_disk(cert: Certificate):
    """Recovers the serial of a cert issued before serials were recorded, from the PEM that
    issuing it left in certs/<CN>/<CN>.pem. That file is overwritten by every later cert for the
    same CN, so it's only trusted for the newest row with that CN, and only if its CN and expiry
    match the row."""
    common_name = cert.common_name
    if not common_name:
        return None
    try:
        # It goes into a file path
        CertificateAuthority.validate_common_name(common_name)
        newer = (
            db.session.query(Certificate.id)
            .filter(Certificate.common_name == common_name, Certificate.id > cert.id)
            .first()
        )
        if newer:
            return None
        path = os.path.join(app.config.get("RAVEN_CA_FOLDER"), "certs", common_name, common_name + ".pem")
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            parsed = cert_revocation.load_pem_certificate(f.read())
        if not parsed:
            return None
        cns = [a.value for a in parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        if [cn.lower() for cn in cns] != [common_name.lower()]:
            return None
        expiry = _local_to_utc(cert.expiration_date)
        if not expiry or abs(parsed.not_valid_after_utc - expiry) > datetime.timedelta(days=1):
            return None
        serial = cert_revocation.normalize_serial(parsed.serial_number)
        taken = (
            db.session.query(Certificate.id)
            .filter(Certificate.serial_number == serial, Certificate.id != cert.id)
            .first()
        )
        return None if taken else serial
    except BaseException as e:
        logger.debug(f"Couldn't recover the serial of certificate {cert.id}: {e}")
        return None


def _backfill_serials(certs):
    changed = False
    for cert in certs:
        if not cert.serial_number:
            serial = _serial_from_disk(cert)
            if serial:
                cert.serial_number = serial
                changed = True
    if changed:
        db.session.commit()


def _reset_password_flag(default):
    value = (request.get_json(silent=True) or {}).get("reset_password")
    return default if value is None else value is True


def _reason_and_note():
    body = request.get_json(silent=True) or {}
    reason = body.get("reason") or "unspecified"
    note = (body.get("note") or "").strip()[:NOTE_MAX_LENGTH] or None
    if reason not in cert_revocation.REVOCATION_REASONS:
        return None, None, (
            jsonify(
                {
                    "success": False,
                    "error": gettext("Invalid revocation reason: %(reason)s", reason=str(reason)),
                }
            ),
            400,
        )
    return reason, note, None


def _subject(common_name):
    return "{}/CN={}".format(app.config.get("RAVEN_CA_SUBJECT") or "", common_name or "unknown")


def _block_enrollment(certs, reason, actor):
    """Block the devices these revoked certs were issued to from enrolling again, for each cert
    that is its device's newest (an old cert the device has since replaced doesn't block it)."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    blocked = []
    for cert in certs:
        if not cert.eud_uid:
            continue
        newest = (
            db.session.query(Certificate.id)
            .filter(Certificate.eud_uid == cert.eud_uid)
            .order_by(Certificate.id.desc())
            .first()
        )
        if newest and newest[0] != cert.id:
            continue
        block = db.session.get(EnrollmentBlock, cert.eud_uid) or EnrollmentBlock(eud_uid=cert.eud_uid)
        block.username = cert.username or cert.common_name
        block.serial_number = cert.serial_number
        block.reason = reason
        block.blocked_at = now
        block.blocked_by = actor
        db.session.add(block)
        blocked.append(cert.eud_uid)
    if blocked:
        db.session.commit()
    return blocked


def reset_user_password(username, actor, why):
    """Set a random password nobody knows on this account and make the user choose a new one,
    so credentials saved on a lost device stop working. The account stays active; an admin hands
    the user a temporary password (Users page) when they need to sign in again.

    :returns: True if it was reset, False if it couldn't be (LDAP, or no such local user)
    """
    if app.config.get("RAVEN_ENABLE_LDAP"):
        record_audit_event(
            "security", "password_reset_skipped", username=username, actor=actor, success=False,
            details=f"{why}: password not reset, LDAP is enabled (reset it on the LDAP server)",
        )
        return False
    user = app.security.datastore.find_user(username=username) if username else None
    if not user:
        return False
    admin_change_password(user, secrets.token_urlsafe(32), False)
    # admin_change_password's password_changed signal clears force_password_change (it's meant
    # for a user setting their own); this one is a lock-out, so set it again afterwards
    user.force_password_change = True
    db.session.add(user)
    db.session.commit()
    record_audit_event(
        "security", "password_reset", username=user.username, actor=actor,
        details=f"{why}: password replaced with a random one, user must set a new password",
    )
    logger.warning(f"Reset {user.username}'s password ({why}) by {actor}")
    return True


def revoke_certificates(certs, reason, actor, note=None):
    """Revoke these Certificate rows: CRL, database, live sessions, audit.

    Rows whose serial is unknown (issued before serials were recorded and no longer on disk)
    can't be revoked and are returned in "skipped". Already revoked rows are left alone.

    :returns: dict with "revoked" and "skipped" (lists of Certificate), "kick" (the result of
        cert_revocation.kick_revoked_sessions) and "blocked" (device uids now blocked from
        enrolling again)
    """
    certs = [c for c in certs if not c.revoked_at]
    _backfill_serials(certs)
    revocable = [c for c in certs if c.serial_number]
    skipped = [c for c in certs if not c.serial_number]
    if not revocable:
        return {"revoked": [], "skipped": skipped, "kick": {"sent": True, "connected": []}, "blocked": []}

    cert_revocation.revoke(
        app.config.get("RAVEN_CA_FOLDER"),
        app.config.get("RAVEN_CA_PASSWORD"),
        [
            {
                "serial": c.serial_number,
                "not_after": _local_to_utc(c.expiration_date)
                or datetime.datetime.now(datetime.timezone.utc),
                "subject": _subject(c.common_name),
                "reason": reason,
            }
            for c in revocable
        ],
    )

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    serials = {c.serial_number for c in revocable}
    revoked_euds = {c.eud_uid for c in revocable}
    # Any other (legacy, colliding) row with the same serial is revoked by the same CRL entry
    for cert in (
        db.session.query(Certificate)
        .filter(Certificate.serial_number.in_(serials), Certificate.revoked_at.is_(None))
        .all()
    ):
        cert.revoked_at = now
        cert.revocation_reason = reason
        revoked_euds.add(cert.eud_uid)
    db.session.commit()
    # Chat queued for the device must not go to whoever connects with its uid next
    offline_chat.drop_queue(db.session, revoked_euds)

    blocked = _block_enrollment(revocable, reason, actor)
    kick = cert_revocation.kick_revoked_sessions(app, serials, logger)

    for cert in revocable:
        details = "Certificate {} (serial {}{}) revoked: {}".format(
            cert.id,
            cert.serial_number,
            ", device {}".format(cert.eud_uid) if cert.eud_uid else "",
            reason,
        )
        if note:
            details += ". " + note
        record_audit_event(
            "certificate", "cert_revoked", username=cert.username or cert.common_name,
            actor=actor, details=details,
        )
        logger.warning(details + " by " + str(actor))

    return {"revoked": revocable, "skipped": skipped, "kick": kick, "blocked": blocked}


def revoke_user_certificates(username, reason, actor, note=None):
    """Revoke every certificate issued to this user. The account itself stays active."""
    certs = (
        db.session.query(Certificate)
        .filter(db.func.lower(Certificate.username) == username.lower())
        .all()
    )
    # Certs from before Certificate.username was always set: same CN
    certs += (
        db.session.query(Certificate)
        .filter(
            Certificate.username.is_(None),
            db.func.lower(Certificate.common_name) == username.lower(),
        )
        .all()
    )
    return revoke_certificates(certs, reason, actor, note)


def _result_json(result, password_reset=None):
    return {
        "success": True,
        "revoked": [c.revocation_json() for c in result["revoked"]],
        "skipped": [c.revocation_json() for c in result["skipped"]],
        # False: RabbitMQ couldn't be reached, live sessions weren't told to disconnect
        "kick_sent": result["kick"]["sent"],
        # Serials a live streaming connection was using, which were told to disconnect
        "sessions_disconnected": result["kick"]["connected"],
        "enrollment_blocked": result["blocked"],
        "password_reset": password_reset,
    }


def _failure(e, what):
    db.session.rollback()
    logger.error(f"Failed to {what}: {e}")
    logger.debug(traceback.format_exc())
    return (
        jsonify({"success": False, "error": gettext("Failed to revoke the certificate: %(error)s", error=str(e))}),
        500,
    )


@certificate_api_blueprint.route("/api/certificates", methods=["GET"])
@roles_accepted("administrator")
def list_certificates():
    query = db.session.query(Certificate)
    username = (request.args.get("username") or "").strip()
    if username:
        query = query.filter(
            db.or_(
                db.func.lower(Certificate.username) == username.lower(),
                db.and_(
                    Certificate.username.is_(None),
                    db.func.lower(Certificate.common_name) == username.lower(),
                ),
            )
        )
    certs = query.order_by(Certificate.id.desc()).all()
    _backfill_serials(certs)
    next_update = cert_revocation.crl_next_update(app.config.get("RAVEN_CA_FOLDER"))
    uids = {c.eud_uid for c in certs if c.eud_uid}
    blocked = (
        {b.eud_uid for b in db.session.query(EnrollmentBlock).filter(EnrollmentBlock.eud_uid.in_(uids))}
        if uids
        else set()
    )
    results = []
    for cert in certs:
        row = cert.revocation_json()
        row["enrollment_blocked"] = bool(cert.eud_uid and cert.eud_uid in blocked)
        results.append(row)
    return jsonify(
        {
            "success": True,
            "results": results,
            "reasons": list(cert_revocation.REVOCATION_REASONS),
            "crl_next_update": next_update.isoformat() if next_update else None,
        }
    )


@certificate_api_blueprint.route("/api/certificates/<int:cert_id>/revoke", methods=["POST"])
@roles_accepted("administrator")
def revoke_certificate(cert_id):
    reason, note, error = _reason_and_note()
    if error:
        return error
    cert = db.session.get(Certificate, cert_id)
    if not cert:
        return jsonify({"success": False, "error": gettext("No such certificate")}), 404
    protected = _protected_cert_response(cert)
    if protected:
        return protected
    if cert.revoked_at:
        return jsonify({"success": False, "error": gettext("This certificate is already revoked")}), 400
    _backfill_serials([cert])
    shared = _shared_serial_response([cert], request.get_json(silent=True) or {})
    if shared:
        return shared

    try:
        result = revoke_certificates([cert], reason, current_user.username, note)
    except BaseException as e:
        return _failure(e, f"revoke certificate {cert_id}")

    if result["skipped"]:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "This certificate was issued before serial numbers were recorded and its "
                        "file has since been replaced, so it can't be revoked individually. Have "
                        "the user enroll again, then revoke by serial number if you have it."
                    ),
                }
            ),
            409,
        )
    password_reset = None
    if _reset_password_flag(False):
        password_reset = reset_user_password(
            cert.username or cert.common_name, current_user.username,
            f"Certificate {cert.serial_number} revoked",
        )
    return jsonify(_result_json(result, password_reset))


@certificate_api_blueprint.route("/api/certificates/revoke", methods=["POST"])
@roles_accepted("administrator")
def revoke_certificate_by_serial():
    """Revoke by serial number, including a cert Raven has no row for (an old one whose serial
    the admin read off the device)."""
    reason, note, error = _reason_and_note()
    if error:
        return error
    body = request.get_json(silent=True) or {}
    serial = cert_revocation.normalize_serial(body.get("serial"))
    if not serial:
        return jsonify({"success": False, "error": gettext("Invalid serial number")}), 400

    certs = db.session.query(Certificate).filter(Certificate.serial_number == serial).all()
    for cert in certs:
        protected = _protected_cert_response(cert)
        if protected:
            return protected
    ca_folder = app.config.get("RAVEN_CA_FOLDER")
    if cert_revocation.is_revoked(ca_folder, serial):
        return jsonify({"success": False, "error": gettext("This certificate is already revoked")}), 400
    shared = _shared_serial_response(certs, body)
    if shared:
        return shared

    try:
        if certs:
            result = revoke_certificates(certs, reason, current_user.username, note)
            password_reset = None
            if _reset_password_flag(False):
                password_reset = {}
                for name in sorted({c.username or c.common_name for c in result["revoked"]}):
                    password_reset[name] = reset_user_password(
                        name, current_user.username, f"Certificate {serial} revoked"
                    )
            return jsonify(_result_json(result, password_reset))

        # No row: the index entry needs an expiry, use the longest a cert from this CA can have
        not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=int(app.config.get("RAVEN_CA_EXPIRATION_TIME") or 3650)
        )
        cert_revocation.revoke(
            ca_folder,
            app.config.get("RAVEN_CA_PASSWORD"),
            [{"serial": serial, "not_after": not_after, "subject": _subject(None), "reason": reason}],
        )
        kick = cert_revocation.kick_revoked_sessions(app, [serial], logger)
        details = f"Certificate serial {serial} revoked: {reason}"
        if note:
            details += ". " + note
        record_audit_event(
            "certificate", "cert_revoked", actor=current_user.username, details=details
        )
        logger.warning(details + " by " + current_user.username)
        return jsonify(
            {
                "success": True,
                "revoked": [{"serial_number": serial, "status": "revoked"}],
                "skipped": [],
                "kick_sent": kick["sent"],
                "sessions_disconnected": kick["connected"],
                "enrollment_blocked": [],
                "password_reset": None,
            }
        )
    except BaseException as e:
        return _failure(e, f"revoke serial {serial}")


@certificate_api_blueprint.route("/api/certificates/revoke_user", methods=["POST"])
@roles_accepted("administrator")
def revoke_all_user_certificates():
    reason, note, error = _reason_and_note()
    if error:
        return error
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    user = app.security.datastore.find_user(username=username) if username else None
    if not user:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext("User %(username)s does not exist", username=username),
                }
            ),
            400,
        )
    protected = _protected_user_response(user.username)
    if protected:
        return protected

    try:
        result = revoke_user_certificates(user.username, reason, current_user.username, note)
        password_reset = None
        # On by default here: revoking everything usually means the credentials are suspect too
        if _reset_password_flag(True):
            password_reset = reset_user_password(
                user.username, current_user.username, "All certificates revoked"
            )
    except BaseException as e:
        return _failure(e, f"revoke {user.username}'s certificates")
    return jsonify(_result_json(result, password_reset))


@certificate_api_blueprint.route("/api/certificates/enrollment_blocks", methods=["GET"])
@roles_accepted("administrator")
def list_enrollment_blocks():
    query = db.session.query(EnrollmentBlock)
    username = (request.args.get("username") or "").strip()
    if username:
        query = query.filter(db.func.lower(EnrollmentBlock.username) == username.lower())
    blocks = query.order_by(EnrollmentBlock.blocked_at.desc()).all()
    return jsonify({"success": True, "results": [b.to_json() for b in blocks]})


@certificate_api_blueprint.route("/api/certificates/allow_enrollment", methods=["POST"])
@roles_accepted("administrator")
def allow_enrollment():
    """Lift the block on a device (EUD uid) enrolling again after its cert was revoked."""
    body = request.get_json(silent=True) or {}
    uid = (body.get("eud_uid") or "").strip()
    block = db.session.get(EnrollmentBlock, uid) if uid else None
    if not block:
        return (
            jsonify({"success": False, "error": gettext("That device isn't blocked from enrolling")}),
            404,
        )
    if block.username:
        protected = _protected_user_response(block.username)
        if protected:
            return protected
    username, serial = block.username, block.serial_number
    db.session.delete(block)
    db.session.commit()
    record_audit_event(
        "certificate", "enrollment_unblocked", username=username, actor=current_user.username,
        details=f"Device {uid} may enroll again (its certificate {serial or ''} was revoked)",
    )
    logger.warning(f"Device {uid} allowed to enroll again by {current_user.username}")
    return jsonify({"success": True})
