"""
Admin API for listing and revoking client certificates (see raven/cert_revocation.py).

Revoking a cert puts its serial in the CA's CRL, drops any live streaming connection using it and
records a "cert_revoked" audit event. The user's account is left active on purpose, so they can
enroll a replacement device straight away.

This blueprint also rejects requests nginx proxies with a revoked client cert in X-Ssl-Cert
(reject_revoked_client_cert), so a revocation takes effect on 8443 even before nginx has reloaded
its CRL.
"""

import datetime
import functools
import os
import traceback

from cryptography.x509.oid import NameOID
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request
from flask_babel import gettext
from flask_security import current_user, roles_accepted

from raven import cert_revocation, offline_chat
from raven.audit import record_audit_event
from raven.blueprints.raven_api.user_api import _protected_user_response
from raven.certificate_authority import CertificateAuthority
from raven.extensions import db, logger
from raven.models.Certificate import Certificate

certificate_api_blueprint = Blueprint("certificate_api_blueprint", __name__)

NOTE_MAX_LENGTH = 500


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


def revoke_certificates(certs, reason, actor, note=None):
    """Revoke these Certificate rows: CRL, database, live sessions, audit.

    Rows whose serial is unknown (issued before serials were recorded and no longer on disk)
    can't be revoked and are returned in "skipped". Already revoked rows are left alone.

    :returns: dict with "revoked" and "skipped" (lists of Certificate) and "disconnected"
        (False if the live-session kick couldn't be published)
    """
    certs = [c for c in certs if not c.revoked_at]
    _backfill_serials(certs)
    revocable = [c for c in certs if c.serial_number]
    skipped = [c for c in certs if not c.serial_number]
    if not revocable:
        return {"revoked": [], "skipped": skipped, "disconnected": True}

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

    disconnected = cert_revocation.kick_revoked_sessions(app, serials, logger)

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

    return {"revoked": revocable, "skipped": skipped, "disconnected": disconnected}


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


def _result_json(result):
    return {
        "success": True,
        "revoked": [c.revocation_json() for c in result["revoked"]],
        "skipped": [c.revocation_json() for c in result["skipped"]],
        "sessions_disconnected": result["disconnected"],
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
    return jsonify(
        {
            "success": True,
            "results": [c.revocation_json() for c in certs],
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
    if cert.username:
        protected = _protected_user_response(cert.username)
        if protected:
            return protected
    if cert.revoked_at:
        return jsonify({"success": False, "error": gettext("This certificate is already revoked")}), 400

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
    return jsonify(_result_json(result))


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
        if cert.username:
            protected = _protected_user_response(cert.username)
            if protected:
                return protected
    ca_folder = app.config.get("RAVEN_CA_FOLDER")
    if cert_revocation.is_revoked(ca_folder, serial):
        return jsonify({"success": False, "error": gettext("This certificate is already revoked")}), 400

    try:
        if certs:
            return jsonify(_result_json(revoke_certificates(certs, reason, current_user.username, note)))

        # No row: the index entry needs an expiry, use the longest a cert from this CA can have
        not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=int(app.config.get("RAVEN_CA_EXPIRATION_TIME") or 3650)
        )
        cert_revocation.revoke(
            ca_folder,
            app.config.get("RAVEN_CA_PASSWORD"),
            [{"serial": serial, "not_after": not_after, "subject": _subject(None), "reason": reason}],
        )
        disconnected = cert_revocation.kick_revoked_sessions(app, [serial], logger)
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
                "sessions_disconnected": disconnected,
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
    except BaseException as e:
        return _failure(e, f"revoke {user.username}'s certificates")
    return jsonify(_result_json(result))
