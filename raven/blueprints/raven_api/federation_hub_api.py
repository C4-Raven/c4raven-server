import time
import traceback

import bleach
import requests
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, request, session
from flask_babel import gettext
from flask_security import current_user, roles_required

from raven.extensions import logger

# How long a 2FA check stays valid before the admin has to re-verify to
# download the Federation Hub admin cert again.
_FEDHUB_CERT_2FA_WINDOW_SECONDS = 60

federation_hub_api = Blueprint("federation_hub_api", __name__)

# Broker config fields that should never leave the server -- getBrokerConfig
# returns these in plaintext since Federation Hub has no separate secrets store.
_REDACTED_CONFIG_FIELDS = {"keystorePassword", "truststorePassword", "dbPassword"}


def _fedhub_request(method, path, **kwargs):
    """Proxy a request to the Federation Hub admin API, authenticating with
    Raven's dedicated fedhub-admin mTLS client cert. Federation Hub is treated
    as fully trusting whoever holds that cert -- there is no per-user identity
    on the far side, so every action here is gated by the administrator role
    on the way in.
    """
    base = app.config.get("RAVEN_FEDHUB_API_ADDRESS")
    return requests.request(
        method,
        f"{base}{path}",
        cert=(
            app.config.get("RAVEN_FEDHUB_CLIENT_CERT"),
            app.config.get("RAVEN_FEDHUB_CLIENT_KEY"),
        ),
        verify=app.config.get("RAVEN_FEDHUB_CA_BUNDLE"),
        timeout=15,
        **kwargs,
    )


def _proxy(method, path, **kwargs):
    """Shared error handling for the simple pass-through endpoints below."""
    try:
        r = _fedhub_request(method, path, **kwargs)
    except requests.exceptions.ConnectionError:
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": gettext("Federation Hub is not running")}), 503
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": gettext("Federation Hub timed out")}), 504

    if r.status_code >= 400:
        return (r.text, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})

    if not r.content:
        return "", r.status_code

    return (r.content, r.status_code, {"Content-Type": r.headers.get("Content-Type", "application/json")})


@federation_hub_api.route("/api/fedhub/connections")
@roles_required("administrator")
def get_connections():
    return _proxy("GET", "/getActiveConnections")


@federation_hub_api.route("/api/fedhub/connections/<connection_id>", methods=["DELETE"])
@roles_required("administrator")
def disconnect_connection(connection_id):
    return _proxy("DELETE", f"/disconnectFederate/{bleach.clean(connection_id)}")


@federation_hub_api.route("/api/fedhub/connections/groups", methods=["POST"])
@roles_required("administrator")
def update_connection_groups():
    return _proxy("POST", "/updateConnectionGroupSets", json=request.json)


@federation_hub_api.route("/api/fedhub/metrics")
@roles_required("administrator")
def get_metrics():
    try:
        broker = _fedhub_request("GET", "/getBrokerMetrics")
        glob = _fedhub_request("GET", "/getBrokerGlobalMetrics")
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": gettext("Federation Hub is not running")}), 503

    if broker.status_code >= 400 or glob.status_code >= 400:
        return jsonify({"success": False, "error": gettext("Failed to fetch broker metrics")}), 502

    return jsonify({"broker": broker.json(), "global": glob.json()})


@federation_hub_api.route("/api/fedhub/config")
@roles_required("administrator")
def get_broker_config():
    try:
        r = _fedhub_request("GET", "/getBrokerConfig")
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": gettext("Federation Hub is not running")}), 503

    if r.status_code >= 400:
        return (r.text, r.status_code)

    config = r.json()
    for field in _REDACTED_CONFIG_FIELDS:
        if field in config:
            config[field] = None

    return jsonify(config)


@federation_hub_api.route("/api/fedhub/broker/restart", methods=["POST"])
@roles_required("administrator")
def restart_broker():
    # Federation Hub itself exposes this as a GET (it's their route, not ours)
    return _proxy("GET", "/restartBroker")


@federation_hub_api.route("/api/fedhub/plugins")
@roles_required("administrator")
def get_plugins():
    return _proxy("GET", "/getRegisteredPlugins")


@federation_hub_api.route("/api/fedhub/ca_groups")
@roles_required("administrator")
def get_ca_groups():
    return _proxy("GET", "/getKnownCaGroups")


# The native Federation Hub admin console (port 9100) requires this exact
# client cert for mTLS login -- there's no cert-free path into it (its
# built-in Keycloak/OAuth support is broken in this Federation Hub release).
# Serving it here means an admin only needs to be logged into Raven once to
# get the file, rather than having it handed around out-of-band.
_FEDHUB_ADMIN_CERT_PATH = "/opt/tak/federation-hub/certs/files/fedhub-admin.p12"
_FEDHUB_CERT_PASSWORD_FILE = "/opt/tak/federation-hub/certs/.fedhub-cert-passwords"


def _fedhub_cert_2fa_verified():
    verified_at = session.get("fedhub_cert_2fa_verified_at")
    return verified_at is not None and (time.time() - verified_at) < _FEDHUB_CERT_2FA_WINDOW_SECONDS


@federation_hub_api.route("/api/fedhub/admin_cert/verify_2fa", methods=["POST"])
@roles_required("administrator")
def verify_admin_cert_2fa():
    if not current_user.tf_primary_method or not current_user.tf_totp_secret:
        return (
            jsonify(
                {
                    "success": False,
                    "error": gettext(
                        "Two-factor authentication isn't set up on your account -- set it up under your profile first"
                    ),
                }
            ),
            400,
        )

    code = bleach.clean(request.json.get("code", "")) if request.json else ""
    if not code:
        return jsonify({"success": False, "error": gettext("Enter your 2FA code")}), 400

    # window is in seconds (not steps) here -- 30s of tolerance each way
    # covers ordinary clock drift between the server and the user's phone.
    valid = app.security.totp_factory.verify_totp(
        code, current_user.tf_totp_secret, current_user, window=30
    )
    if not valid:
        return jsonify({"success": False, "error": gettext("Invalid code")}), 401

    session["fedhub_cert_2fa_verified_at"] = time.time()
    return jsonify({"success": True})


@federation_hub_api.route("/api/fedhub/admin_cert")
@roles_required("administrator")
def get_admin_cert():
    if not _fedhub_cert_2fa_verified():
        return jsonify({"success": False, "error": gettext("2FA verification required")}), 403

    try:
        with open(_FEDHUB_ADMIN_CERT_PATH, "rb") as f:
            data = f.read()
    except OSError as e:
        logger.error(f"Failed to read Federation Hub admin cert: {e}")
        return jsonify({"success": False, "error": gettext("Admin certificate not found")}), 500

    return (
        data,
        200,
        {
            "Content-Type": "application/x-pkcs12",
            "Content-Disposition": "attachment; filename=fedhub-admin.p12",
        },
    )


@federation_hub_api.route("/api/fedhub/admin_cert/password")
@roles_required("administrator")
def get_admin_cert_password():
    if not _fedhub_cert_2fa_verified():
        return jsonify({"success": False, "error": gettext("2FA verification required")}), 403

    try:
        with open(_FEDHUB_CERT_PASSWORD_FILE) as f:
            for line in f:
                if line.startswith("PASS="):
                    return jsonify({"password": line.strip().split("=", 1)[1]})
    except OSError as e:
        logger.error(f"Failed to read Federation Hub cert password file: {e}")

    return jsonify({"success": False, "error": gettext("Certificate password not found")}), 500


@federation_hub_api.route("/api/fedhub/ca_self")
@roles_required("administrator")
def get_self_ca():
    # Hand this to a partner so they can add it as a trusted CA on their end
    # -- the other half of establishing federation trust in both directions.
    try:
        r = _fedhub_request("GET", "/getSelfCaFile")
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": gettext("Federation Hub is not running")}), 503

    if r.status_code >= 400:
        return (r.text, r.status_code)

    return (
        r.content,
        200,
        {
            "Content-Type": "application/x-pem-file",
            "Content-Disposition": "attachment; filename=federation-hub-ca.pem",
        },
    )


@federation_hub_api.route("/api/fedhub/ca_groups", methods=["POST"])
@roles_required("administrator")
def add_ca_group():
    if "file" not in request.files:
        return jsonify({"success": False, "error": gettext("Please select a CA certificate file")}), 400

    file = request.files["file"]
    nickname = bleach.clean(request.form.get("nickname", ""))

    return _proxy(
        "POST",
        "/addNewGroupCa",
        files={"file": (file.filename, file.stream, file.mimetype)},
        data={"nickname": nickname},
    )


@federation_hub_api.route("/api/fedhub/ca_groups", methods=["PATCH"])
@roles_required("administrator")
def update_ca_group_nickname():
    return _proxy("POST", "/updateCaNickname", json=request.json)


@federation_hub_api.route("/api/fedhub/ca_groups/<uid>", methods=["DELETE"])
@roles_required("administrator")
def delete_ca_group(uid):
    return _proxy("DELETE", f"/deleteGroupCa/{bleach.clean(uid)}")


@federation_hub_api.route("/api/fedhub/federations")
@roles_required("administrator")
def get_federations():
    return _proxy("GET", "/federations")


@federation_hub_api.route("/api/fedhub/federations/<name>")
@roles_required("administrator")
def get_federation(name):
    return _proxy("GET", f"/federation/{bleach.clean(name)}")


@federation_hub_api.route("/api/fedhub/federations/<name>/graph")
@roles_required("administrator")
def get_federation_graph(name):
    return _proxy("GET", f"/graphAsJson/{bleach.clean(name)}")


@federation_hub_api.route("/api/fedhub/federations/<name>/activate", methods=["POST"])
@roles_required("administrator")
def activate_federation_policy(name):
    # Federation Hub itself exposes this as a GET (it's their route, not ours)
    return _proxy("GET", f"/activateFederationPolicy/{bleach.clean(name)}")


@federation_hub_api.route("/api/fedhub/federations/<name>/policy", methods=["DELETE"])
@roles_required("administrator")
def delete_federation_policy(name):
    return _proxy("DELETE", f"/deleteFederationPolicy/{bleach.clean(name)}")


@federation_hub_api.route("/api/fedhub/policy")
@roles_required("administrator")
def get_active_policy():
    return _proxy("GET", "/getActivePolicy")


@federation_hub_api.route("/api/fedhub/policy", methods=["POST"])
@roles_required("administrator")
def save_policy():
    return _proxy("POST", "/saveFederationPolicy", json=request.json)


@federation_hub_api.route("/api/fedhub/policy/core", methods=["POST"])
@roles_required("administrator")
def save_core_policy():
    return _proxy("POST", "/saveFederationCorePolicy", json=request.json)


@federation_hub_api.route("/api/fedhub/policy/view", methods=["POST"])
@roles_required("administrator")
def save_view_policy():
    return _proxy("POST", "/saveFederationViewPolicy", json=request.json)


@federation_hub_api.route("/api/fedhub/policy/plugins", methods=["POST"])
@roles_required("administrator")
def save_plugins_policy():
    return _proxy("POST", "/saveFederationPluginsPolicy", json=request.json)
