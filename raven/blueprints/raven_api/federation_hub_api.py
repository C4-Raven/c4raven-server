import os
import subprocess
import time
import traceback
from urllib.parse import quote, urlparse

import bleach
import requests
from flask import Blueprint
from flask import current_app as app
from flask import jsonify, make_response, request, session
from flask_babel import gettext
from flask_security import current_user, roles_required

from raven import fedhub_partners as fp
from raven.audit import record_admin_action
from raven.extensions import logger

# How long a 2FA check stays valid before the admin has to re-verify to
# download the Federation Hub admin cert again.
_FEDHUB_CERT_2FA_WINDOW_SECONDS = 300

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
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": gettext("Federation Hub timed out")}), 504

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
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": gettext("Federation Hub timed out")}), 504

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
#
# Where the .p12 and its import password live comes from config
# (RAVEN_FEDHUB_ADMIN_P12 / RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE): new
# installs copy both somewhere the raven user can read, while legacy boxes
# keep the defaults pointing at Federation Hub's own files.
_LEGACY_PASSWORD_FILE_NAME = ".fedhub-cert-passwords"


def _read_admin_cert_password(path):
    """Return the admin .p12 import password from ``path``, or None.

    Two formats are accepted:
      * the legacy Federation Hub ``.fedhub-cert-passwords`` shell-env file
        (``CAPASS=...`` / ``PASS=...`` lines) -- the ``PASS=`` value is used;
      * a file holding only the password on a single line (stripped).
    """
    with open(path) as f:
        content = f.read()

    lines = [line.strip() for line in content.splitlines() if line.strip()]
    legacy = os.path.basename(path) == _LEGACY_PASSWORD_FILE_NAME or (
        len(lines) > 1 and any(line.startswith("PASS=") for line in lines)
    )
    if legacy:
        for line in lines:
            if line.startswith("PASS="):
                return line.split("=", 1)[1] or None
        return None

    return lines[0] if len(lines) == 1 else None


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


def _audited(body, status=200, headers=None):
    """GETs that hand out the admin cert or its password aren't caught by the central admin
    action hook (it only logs state-changing methods), so they record their own row."""
    response = make_response(body, status, headers or {})
    record_admin_action(response)
    return response


@federation_hub_api.route("/api/fedhub/admin_cert")
@roles_required("administrator")
def get_admin_cert():
    if not _fedhub_cert_2fa_verified():
        return _audited(
            jsonify({"success": False, "error": gettext("2FA verification required")}), 403
        )

    try:
        with open(app.config.get("RAVEN_FEDHUB_ADMIN_P12"), "rb") as f:
            data = f.read()
    except OSError as e:
        logger.error(f"Failed to read Federation Hub admin cert: {e}")
        return _audited(
            jsonify({"success": False, "error": gettext("Admin certificate not found")}), 500
        )

    return _audited(
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
        return _audited(
            jsonify({"success": False, "error": gettext("2FA verification required")}), 403
        )

    try:
        password = _read_admin_cert_password(app.config.get("RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"))
        if password:
            return _audited(jsonify({"password": password}))
    except (OSError, TypeError, UnicodeDecodeError) as e:
        logger.error(f"Failed to read Federation Hub cert password file: {e}")

    return _audited(
        jsonify({"success": False, "error": gettext("Certificate password not found")}), 500
    )


@federation_hub_api.route("/api/fedhub/ca_self")
@roles_required("administrator")
def get_self_ca():
    # Hand this to a partner so they can add it as a trusted CA on their end
    # -- the other half of establishing federation trust in both directions.
    try:
        r = _fedhub_request("GET", "/getSelfCaFile")
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": gettext("Federation Hub is not running")}), 503
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": gettext("Federation Hub timed out")}), 504

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
    """Saves a whole policy; with ?activate=1 also makes it the active one (the advanced
    editor's "Save & apply" -- a save alone isn't enforced by the broker)."""
    if not fp.parse_bool(request.args.get("activate"), False):
        return _proxy("POST", "/saveFederationPolicy", json=request.json)

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body.get("name"):
        return _partner_error(
            fp.PartnerError("invalid_policy", gettext("The policy needs a name"))
        )
    client = _client()
    try:
        with fp.policy_lock():
            client.save_policy(fp.prepare_for_save(body))
            client.activate(body["name"])
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify({"success": True, "activated": True, "name": body["name"]})


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


# --- Partners: the guided Federation Hub page (raven/fedhub_partners.py) ----------------
#
# Every mutating partner route reads the active policy, changes it, saves AND activates it,
# re-reads it to confirm, and undoes its own changes if any step fails. A module-level lock
# (fp.policy_lock) keeps two admins from interleaving those read-modify-write cycles.

_BROKER_CONFIG_CACHE = {"at": 0.0, "value": None}
_BROKER_CONFIG_TTL_SECONDS = 60


def _client():
    # Looks _fedhub_request up at call time so tests can swap in a fake hub
    return fp.HubClient(lambda method, path, **kwargs: _fedhub_request(method, path, **kwargs))


def _partner_error(e):
    return jsonify(e.to_json()), e.status


def _api_host():
    return urlparse(app.config.get("RAVEN_FEDHUB_API_ADDRESS") or "").hostname


def _is_loopback(host):
    if not host or host == "localhost":
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _broker_host():
    """The name partners dial: it must be the name in the broker's server cert (G8), which is
    what Raven's own bridge dials too."""
    configured = (app.config.get("RAVEN_FEDHUB_HOST") or "").strip()
    if configured:
        return configured
    broker = (app.config.get("RAVEN_FEDHUB_BROKER_ADDRESS") or "").strip()
    if broker:
        host = urlparse(f"//{broker}").hostname
        if host and not _is_loopback(host):
            return host
    return _api_host()


def _native_url():
    host = _api_host()
    if _is_loopback(host):
        host = (app.config.get("RAVEN_FEDHUB_HOST") or "").strip() or _broker_host() or host
    return f"https://{host}:9100" if host else None


def _bridge_service_state():
    """systemctl is-active fedhub_bridge, unprivileged and read-only; "unknown" if that fails."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "fedhub_bridge"], capture_output=True, text=True, timeout=2
        )
        return (result.stdout or "").strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _broker_config(client):
    """getBrokerConfig, cached briefly (the overview is polled). Only non-secret fields are
    kept."""
    now = time.time()
    if _BROKER_CONFIG_CACHE["value"] is None or now - _BROKER_CONFIG_CACHE["at"] > _BROKER_CONFIG_TTL_SECONDS:
        config = client.broker_config()
        _BROKER_CONFIG_CACHE["value"] = {"id": config.get("id"), "v2Port": config.get("v2Port")}
        _BROKER_CONFIG_CACHE["at"] = now
    return _BROKER_CONFIG_CACHE["value"]


def _v2_port(client):
    try:
        return int(_broker_config(client).get("v2Port") or fp.DEFAULT_V2_PORT)
    except (fp.PartnerError, TypeError, ValueError):
        return fp.DEFAULT_V2_PORT


def _optional(fn, default):
    try:
        return fn()
    except fp.PartnerError:
        return default


def _bridge_uid():
    return app.config.get("RAVEN_FEDHUB_FEDERATE_UID") or "raven-federate"


def _require_own(known):
    own = fp.own_ca(known)
    if not own:
        raise fp.PartnerError(
            "own_ca_unknown",
            gettext("Federation Hub doesn't report its own CA. Check the hub's installation"),
            502,
        )
    return own


def _require_policy(client):
    policy = client.active_policy()
    if not policy:
        raise fp.PartnerError(
            "no_active_policy", gettext("Federation Hub has no active federation policy"), 404
        )
    return policy


def _partner_view(client, policy, known, partner_id):
    own = _require_own(known)
    connections = _optional(client.connections, [])
    metrics = _optional(client.metrics, {})
    partners, _, _ = fp.build_partners(policy, own["uid"], known, connections, metrics, _bridge_uid())
    for partner in partners:
        if partner["id"] == partner_id:
            return partner, connections
    raise fp.PartnerError(
        "not_found", gettext("That server isn't in the active federation policy"), 404
    )


def _entry_owning_node(policy, own_uid, node):
    for entry in fp.partner_entries(policy, own_uid):
        if node in (entry["ca_node"], entry["outgoing"]):
            return entry
    return None


def _check_outgoing_free(policy, own_uid, host, port, except_node=None):
    existing = fp.outgoing_to(policy, host, port)
    if existing is not None and existing is not except_node:
        entry = _entry_owning_node(policy, own_uid, existing)
        raise fp.PartnerError(
            "outgoing_exists",
            gettext("This hub already connects to %(host)s:%(port)s", host=host, port=port),
            409,
            existing_partner_id=entry["id"] if entry else None,
        )


def _check_not_dialing_us(client, ca_uid):
    """G6: if the partner already connects to us we must not dial it as well."""
    if not ca_uid:
        return
    for conn in _optional(client.connections, []):
        if ca_uid in (conn.get("groupIdentities") or []):
            raise fp.PartnerError(
                "they_already_dial",
                gettext(
                    "That server is already connected to us, so we mustn't connect to it as well. "
                    "Choose \"They connect to us\""
                ),
                409,
            )


@federation_hub_api.route("/api/fedhub/overview")
@roles_required("administrator")
def get_overview():
    client = _client()
    hub = {
        "reachable": False,
        "active_policy": None,
        "broker_id": None,
        "v2_port": fp.DEFAULT_V2_PORT,
        "host": _broker_host(),
    }
    own_out = {"uid": None, "sha256": None, "subject": None, "nickname": None, "connected": False}
    bridge = {
        "enabled": bool(app.config.get("RAVEN_FEDHUB_FEDERATE_ENABLE")),
        "service_state": _bridge_service_state(),
    }
    body = {
        "hub": hub,
        "own": own_out,
        "bridge": bridge,
        "partners": [],
        "unattributed_connections": [],
        "problems": [],
    }
    try:
        known = client.known_cas()
        hub["reachable"] = True
        policy = client.active_policy()
    except fp.HubUnavailable as e:
        body["problems"].append("hub_unreachable")
        body["error"] = e.message
        return jsonify(body)
    except fp.PartnerError as e:
        body["problems"].append("hub_error")
        body["error"] = e.message
        return jsonify(body)

    connections = _optional(client.connections, [])
    metrics = _optional(client.metrics, {})
    config = _optional(lambda: _broker_config(client), {}) or {}
    hub["broker_id"] = config.get("id")
    try:
        hub["v2_port"] = int(config.get("v2Port") or fp.DEFAULT_V2_PORT)
    except (TypeError, ValueError):
        pass
    hub["active_policy"] = policy.get("name") if policy else None

    own = fp.own_ca(known)
    own_uid = own["uid"] if own else None
    if own:
        own_out.update(
            uid=own_uid,
            sha256=(own.get("alias") or "").lower() or None,
            subject=own.get("subject"),
            nickname=own.get("nickname"),
        )
    else:
        body["problems"].append("own_ca_unknown")
    if not policy:
        body["problems"].append("no_active_policy")
    if own and (not policy or not fp.own_node(policy, own_uid)):
        body["problems"].append("own_ca_missing")

    partners, bridge_conns, rest = fp.build_partners(
        policy or {}, own_uid, known, connections, metrics, _bridge_uid()
    )
    own_out["connected"] = bool(bridge_conns)
    if bridge["enabled"] and not bridge_conns:
        body["problems"].append("bridge_not_connected")
    body["partners"] = partners
    body["unattributed_connections"] = rest
    return jsonify(body)


def _read_upload(field):
    storage = request.files.get(field)
    if storage is None:
        return None
    return storage.read(fp.MAX_CA_BYTES + 1)


@federation_hub_api.route("/api/fedhub/partners", methods=["POST"])
@roles_required("administrator")
def create_partner():
    client = _client()
    try:
        form = request.form
        name = fp.validate_name(form.get("name"))
        kind = fp.validate_kind(form.get("kind"))
        direction = fp.validate_direction(form.get("direction"))
        host = port = None
        if direction == "we_dial":
            host = fp.validate_host(form.get("host"))
            port = fp.validate_port(form.get("port") or fp.DEFAULT_V2_PORT)
        interconnected = fp.parse_bool(form.get("interconnected"), False)
        share = fp.validate_filter(form.get("share"), gettext("what to share"))
        receive = fp.validate_filter(form.get("receive"), gettext("what to receive"))
        data = _read_upload("ca_file")
        ca_info = fp.parse_ca_file(data) if data is not None else None
        ca_uid_param = (form.get("ca_uid") or "").strip() or None
        if ca_info is None and not ca_uid_param:
            raise fp.PartnerError(
                "invalid_ca", gettext("Choose the other server's CA certificate file")
            )

        with fp.policy_lock():
            known = client.known_cas()
            own = _require_own(known)
            previous = client.active_policy()
            policy = previous or fp.empty_policy()

            if ca_info is not None:
                existing = fp.find_ca(known, sha256=ca_info["sha256"])
            else:
                existing = fp.find_ca(known, uid=ca_uid_param)
                if existing is None:
                    raise fp.PartnerError(
                        "ca_not_found", gettext("That CA isn't trusted by the hub yet"), 404
                    )
            if existing is not None and existing.get("uid") == own["uid"]:
                raise fp.PartnerError(
                    "own_ca",
                    gettext("That is this hub's own CA. Upload the other server's CA instead"),
                    409,
                )
            if existing is not None:
                entry = fp.find_entry(policy, own["uid"], existing["uid"])
                if entry is not None:
                    raise fp.PartnerError(
                        "ca_exists",
                        gettext("A server with this CA is already connected"),
                        409,
                        existing_partner_id=entry["id"],
                    )
            if direction == "we_dial":
                _check_outgoing_free(policy, own["uid"], host, port)
                _check_not_dialing_us(client, existing["uid"] if existing else None)

            ca_added = False
            renamed_from = None
            if existing is None:
                client.add_ca(ca_info["pem"], name)
                ca_added = True
                known = client.known_cas()
                existing = fp.find_ca(known, sha256=ca_info["sha256"])
                if existing is None:
                    raise fp.PartnerError(
                        "ca_not_added",
                        gettext("Federation Hub didn't keep the CA certificate. Nothing was changed"),
                        502,
                    )
            elif existing.get("nickname") != name:
                try:
                    client.rename_ca(existing, name)
                    renamed_from = existing
                    existing = dict(existing, nickname=name)
                    known = [existing if ca.get("uid") == existing["uid"] else ca for ca in known]
                except fp.PartnerError as e:
                    logger.warning(f"Federation Hub: couldn't rename CA: {e.message}")

            try:
                new_policy, partner_id = fp.add_partner(
                    policy,
                    own,
                    name=name,
                    kind=kind,
                    direction=direction,
                    ca_uid=existing["uid"],
                    host=host,
                    port=port,
                    interconnected=interconnected,
                    share=share,
                    receive=receive,
                    expires=ca_info["not_after"] if ca_info else None,
                )
                active = fp.apply_policy(client, new_policy, previous, logger)
            except fp.PartnerError as e:
                if ca_added:
                    try:
                        client.delete_ca(existing["uid"])
                    except fp.PartnerError as rollback:
                        logger.error(f"Federation Hub: couldn't remove the CA again: {rollback.message}")
                        e.extra["rollback_failed"] = True
                if renamed_from is not None:
                    try:
                        client.rename_ca(renamed_from, renamed_from.get("nickname"))
                    except fp.PartnerError as rollback:
                        logger.error(f"Federation Hub: couldn't restore CA nickname: {rollback.message}")
                raise

            partner, _ = _partner_view(client, active, known, partner_id)
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify(partner), 201


def _patch_changes(data):
    changes = {}
    if "name" in data:
        changes["name"] = fp.validate_name(data["name"])
    if "kind" in data:
        changes["kind"] = fp.validate_kind(data["kind"])
    if "direction" in data:
        changes["direction"] = fp.validate_direction(data["direction"])
    if "enabled" in data:
        changes["enabled"] = fp.parse_bool(data["enabled"])
    if "interconnected" in data:
        changes["interconnected"] = fp.parse_bool(data["interconnected"])
    if "host" in data:
        changes["host"] = fp.validate_host(data["host"])
    if "port" in data:
        changes["port"] = fp.validate_port(data["port"])
    if "share" in data:
        changes["share"] = fp.validate_filter(data["share"], gettext("what to share"))
    if "receive" in data:
        changes["receive"] = fp.validate_filter(data["receive"], gettext("what to receive"))
    return changes


@federation_hub_api.route("/api/fedhub/partners/<path:partner_id>", methods=["PATCH"])
@roles_required("administrator")
def update_partner(partner_id):
    client = _client()
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise fp.PartnerError("invalid_request", gettext("Send the changes as a JSON object"))
        changes = _patch_changes(data)
        if not changes:
            raise fp.PartnerError("nothing_to_change", gettext("Nothing to change"))

        with fp.policy_lock():
            known = client.known_cas()
            own = _require_own(known)
            previous = _require_policy(client)
            entry = fp.find_entry(previous, own["uid"], partner_id)
            if entry is None:
                raise fp.PartnerError(
                    "not_found", gettext("That server isn't in the active federation policy"), 404
                )

            dials = entry["outgoing"] is not None
            will_dial = changes.get("direction", "we_dial" if dials else "they_dial") == "we_dial"
            if will_dial and ("host" in changes or "port" in changes or not dials):
                config = (entry["outgoing"] or {}).get("config") or {}
                host = changes.get("host", config.get("host"))
                port = changes.get("port", config.get("port") or fp.DEFAULT_V2_PORT)
                if not host:
                    raise fp.PartnerError(
                        "invalid_host", gettext("Enter the other server's address and port")
                    )
                changes.setdefault("host", host)
                changes.setdefault("port", port)
                _check_outgoing_free(previous, own["uid"], host, port, except_node=entry["outgoing"])
            if will_dial and not dials:
                _check_not_dialing_us(client, entry["ca_uid"])

            renamed = None
            if "name" in changes and entry["ca_uid"]:
                ca = fp.find_ca(known, uid=entry["ca_uid"])
                if ca and ca.get("nickname") != changes["name"]:
                    client.rename_ca(ca, changes["name"])
                    renamed = ca
                    known = [dict(c, nickname=changes["name"]) if c is ca else c for c in known]
            try:
                new_policy, new_id = fp.update_partner(previous, own, partner_id, changes)
                active = fp.apply_policy(client, new_policy, previous, logger)
            except fp.PartnerError:
                if renamed is not None:
                    try:
                        client.rename_ca(renamed, renamed.get("nickname"))
                    except fp.PartnerError as rollback:
                        logger.error(f"Federation Hub: couldn't restore CA nickname: {rollback.message}")
                raise
            partner, _ = _partner_view(client, active, known, new_id)
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify(partner)


@federation_hub_api.route("/api/fedhub/partners/<path:partner_id>", methods=["DELETE"])
@roles_required("administrator")
def delete_partner(partner_id):
    client = _client()
    try:
        keep_ca = fp.parse_bool(request.args.get("keep_ca"), False)
        with fp.policy_lock():
            known = client.known_cas()
            own = _require_own(known)
            previous = _require_policy(client)
            new_policy, ca_uid = fp.remove_partner(previous, own["uid"], partner_id)
            # Policy first, CA second (G11): deleting a CA that's still in the active policy
            # leaves dangling nodes, and deleting it restarts the hub's v2 server anyway
            fp.apply_policy(client, new_policy, previous, logger)

            body = {"success": True, "id": partner_id, "ca_removed": False}
            if ca_uid and not keep_ca and fp.find_ca(known, uid=ca_uid) and ca_uid != own["uid"]:
                try:
                    stored = client.stored_policies()
                    users = [
                        p.get("name")
                        for p in stored
                        if isinstance(p, dict)
                        and p.get("name") != new_policy.get("name")
                        and fp.ca_referenced(p, ca_uid)
                    ]
                except fp.PartnerError:
                    users = None
                if users is None:
                    body["warning"] = gettext(
                        "The server was removed, but its CA was kept because the stored policies "
                        "couldn't be checked"
                    )
                elif users:
                    body["warning"] = gettext(
                        "The server was removed. Its CA was kept because the policy %(names)s "
                        "still uses it",
                        names=", ".join(str(u) for u in users),
                    )
                else:
                    try:
                        client.delete_ca(ca_uid)
                        body["ca_removed"] = True
                    except fp.PartnerError as e:
                        body["warning"] = gettext(
                            "The server was removed, but its CA couldn't be: %(error)s",
                            error=e.message,
                        )
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify(body)


@federation_hub_api.route("/api/fedhub/partners/<path:partner_id>/check")
@roles_required("administrator")
def check_partner(partner_id):
    client = _client()
    try:
        known = client.known_cas()
        own = _require_own(known)
        policy = _require_policy(client)
        partner, connections = _partner_view(client, policy, known, partner_id)
        entry = fp.find_entry(policy, own["uid"], partner_id)
        checks = fp.build_checks(
            entry,
            partner,
            policy,
            own["uid"],
            known,
            connections,
            resolver=fp.resolve,
            connector=fp.tcp_connect,
        )
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify(checks)


@federation_hub_api.route("/api/fedhub/partners/<path:partner_id>/reconnect", methods=["POST"])
@roles_required("administrator")
def reconnect_partner(partner_id):
    client = _client()
    try:
        known = client.known_cas()
        policy = _require_policy(client)
        partner, _ = _partner_view(client, policy, known, partner_id)
        for conn in partner["connections"]:
            client.disconnect(conn.get("connectionId"))
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify({"success": True, "disconnected": len(partner["connections"])})


def _handoff_steps(host, port, own_name, fingerprint):
    where = f"{host}:{port}"
    return {
        "raven_hub": [
            gettext("Open Federation Hub in your C4 Raven and click \"Connect a server\"."),
            gettext("Choose \"Raven with its own hub\"."),
            gettext("Download your hub's CA and send it to us; upload our CA (attached) when asked."),
            gettext("Check that our CA's fingerprint is %(fp)s.", fp=fingerprint),
            gettext(
                "Under \"Who connects\", choose \"We connect to them\" and enter %(where)s, "
                "unless we agreed that we connect to you. Only one side may connect.",
                where=where,
            ),
            gettext("Leave \"What to share\" on \"Everything\" and click Connect."),
        ],
        "tak_server": [
            gettext(
                "In TAK Server go to Configuration > Manage Federates > Edit Configuration, "
                "enable federation (v2) and restart TAK Server if it asks."
            ),
            gettext(
                "Under Manage Federate Certificate Authorities, upload our CA (attached). Its "
                "fingerprint is %(fp)s.",
                fp=fingerprint,
            ),
            gettext(
                "Send us /opt/tak/certs/files/ca.pem: the CA that issued your server certificate."
            ),
            gettext(
                "Add an Outgoing Connection: address %(host)s, port %(port)s, protocol version 2, "
                "enabled. Skip this if we agreed that we connect to you (then we dial your "
                "federation port, 9001 by default).",
                host=host,
                port=port,
            ),
            gettext(
                "Under Active Connections, open Manage Groups for the %(name)s federate and choose "
                "the inbound and outbound groups (for example __ANON__ or your federation group). "
                "Nothing is shared until you do.",
                name=own_name,
            ),
        ],
        "other": [
            gettext("Trust our CA (attached) in your federation trust store. Fingerprint: %(fp)s.", fp=fingerprint),
            gettext("Send us the CA that issued the certificate your server presents."),
            gettext(
                "Connect to %(where)s using federation protocol v2 over mutual TLS, unless we "
                "agreed that we connect to you. Only one side may connect.",
                where=where,
            ),
        ],
    }


@federation_hub_api.route("/api/fedhub/handoff")
@roles_required("administrator")
def get_handoff():
    client = _client()
    try:
        pem = client.self_ca()
        info = fp.parse_ca_file(pem)
        own = fp.own_ca(_optional(client.known_cas, [])) or {}
        port = _v2_port(client)
    except fp.PartnerError as e:
        return _partner_error(e)

    host = _broker_host()
    nickname = own.get("nickname") or gettext("this hub")
    fpr = fp.fingerprint(info["sha256"])
    steps = _handoff_steps(host, port, nickname, fpr)
    kind = request.args.get("kind")
    if kind in fp.KINDS:
        steps = {kind: steps[kind]}
    body = {
        "ca_pem": info["pem"].decode(),
        "sha256": info["sha256"],
        "fingerprint": fpr,
        "subject": info["subject"],
        "nickname": own.get("nickname"),
        "not_after": info["not_after"],
        "host": host,
        "port": port,
        "steps": steps,
    }
    if request.args.get("format") != "txt":
        return jsonify(body)

    titles = {
        "raven_hub": gettext("If you run C4 Raven with its own Federation Hub"),
        "tak_server": gettext("If you run TAK Server"),
        "other": gettext("Any other federation server"),
    }
    lines = [
        gettext("Federating with %(name)s", name=nickname),
        "",
        gettext("Our federation address: %(host)s, port %(port)s (v2)", host=host, port=port),
        gettext("Our CA: %(subject)s", subject=info["subject"]),
        gettext("SHA-256 fingerprint: %(fp)s", fp=fpr),
        "",
    ]
    for key, items in steps.items():
        lines.append(titles[key])
        lines.extend(f"  {i}. {text}" for i, text in enumerate(items, 1))
        lines.append("")
    lines.append(gettext("Our CA certificate (save as federation-hub-ca.pem):"))
    lines.append(body["ca_pem"].strip())
    return (
        "\n".join(lines) + "\n",
        200,
        {
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Disposition": "attachment; filename=federation-instructions.txt",
        },
    )


@federation_hub_api.route("/api/fedhub/repair", methods=["POST"])
@roles_required("administrator")
def repair_policy():
    client = _client()
    try:
        with fp.policy_lock():
            known = client.known_cas()
            own = _require_own(known)
            previous = client.active_policy()
            new_policy, added = fp.ensure_own_node(previous or fp.empty_policy(), own)
            if not added:
                return jsonify({"success": True, "changed": False})
            fp.apply_policy(client, new_policy, previous, logger)
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify({"success": True, "changed": True, "policy": new_policy.get("name")})


@federation_hub_api.route("/api/fedhub/ca_inspect", methods=["GET", "POST"])
@roles_required("administrator")
def inspect_ca():
    client = _client()
    try:
        data = _read_upload("file")
        if data is None:
            raise fp.PartnerError(
                "invalid_ca", gettext("Choose the other server's CA certificate file")
            )
        info = fp.parse_ca_file(data)
        known = client.known_cas()
        existing = fp.find_ca(known, sha256=info["sha256"])
        own = fp.own_ca(known)
        partner_id = None
        if existing is not None and own:
            policy = client.active_policy()
            entry = fp.find_entry(policy, own["uid"], existing["uid"]) if policy else None
            partner_id = entry["id"] if entry else None
    except fp.PartnerError as e:
        return _partner_error(e)
    left = fp.days_left(info["not_after"])
    return jsonify(
        {
            "subject": info["subject"],
            "issuer": info["issuer"],
            "sha256": info["sha256"],
            "fingerprint": fp.fingerprint(info["sha256"]),
            "uid": existing["uid"] if existing else info["uid"],
            "not_after": info["not_after"],
            "days_left": int(left) if left is not None else None,
            "is_ca": info["is_ca"],
            "already_trusted": existing is not None,
            "nickname": existing.get("nickname") if existing else None,
            "is_own": bool(existing and own and existing.get("uid") == own.get("uid")),
            "existing_partner_id": partner_id,
        }
    )


@federation_hub_api.route("/api/fedhub/known_groups/<path:node_id>")
@roles_required("administrator")
def get_known_groups(node_id):
    """Groups the hub has seen advertised through a graph node. ``node_id`` is a policy node
    id, or a partner id: then the union over its CA node and its outgoing node."""
    client = _client()
    try:
        node_ids = [node_id]
        policy = client.active_policy()
        if policy and node_id not in fp.entity_ids(policy):
            own = fp.own_ca(client.known_cas())
            entry = fp.find_entry(policy, own["uid"] if own else None, node_id)
            if entry is None:
                raise fp.PartnerError(
                    "not_found", gettext("That server isn't in the active federation policy"), 404
                )
            node_ids = [n["id"] for n in (entry["ca_node"], entry["outgoing"]) if n]
        groups = []
        for nid in node_ids:
            found = client.json(
                "GET",
                f"/getKnownGroupsForGraphNode/{quote(nid, safe='')}",
                gettext("list known groups"),
            )
            for group in found or []:
                if group not in groups:
                    groups.append(group)
    except fp.PartnerError as e:
        return _partner_error(e)
    return jsonify(groups)


@federation_hub_api.route("/api/fedhub/federations/<name>/export")
@roles_required("administrator")
def export_federation(name):
    client = _client()
    fmt = request.args.get("format", "json")
    safe_name = quote(name, safe="")
    try:
        if fmt == "yaml":
            content = client.call("GET", f"/graphAsYaml/{safe_name}", gettext("export the policy")).content
            content_type, ext = "text/yaml; charset=utf-8", "yaml"
        elif fmt == "json":
            policy = client.json("GET", f"/federation/{safe_name}", gettext("read the policy"))
            if not policy:
                raise fp.PartnerError("not_found", gettext("No policy with that name"), 404)
            content = client.call("POST", "/policyToJson", gettext("export the policy"), json=policy).content
            content_type, ext = "application/json", "json"
        else:
            raise fp.PartnerError("invalid_format", gettext("Choose JSON or YAML"))
    except fp.PartnerError as e:
        return _partner_error(e)
    filename = "".join(c if c.isalnum() or c in "-_." else "_" for c in name) or "policy"
    return (
        content,
        200,
        {"Content-Type": content_type, "Content-Disposition": f"attachment; filename={filename}.{ext}"},
    )


@federation_hub_api.route("/api/fedhub/tokens", methods=["POST"])
@roles_required("administrator")
def generate_token():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not str(body.get("clientGroup") or "").strip():
        return _partner_error(
            fp.PartnerError("invalid_request", gettext("Choose the token group to issue a token for"))
        )
    body = dict(body)
    try:
        body["expiration"] = int(body.get("expiration", -1))
    except (TypeError, ValueError):
        return _partner_error(
            fp.PartnerError("invalid_expiration", gettext("The expiry must be a time in milliseconds, or -1"))
        )
    body.setdefault(
        "clientFingerprint", f"{int(time.time() * 1000)}_{body['clientGroup']}_token_fingerprint"
    )
    return _proxy("POST", "/generateJwtToken", json=body)


@federation_hub_api.route("/api/fedhub/reachability", methods=["POST"])
@roles_required("administrator")
def check_reachability():
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise fp.PartnerError("invalid_request", gettext("Send the host and port as JSON"))
        host = fp.validate_host(data.get("host"))
        port = fp.validate_port(data.get("port") or fp.DEFAULT_V2_PORT)
    except fp.PartnerError as e:
        return _partner_error(e)
    result = fp.reachability(host, port, resolver=fp.resolve, connector=fp.tcp_connect)
    return jsonify(dict(result, host=host, port=port))


@federation_hub_api.route("/api/fedhub/native_url")
@roles_required("administrator")
def get_native_url():
    return jsonify({"url": _native_url()})
