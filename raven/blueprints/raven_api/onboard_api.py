"""
VPN / bare-IP onboarding.

ATAK has no trust-on-first-use: a device can only enroll against a server whose certificate isn't
publicly trusted (e.g. reached by a bare VPN IP) if that server's CA is already in ATAK for that
connection ("preconfigured trust"). The only way to get the CA onto a fresh device is a data
package, so this flow is:

1. A user (or an admin, for any user) generates a QR with POST /api/vpn_qr_string:
   tak://com.atakmap.app/import?url=http://<IPv4>:8080/api/onboard/<onboarding link token>
2. ATAK downloads that URL over plain HTTP (it doesn't trust anything yet) and imports the data
   package returned by GET /api/onboard/<token>: one cot_streams connection to <IPv4>:8089:ssl
   with the Raven CA as that connection's truststore, enrollForCertificateWithTrust=true and
   enrollUseTrust=true.
3. ATAK's ImportCertResolver then enrolls against <IPv4>:8446 with isQuickConnect=false, i.e.
   validating the server against the bundled CA (no hostname check). ATAK has no stored
   credentials for the new connection, so it shows its username/password prompt once; the user
   enters their Raven username and password. After enrollment the device connects with its client
   certificate.

The link token is NOT an enrollment credential. It's a stateless JWT signed with the server key
with "scope": "onboard"; it only authorizes downloading the onboarding package (which holds the
CA certificate, nothing secret) until it expires. Token.verify_token (Basic auth for signClient,
the enrollment profile and streaming <auth>) rejects anything with a scope, and the user's
regular enrollment token (Token row / ATAK enroll QR) is not touched.
"""

import io
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import time
import traceback
import uuid
import zipfile
from urllib.parse import quote, urlparse
from xml.etree.ElementTree import Element, SubElement, tostring

import bleach
import jwt
from flask import Blueprint, Response
from flask import current_app as app
from flask import jsonify, request
from flask_login import current_user
from flask_security import auth_required
from sqlalchemy import func

from raven.extensions import db, logger
from raven.models.user import User

onboard_api_blueprint = Blueprint("onboard_api_blueprint", __name__)

ONBOARD_SCOPE = "onboard"

# Where ATAK's ImportCertResolver copies .p12 files from an imported data package
# (FileSystemUtils.getItem("cert")). Same directory the CONFIG.zip generator in
# certificate_authority.py uses.
ATAK_CERT_DIR = "/storage/emulated/0/atak/cert"

VPN_INTERFACE_PREFIXES = ("wt", "wg", "tun", "tap", "tailscale", "zt", "ppp", "ipsec", "nordlynx")
# Container / VM bridges: never an address a phone should be told to use
IGNORED_INTERFACE_PREFIXES = (
    "docker", "veth", "br-", "virbr", "lxc", "lxd", "cni", "flannel", "podman",
)
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify_address(interface: str, address: str) -> str | None:
    """Returns "vpn", "lan" or "public" for an IPv4 interface address, or None to leave it out."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None

    if ip.version != 4:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return None

    name = (interface or "").lower()
    if name.startswith(IGNORED_INTERFACE_PREFIXES):
        return None

    if name.startswith(VPN_INTERFACE_PREFIXES) or ip in CGNAT:
        return "vpn"

    if ip.is_private:
        return "lan"

    return "public"


def list_server_addresses() -> list[dict]:
    """Enumerates this host's usable IPv4 interface addresses, VPN first, then LAN, then public."""
    import psutil

    addresses = []
    seen = set()
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            kind = classify_address(interface, addr.address)
            if not kind or addr.address in seen:
                continue
            seen.add(addr.address)
            addresses.append({"address": addr.address, "interface": interface, "kind": kind})

    order = {"vpn": 0, "lan": 1, "public": 2}
    addresses.sort(
        key=lambda a: (order[a["kind"]], a["interface"], ipaddress.ip_address(a["address"]))
    )
    return addresses


def normalize_ipv4(host) -> str | None:
    """Returns host if it is a plain dotted-quad IPv4 literal (no port, scheme or path), else None."""
    if not isinstance(host, str):
        return None
    host = host.strip()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        return None
    return ip.compressed


def truststore_filename(host: str) -> str:
    """Per-server name for the truststore on the phone, so servers don't overwrite each other."""
    return "raven-{}-truststore.p12".format(re.sub(r"[^A-Za-z0-9]", "-", host))


def onboard_filename(host: str) -> str:
    return "Raven_{}.zip".format(re.sub(r"[^A-Za-z0-9._-]", "-", host))


def _server_key_path(name: str) -> str:
    return os.path.join(app.config.get("RAVEN_CA_FOLDER"), "certs", "raven", name)


def create_onboard_token(username: str, expiration: int) -> str:
    """Signs a stateless onboarding link token. It's not stored and not an enrollment credential."""
    now = int(time.time())
    claims = {
        "sub": username,
        "iat": now,
        "nbf": now,
        "exp": int(expiration),
        "iss": "Raven",
        "aud": "Raven",
        "scope": ONBOARD_SCOPE,
        "jti": uuid.uuid4().hex,
    }
    with open(_server_key_path("raven.nopass.key"), "rb") as key:
        return jwt.encode(claims, key.read(), algorithm="RS256")


def verify_onboard_token(token: str) -> User | None:
    """
    Returns the active user an onboarding link token was issued for, or None. Checks the
    signature, aud/iss, exp/nbf and scope == "onboard".
    """
    if not token or len(token) > 4096:
        return None
    try:
        with open(_server_key_path("raven.pub"), "r") as key:
            claims = jwt.decode(
                token,
                key.read(),
                algorithms=["RS256"],
                audience="Raven",
                issuer="Raven",
                options={"require": ["exp", "iat", "sub", "scope", "jti"]},
            )
    except jwt.exceptions.InvalidTokenError as e:
        logger.info(f"Rejected onboarding token: {e}")
        return None

    if claims.get("scope") != ONBOARD_SCOPE or not isinstance(claims.get("sub"), str):
        return None

    user = app.security.datastore.find_user(username=claims["sub"])
    if not user or not user.active:
        return None
    return user


def export_onboard_truststore(ca_folder: str, password: str, ca_name: str) -> bytes:
    """
    Exports a PKCS12 truststore holding only the CA certificate, under its own (non-secret)
    password, with the same legacy encryption create_ca() uses for truststore-root.p12 (which ATAK
    needs). Never ships RAVEN_CA_PASSWORD, which also protects the CA's private key.
    """
    ca_cert = os.path.join(ca_folder, "ca-trusted.pem")
    if not os.path.exists(ca_cert):
        ca_cert = os.path.join(ca_folder, "ca.pem")

    use_legacy = (
        subprocess.call(
            ["openssl", "list", "-providers"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        == 0
    )

    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "truststore.p12")
        command = ["openssl", "pkcs12"]
        if use_legacy:
            command.append("-legacy")
        command += [
            "-export",
            "-nokeys",
            "-in", ca_cert,
            "-out", out,
            "-caname", ca_name or "Raven-CA",
            "-passout", f"pass:{password}",
        ]
        result = subprocess.run(command, capture_output=True)
        if result.returncode:
            raise RuntimeError(
                "openssl pkcs12 export failed ({}): {}".format(
                    result.returncode, result.stderr.decode(errors="replace").strip()
                )
            )
        with open(out, "rb") as f:
            return f.read()


def build_onboard_package(host: str, ssl_port: int, truststore: bytes, truststore_password: str) -> bytes:
    """
    Builds the ATAK connection data package for onboarding by IP.

    cot_streams keys are the per-connection keys PreferenceControl.loadSettings reads (index 0):
    description0, connectString0, enabled0, caLocation0, caPassword0,
    enrollForCertificateWithTrust0, enrollUseTrust0.

    Deliberately absent:
    * username0/password0: ATAK never reads credentials from a .pref.
    * cacheCreds0: CotService._saveInputOutput would then save the (always empty) bundle
      username/password as this host's COT_SERVICE credentials, wiping any cached ones. Without
      it ATAK prompts once at enrollment and uses the typed credentials for that enrollment.
    * useAuth0: the device identifies itself on 8089 with its client cert. With useAuth and no
      cached credentials ATAK would send an <auth> with empty/stale credentials, which Raven
      rejects.
    """
    connect_string = f"{host}:{ssl_port}:ssl"
    folder = uuid.uuid4().hex
    p12_name = truststore_filename(host)
    pref_name = f"{folder}/raven-onboard.pref"
    truststore_entry = f"{folder}/{p12_name}"

    preferences = Element("preferences")
    streams = SubElement(preferences, "preference", {"version": "1", "name": "cot_streams"})

    def entry(key, java_class, value):
        e = SubElement(streams, "entry", {"key": key, "class": f"class java.lang.{java_class}"})
        e.text = value

    entry("count", "Integer", "1")
    entry("description0", "String", f"Raven ({host})")
    entry("enabled0", "Boolean", "true")
    entry("connectString0", "String", connect_string)
    entry("caLocation0", "String", f"{ATAK_CERT_DIR}/{p12_name}")
    entry("caPassword0", "String", truststore_password)
    entry("enrollForCertificateWithTrust0", "Boolean", "true")
    entry("enrollUseTrust0", "Boolean", "true")

    manifest = Element("MissionPackageManifest", {"version": "2"})
    configuration = SubElement(manifest, "Configuration")
    SubElement(configuration, "Parameter", {"name": "uid", "value": str(uuid.uuid4())})
    SubElement(configuration, "Parameter", {"name": "name", "value": f"Raven_{host}"})
    SubElement(configuration, "Parameter", {"name": "onReceiveImport", "value": "true"})
    SubElement(configuration, "Parameter", {"name": "onReceiveDelete", "value": "true"})
    contents = SubElement(manifest, "Contents")
    SubElement(contents, "Content", {"ignore": "false", "zipEntry": pref_name})
    SubElement(contents, "Content", {"ignore": "false", "zipEntry": truststore_entry})

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr(
            "MANIFEST/manifest.xml",
            b"<?xml version='1.0' encoding='UTF-8'?>\n" + tostring(manifest),
        )
        zipf.writestr(
            pref_name,
            b"<?xml version='1.0' standalone='yes'?>\n" + tostring(preferences),
        )
        zipf.writestr(truststore_entry, truststore)

    return buffer.getvalue()


@onboard_api_blueprint.route("/api/server_addresses", methods=["GET"])
@auth_required()
def get_server_addresses():
    """
    Lists this server's IPv4 interface addresses for VPN/IP onboarding.

    :return: {"addresses": [{"address", "interface", "kind": "vpn"|"lan"|"public"}], "domain"}
    """
    try:
        addresses = list_server_addresses()
    except BaseException as e:
        logger.error(f"Failed to list server addresses: {e}")
        logger.debug(traceback.format_exc())
        addresses = []

    return jsonify({"addresses": addresses, "domain": app.config.get("RAVEN_DOMAIN") or None})


@onboard_api_blueprint.route("/api/vpn_qr_string", methods=["POST"])
@auth_required()
def new_vpn_qr_string():
    """
    Generates a QR string that onboards ATAK to this server by IPv4 address (e.g. over a VPN).

    The link token is a stateless, onboarding-only JWT; it doesn't create, rotate or otherwise
    touch the user's enrollment token.

    :param host: IPv4 address the phone will reach the server at (required)
    :param expiration: Link expiration in unix epoch seconds (or ms). Optional, defaults to now +
        RAVEN_VPN_QR_DEFAULT_EXPIRATION_HOURS (24)
    :param username: Admins may generate a QR for another user (case-insensitive)

    :return: {"success": true, "qr_string", "url", "host", "username", "expiration"}
    """
    try:
        data = request.get_json(silent=True) or {}

        host = normalize_ipv4(data.get("host"))
        if not host:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "host must be an IPv4 address (hostnames and IPv6 aren't "
                        "supported for VPN onboarding; use Quick Connect for a domain)",
                    }
                ),
                400,
            )

        requested = data.get("username")
        if not requested or str(requested).lower() == current_user.username.lower():
            username = current_user.username
        elif not current_user.has_role("administrator"):
            return jsonify({"success": False, "error": "Cannot generate QR for another user"}), 403
        else:
            user = (
                db.session.query(User)
                .filter(func.lower(User.username) == str(requested).lower())
                .first()
            )
            if not user:
                return (
                    jsonify(
                        {"success": False, "error": f"No such user: {bleach.clean(str(requested))}"}
                    ),
                    404,
                )
            username = user.username

        now = int(time.time())
        try:
            expiration = data.get("expiration", data.get("exp"))
            expiration = int(expiration) if expiration not in (None, "") else None
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid expiration"}), 400
        # Accept milliseconds like atak_qr_string does
        if expiration and expiration > 2147483647:
            expiration = expiration // 1000
        if expiration is None:
            hours = app.config.get("RAVEN_VPN_QR_DEFAULT_EXPIRATION_HOURS") or 24
            expiration = now + int(float(hours) * 3600)
        if expiration <= now:
            return jsonify({"success": False, "error": "Expiration is in the past"}), 400

        token = create_onboard_token(username, expiration)
        port = app.config.get("RAVEN_MARTI_HTTP_PORT") or 8080
        url = f"http://{host}:{port}/api/onboard/{token}"

        return jsonify(
            {
                "success": True,
                "qr_string": "tak://com.atakmap.app/import?url=" + quote(url, safe=""),
                "url": url,
                "host": host,
                "username": username,
                "expiration": expiration,
            }
        )

    except BaseException as e:
        logger.error(f"Failed to create VPN QR string: {e}")
        logger.debug(traceback.format_exc())
        return jsonify({"success": False, "error": "Failed to create VPN QR string"}), 500


@onboard_api_blueprint.route("/api/onboard/<token>", methods=["GET"])
def onboard_package(token):
    """
    Unauthenticated (ATAK fetches it over plain HTTP before it trusts the server). Requires a
    valid, unexpired onboarding link token (scope "onboard") for an active user. Any failure is a
    bare 404.
    """
    not_found = ("", 404, {"Cache-Control": "no-store"})

    try:
        user = verify_onboard_token(token)
        if not user:
            return not_found

        # The address the phone actually reached us at
        host = normalize_ipv4(urlparse(request.url_root).hostname or "")
        if not host:
            return not_found

        password = app.config.get("RAVEN_ONBOARD_TRUSTSTORE_PASSWORD") or "atakatak"
        truststore = export_onboard_truststore(
            app.config.get("RAVEN_CA_FOLDER"), password, app.config.get("RAVEN_CA_NAME")
        )

        package = build_onboard_package(
            host, app.config.get("RAVEN_SSL_STREAMING_PORT"), truststore, password
        )

        logger.info(f"Serving onboarding package for {user.username} via {host}")
        return Response(
            package,
            mimetype="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{onboard_filename(host)}"',
                "Cache-Control": "no-store",
            },
        )

    except BaseException as e:
        logger.error(f"Failed to build onboarding package: {e}")
        logger.debug(traceback.format_exc())
        return not_found
