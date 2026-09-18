"""Signed remote "clear content" commands for the C4 Raven ATAK plugin.

An administrator can remotely clear a device's local ATAK content (the ATAK
"Clear Content"/zeroize action) from the web UI. ATAK has no built-in remote
trigger for this, so it is driven by our own ATAK plugin
(c4raven-clear-plugin) that acts ONLY on a command that

  * arrives over the authenticated server stream (the plugin checks the
    inbound CoT's ``serverFrom`` marker), and
  * carries a valid RSA-2048/SHA-256 signature from THIS server's key, and
  * targets that device's own uid, and
  * is fresh and non-replayed.

The private signing key never leaves the server; devices hold only the public
key, so a compromised device cannot forge a wipe command for any other device.
This module owns the key material and the signed-CoT construction. It also
offers a thin ``publish_clear_cot`` helper that puts a freshly-signed command on
the ``dms`` exchange, shared by the admin endpoint (immediate send) and by
EudHandler (delivery of commands queued while a device was offline).

Wire contract (must match the plugin's ClearCommandVerifier exactly):
  CoT type      "t-x-raven-clr"
  detail        <__ravenclear target=.. nonce=.. issued=.. clearmaps=.. sig=..>
  issued        epoch milliseconds, as a string
  clearmaps     "true" | "false"
  sig           base64(RSASSA-PKCS1-v1_5 / SHA-256 over the canonical string)
  canonical     target + "|" + nonce + "|" + issued + "|" + clearmaps  (UTF-8)
  public key    provisioned to devices as base64(DER SubjectPublicKeyInfo)
"""

import base64
import json
import os
import time
import uuid
from xml.etree.ElementTree import Element, SubElement, tostring

import pika

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import current_app as app

from raven.functions import iso8601_string_from_datetime

# The exact CoT type and detail schema the plugin listens for.
CLEAR_COT_TYPE = "t-x-raven-clr"
CLEAR_DETAIL = "__ravenclear"

# Default-SharedPreferences key the plugin reads the server public key from;
# provisioned via the connection device profile (see device_profile_marti_api).
SERVER_PUBKEY_PREF_KEY = "ravenclear.server_pubkey"

_PRIVATE_KEY_NAME = "ravenclear_signing.key"
_PUBLIC_KEY_NAME = "ravenclear_signing.pub"


def _key_dir() -> str:
    # Keep the signing key beside the CA material (already a locked-down,
    # backed-up secret store). RAVEN_CA_FOLDER defaults to <data>/ca.
    return app.config.get("RAVEN_CA_FOLDER")


def _canonical(target_uid: str, nonce: str, issued_ms: int, clearmaps: bool) -> bytes:
    return "{}|{}|{}|{}".format(
        target_uid, nonce, issued_ms, "true" if clearmaps else "false"
    ).encode("utf-8")


def get_signing_key() -> rsa.RSAPrivateKey:
    """Load the RSA signing key, generating it on first use.

    Generation is lazy (never at import) so merely importing this module has no
    side effect on the live key store.
    """
    key_dir = _key_dir()
    priv_path = os.path.join(key_dir, _PRIVATE_KEY_NAME)

    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    os.makedirs(key_dir, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # 0600 before writing any bytes: the private key must never be group/world
    # readable even briefly.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv_pem)

    with open(os.path.join(key_dir, _PUBLIC_KEY_NAME), "wb") as f:
        f.write(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return key


def public_key_der_b64() -> str:
    """Single-line base64 of the SPKI DER -- exactly what the device pref stores."""
    der = get_signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def public_key_pem() -> str:
    """PEM SPKI, for a human or a manual plugin install."""
    return (
        get_signing_key()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def sign_clear_command(target_uid: str, nonce: str, issued_ms: int, clearmaps: bool) -> str:
    """Sign the canonical command string; returns base64 (matches Java SHA256withRSA)."""
    sig = get_signing_key().sign(
        _canonical(target_uid, nonce, issued_ms, clearmaps),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


def build_clear_cot(target_uid: str, clearmaps: bool = False, node_id: str | None = None) -> str:
    """Build a fully signed t-x-raven-clr CoT addressed to one device uid."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    nonce = uuid.uuid4().hex
    issued_ms = int(time.time() * 1000)

    event = Element(
        "event",
        {
            "version": "2.0",
            "uid": str(uuid.uuid4()),
            "type": CLEAR_COT_TYPE,
            "how": "h-g-i-g-o",
            "time": iso8601_string_from_datetime(now),
            "start": iso8601_string_from_datetime(now),
            # Short stale: a wipe command that wasn't delivered promptly should
            # not linger. The plugin also enforces its own freshness window.
            "stale": iso8601_string_from_datetime(now + timedelta(minutes=10)),
        },
    )
    SubElement(
        event, "point", {"ce": "9999999", "le": "9999999", "hae": "0", "lat": "0", "lon": "0"}
    )
    detail = SubElement(event, "detail")
    SubElement(
        detail,
        CLEAR_DETAIL,
        {
            "target": target_uid,
            "nonce": nonce,
            "issued": str(issued_ms),
            "clearmaps": "true" if clearmaps else "false",
            "sig": sign_clear_command(target_uid, nonce, issued_ms, clearmaps),
        },
    )
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + tostring(
        event, encoding="unicode"
    )


# Ten minutes, matching the CoT's own stale window: an immediate send that is
# not consumed promptly must not linger in the queue and land on a device that
# reconnects much later. Reconnect delivery passes expiration=None instead,
# since the device is already connected and consuming when it is published.
DEFAULT_CLEAR_EXPIRATION_MS = "600000"


def publish_clear_cot(channel, target_uid, node_id, clearmaps=False, expiration=DEFAULT_CLEAR_EXPIRATION_MS):
    """Build a freshly-signed clear command for ``target_uid`` and publish it to
    the ``dms`` exchange so the device's direct-message queue receives it.

    ``channel`` is any open pika channel (the endpoint's BlockingConnection
    channel, or EudHandler's SelectConnection channel). The message uid is the
    server ``node_id``, never the device uid: EudHandler.on_message drops any
    message whose uid equals the receiving device's own uid (echo suppression).
    Pass ``expiration=None`` to publish without a per-message TTL.
    """
    cot = build_clear_cot(target_uid, clearmaps=clearmaps, node_id=node_id)
    properties = pika.BasicProperties(expiration=expiration) if expiration else pika.BasicProperties()
    channel.basic_publish(
        exchange="dms",
        routing_key=target_uid,
        body=json.dumps({"uid": node_id, "cot": cot}),
        properties=properties,
    )


if __name__ == "__main__":
    # Offline correctness proof: generate a key, build a command, re-parse it,
    # and verify the signature the way the device will. Point the key store at a
    # scratch dir via RAVEN_CA_FOLDER before running.
    import xml.etree.ElementTree as ET

    from flask import Flask

    scratch = os.environ.get("RAVEN_CA_FOLDER", "/tmp/rc-test")
    os.makedirs(scratch, exist_ok=True)
    _app = Flask(__name__)
    _app.config["RAVEN_CA_FOLDER"] = scratch
    with _app.app_context():
        uid = "ANDROID-deadbeef"
        xml = build_clear_cot(uid, clearmaps=True)
        root = ET.fromstring(xml.split("?>", 1)[1])
        d = root.find("./detail/" + CLEAR_DETAIL)
        target = d.get("target")
        nonce = d.get("nonce")
        issued = int(d.get("issued"))
        clearmaps = d.get("clearmaps") == "true"
        sig = base64.b64decode(d.get("sig"))

        pub = get_signing_key().public_key()
        try:
            pub.verify(
                sig,
                _canonical(target, nonce, issued, clearmaps),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            print("OK: signature verifies")
        except InvalidSignature:
            print("FAIL: signature does not verify")
            raise
        # Tamper check: flipping the target must break the signature.
        try:
            pub.verify(
                sig,
                _canonical("someone-else", nonce, issued, clearmaps),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            print("FAIL: tampered target still verified")
            raise SystemExit(1)
        except InvalidSignature:
            print("OK: tampered command rejected")
        print("pubkey der(b64) len:", len(public_key_der_b64()))
