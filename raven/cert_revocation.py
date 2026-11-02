"""
Client certificate revocation.

Raven signs client certs with ``openssl x509 -req`` (see CertificateAuthority.sign_csr), not
``openssl ca``, so they never get an entry in the CA's crl_index.txt, and the PEM on disk is
overwritten every time the same CN is issued again (every cert for a user has CN=<username>).
``openssl ca -revoke <file>`` can't be used for an old cert whose file is gone, so revoke() writes
the revoked ("R") line into crl_index.txt itself, in the format openssl uses, and then runs
``openssl ca -gencrl`` to regenerate ca.crl from it.

crl_index.txt is the source of truth for enforcement, not the certificates table: purge_data and
re-enrollment can delete or rewrite Certificate rows, but a revoked serial must stay revoked.
Three places enforce it:

* the SSL streaming port (raven/eud_handler/EudServerSSL.py) verifies every handshake against
  ca.crl and rebuilds its SSL context when the file changes;
* nginx on 8443 (ssl_crl in nginx_configs/raven_https of the setup repo), once reloaded;
* check_forwarded_cert() below, for every request nginx proxies with an X-Ssl-Cert header, which
  covers the gap until nginx has reloaded (or on an install whose nginx has no ssl_crl yet).

ca.crl must always exist and never expire: nginx refuses to start when ssl_crl names a missing
file and rejects every client cert once the CRL's nextUpdate has passed, and the streaming port
does the same with VERIFY_CRL_CHECK_LEAF. ensure_crl() (at start-up and from the daily
refresh_crl job) regenerates it when it is missing or within CRL_REFRESH_DAYS of expiring.
"""

import datetime
import json
import os
import subprocess
from contextlib import contextmanager
from urllib.parse import unquote

try:
    import fcntl
except ImportError:  # Windows: no cross-process lock, single worker there anyway
    fcntl = None

from cryptography import x509

from raven.ca_config import ca_config

# How long each generated CRL is valid for (nextUpdate). Same as default_crl_days in ca_config.
CRL_DAYS = 730
# ensure_crl() regenerates the CRL when it has fewer days than this left.
CRL_REFRESH_DAYS = 30

# The RFC 5280 reasons an admin can pick, by their openssl names (openssl ca -crl_reason).
# removeFromCRL and certificateHold are left out: a revocation here is permanent.
REVOCATION_REASONS = (
    "unspecified",
    "keyCompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
)

# Routing key prefix on the eud_control exchange that reaches the streaming connection using a
# given cert serial (see EudHandler.parse_device_info / on_control_message).
CERT_ROUTING_PREFIX = "cert."

_revoked_cache = {"key": None, "serials": frozenset()}


def normalize_serial(value) -> str | None:
    """A cert serial as uppercase hex without leading zeros, the form used everywhere here.

    Accepts an int or a hex string (with or without 0x, colons or leading zeros, any case) as
    ssl.getpeercert(), openssl and the API might give it. Returns None for anything else."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    else:
        text = str(value).strip().replace(":", "").lower()
        if text.startswith("0x"):
            text = text[2:]
        if not text:
            return None
        try:
            number = int(text, 16)
        except ValueError:
            return None
    if number < 0:
        return None
    return format(number, "X")


def load_pem_certificate(pem) -> x509.Certificate | None:
    if isinstance(pem, str):
        pem = pem.encode()
    try:
        return x509.load_pem_x509_certificate(pem)
    except (ValueError, TypeError):
        return None


def serial_from_pem(pem) -> str | None:
    cert = load_pem_certificate(pem)
    return normalize_serial(cert.serial_number) if cert else None


def _paths(ca_folder):
    return {
        "index": os.path.join(ca_folder, "crl_index.txt"),
        "attr": os.path.join(ca_folder, "crl_index.txt.attr"),
        "config": os.path.join(ca_folder, "ca_config.cfg"),
        "key": os.path.join(ca_folder, "ca-do-not-share.key"),
        "cert": os.path.join(ca_folder, "ca.pem"),
        "crl": os.path.join(ca_folder, "ca.crl"),
        "lock": os.path.join(ca_folder, "crl.lock"),
    }


@contextmanager
def _ca_lock(ca_folder):
    """Serialises crl_index.txt / ca.crl writers across gunicorn workers and processes."""
    with open(_paths(ca_folder)["lock"], "a") as lock_file:
        if fcntl:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl:
                fcntl.flock(lock_file, fcntl.LOCK_UN)


def _ensure_index_files(ca_folder):
    paths = _paths(ca_folder)
    if not os.path.exists(paths["index"]):
        open(paths["index"], "a").close()
    if not os.path.exists(paths["attr"]):
        with open(paths["attr"], "w") as f:
            f.write("unique_subject = no")
    if not os.path.exists(paths["config"]):
        with open(paths["config"], "w") as f:
            f.write(ca_config)


def _index_time(value: datetime.datetime) -> str:
    """openssl index date: UTCTime (YYMMDDHHMMSSZ) up to 2049, GeneralizedTime after."""
    if value.tzinfo is not None:
        value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    if value.year >= 2050:
        return value.strftime("%Y%m%d%H%M%SZ")
    return value.strftime("%y%m%d%H%M%SZ")


def _index_serial(serial: str) -> str:
    # openssl writes serials as even-length uppercase hex
    return serial if len(serial) % 2 == 0 else "0" + serial


def _read_index(ca_folder):
    path = _paths(ca_folder)["index"]
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def revoked_serials(ca_folder) -> frozenset:
    """Every serial marked revoked in crl_index.txt, normalized. Cached until the file changes."""
    path = _paths(ca_folder)["index"]
    try:
        stat = os.stat(path)
    except OSError:
        return frozenset()
    key = (path, stat.st_mtime_ns, stat.st_size)
    if _revoked_cache["key"] == key:
        return _revoked_cache["serials"]
    serials = set()
    for line in _read_index(ca_folder):
        fields = line.split("\t")
        if len(fields) >= 4 and fields[0] == "R":
            serial = normalize_serial(fields[3])
            if serial:
                serials.add(serial)
    serials = frozenset(serials)
    _revoked_cache["key"] = key
    _revoked_cache["serials"] = serials
    return serials


def is_revoked(ca_folder, serial) -> bool:
    serial = normalize_serial(serial)
    return bool(serial) and serial in revoked_serials(ca_folder)


def _run_gencrl(ca_folder, password):
    """openssl ca -gencrl into a temp file, then an atomic rename over ca.crl, so nginx and the
    streaming port never read a half-written CRL. Caller holds _ca_lock."""
    paths = _paths(ca_folder)
    tmp = paths["crl"] + ".tmp"
    env = dict(os.environ, RAVEN_CA_PASSIN=str(password))
    result = subprocess.run(
        [
            "openssl", "ca", "-config", paths["config"], "-gencrl",
            "-keyfile", paths["key"], "-cert", paths["cert"],
            "-passin", "env:RAVEN_CA_PASSIN",
            "-crldays", str(CRL_DAYS), "-out", tmp,
        ],
        cwd=ca_folder,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise RuntimeError("openssl ca -gencrl failed: {}".format(result.stderr.strip()))
    os.chmod(tmp, 0o644)
    os.replace(tmp, paths["crl"])


def generate_crl(ca_folder, password):
    """Regenerate ca.crl from crl_index.txt."""
    with _ca_lock(ca_folder):
        _ensure_index_files(ca_folder)
        _run_gencrl(ca_folder, password)


def crl_next_update(ca_folder) -> datetime.datetime | None:
    try:
        with open(_paths(ca_folder)["crl"], "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
    except (OSError, ValueError):
        return None
    return crl.next_update_utc


def ensure_crl(ca_folder, password, logger=None) -> bool:
    """Make sure ca.crl exists, parses and has at least CRL_REFRESH_DAYS left before its
    nextUpdate. Regenerates it otherwise. Returns True if it was regenerated."""
    if not os.path.exists(_paths(ca_folder)["cert"]):
        return False
    next_update = crl_next_update(ca_folder)
    now = datetime.datetime.now(datetime.timezone.utc)
    if next_update and next_update - now > datetime.timedelta(days=CRL_REFRESH_DAYS):
        return False
    generate_crl(ca_folder, password)
    if logger:
        logger.info(
            "Regenerated the CA's CRL ({})".format(
                "it was missing" if next_update is None else "it expires " + next_update.isoformat()
            )
        )
    return True


def revoke(ca_folder, password, entries):
    """Mark certificates revoked in crl_index.txt and regenerate ca.crl.

    :param entries: iterable of dicts with ``serial`` (any form normalize_serial takes),
        ``not_after`` (datetime, the cert's expiry), ``subject`` (openssl "/K=V" form) and
        ``reason`` (one of REVOCATION_REASONS)
    :returns: the normalized serials that were newly revoked (already revoked ones are skipped)
    """
    now = _index_time(datetime.datetime.now(datetime.timezone.utc))
    revoked = []
    with _ca_lock(ca_folder):
        _ensure_index_files(ca_folder)
        lines = _read_index(ca_folder)
        by_serial = {}
        for i, line in enumerate(lines):
            fields = line.split("\t")
            if len(fields) >= 6:
                by_serial[normalize_serial(fields[3])] = i

        for entry in entries:
            serial = normalize_serial(entry["serial"])
            if not serial:
                raise ValueError("Invalid certificate serial: {!r}".format(entry["serial"]))
            reason = entry.get("reason") or "unspecified"
            if reason not in REVOCATION_REASONS:
                raise ValueError("Invalid revocation reason: {!r}".format(reason))
            # Tabs or newlines would break the index's line/field format
            subject = " ".join(str(entry.get("subject") or "/CN=unknown").split())
            existing = by_serial.get(serial)
            if existing is not None:
                fields = lines[existing].split("\t")
                if fields[0] == "R":
                    continue
                fields[0] = "R"
                fields[2] = "{},{}".format(now, reason)
                lines[existing] = "\t".join(fields)
            else:
                lines.append(
                    "\t".join(
                        (
                            "R",
                            _index_time(entry["not_after"]),
                            "{},{}".format(now, reason),
                            _index_serial(serial),
                            "unknown",
                            subject,
                        )
                    )
                )
                by_serial[serial] = len(lines) - 1
            revoked.append(serial)

        if revoked:
            index = _paths(ca_folder)["index"]
            tmp = index + ".tmp"
            with open(tmp, "w") as f:
                f.write("".join(line + "\n" for line in lines))
            os.replace(tmp, index)
        # Regenerated even when nothing was new, so a revoke also repairs a missing CRL
        _run_gencrl(ca_folder, password)
    return revoked


def forwarded_cert_serial(header_value) -> str | None:
    """The serial of the client cert nginx forwarded (URL-escaped PEM, $ssl_client_escaped_cert)."""
    if not header_value:
        return None
    return serial_from_pem(unquote(header_value))


def kick_revoked_sessions(app, serials, logger=None):
    """Ask the SSL streaming port to drop any live connection using one of these serials.

    The streaming handlers are separate processes; each one binds its eud_control queue to
    "cert.<serial>" (see EudHandler), so this reaches exactly the connection(s) on that cert.
    Best effort: a connection that is missed is still cut off at its next handshake by the CRL.
    Returns True if the messages were published."""
    serials = [s for s in (normalize_serial(s) for s in serials) if s]
    if not serials:
        return True
    import pika

    connection = None
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS"),
                credentials=pika.PlainCredentials(
                    app.config.get("RAVEN_RABBITMQ_USERNAME"),
                    app.config.get("RAVEN_RABBITMQ_PASSWORD"),
                ),
            )
        )
        channel = connection.channel()
        # Args must match raven.app / EudHandler exactly or the broker closes the channel (406)
        channel.exchange_declare("eud_control", durable=True, exchange_type="direct")
        for serial in serials:
            channel.basic_publish(
                exchange="eud_control",
                routing_key=CERT_ROUTING_PREFIX + serial,
                body=json.dumps({"action": "revoke", "serial": serial}),
                properties=pika.BasicProperties(expiration="60000"),
            )
        channel.close()
        return True
    except BaseException as e:
        if logger:
            logger.error("Failed to disconnect sessions for revoked cert(s) {}: {}".format(serials, e))
        return False
    finally:
        if connection is not None and connection.is_open:
            connection.close()
