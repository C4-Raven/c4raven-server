"""
Federation Hub "partners": the model behind the guided Federation Hub page.

A partner is another server this Raven's Federation Hub federates with. On the hub
it is one or two nodes of the active policy graph:

  * a ``FederationGroup`` node whose ``name`` is the partner CA's uid
    (``"<subject DN>-<sha256 of the CA>"``, exactly ``getKnownCaGroups[].uid``), and/or
  * a ``FederationOutgoing`` node (``name`` ``"<displayName>_<uuid4>"``) when this hub
    dials the partner,

plus rules (directed edges) both ways between those nodes and the hub's own CA node
(the ``FederationGroup`` whose name is the uid of the CA with ``hubGroup: true``),
which is where Raven's own bridge connects.

Everything here except :class:`HubClient` and :func:`apply_policy` is a pure function
over plain dicts so it can be unit tested without a hub. Policies are deep-copied
before they're changed and every field this module doesn't know about (views,
groupSets, plugins, token groups, other nodes and rules...) is carried through as is.

The hub's entity ``config`` objects are fixed Java classes, so extra keys there would be
dropped (or rejected) on save. Raven's own bookkeeping for a node (partner kind, the CA
an outgoing node belongs to, the CA's expiry) lives in the entity's free-text
``description`` instead, as JSON: ``{"raven": {"kind": ..., "ca": ..., "expires": ...}}``.
"""

import copy
import datetime
import hashlib
import ipaddress
import json
import re
import socket
import threading
import uuid
from contextlib import contextmanager
from urllib.parse import quote

import requests
from flask_babel import gettext

GROUP = "FederationGroup"
OUTGOING = "FederationOutgoing"

FILTER_TYPES = ("allGroups", "allowed", "disallowed", "allowedAndDisallowed")
KINDS = ("raven_hub", "tak_server", "other")
DIRECTIONS = ("we_dial", "they_dial")

DEFAULT_V2_PORT = 9102
DEFAULT_POLICY_NAME = "C4Raven"
MAX_CA_BYTES = 1024 * 1024
MAX_NAME_LENGTH = 100
CA_EXPIRY_WARNING_DAYS = 30
TCP_TIMEOUT_SECONDS = 3

# Problems that mean the partner can't work as configured (the card shows "error")
ERROR_PROBLEMS = frozenset(("ca_not_trusted", "no_rule_out", "no_rule_in", "ca_expired", "both_sides_dial"))

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.?$")


class PartnerError(Exception):
    """A user-facing failure: ``message`` is readable English (gettext), ``code`` is for machines."""

    def __init__(self, code, message, status=400, **extra):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.extra = extra

    undo_safe = True

    def with_undo(self, safe):
        self.undo_safe = safe
        return self

    def to_json(self):
        body = {"success": False, "error": self.message, "code": self.code}
        body.update(self.extra)
        return body


# --- small helpers -----------------------------------------------------------


def _core(policy):
    core = policy.get("policy")
    if not isinstance(core, dict):
        core = policy["policy"] = {}
    for key in ("entities", "rules", "groupSets"):
        if not isinstance(core.get(key), list):
            core[key] = []
    return core


def entities(policy):
    return _core(policy)["entities"]


def rules(policy):
    return _core(policy)["rules"]


def node_meta(entity):
    """Raven's bookkeeping stored in an entity's description (see module docstring)."""
    try:
        data = json.loads(entity.get("description") or "")
        meta = data.get("raven") if isinstance(data, dict) else None
        return dict(meta) if isinstance(meta, dict) else {}
    except (TypeError, ValueError):
        return {}


def set_node_meta(entity, **values):
    meta = node_meta(entity)
    data = {}
    description = entity.get("description")
    if description and not meta:
        # A description someone typed in the native console: keep it alongside
        try:
            parsed = json.loads(description)
            data = parsed if isinstance(parsed, dict) else {"note": description}
        except (TypeError, ValueError):
            data = {"note": description}
    elif description:
        data = json.loads(description)
    meta.update({k: v for k, v in values.items() if v is not None})
    data["raven"] = meta
    entity["description"] = json.dumps(data, sort_keys=True)


def own_ca(known_cas):
    for ca in known_cas or []:
        if ca.get("hubGroup"):
            return ca
    return None


def find_ca(known_cas, uid=None, sha256=None):
    for ca in known_cas or []:
        if uid is not None and ca.get("uid") == uid:
            return ca
        if sha256 is not None and (ca.get("alias") or "").lower() == sha256.lower():
            return ca
    return None


def sha256_from_uid(uid):
    tail = (uid or "").rsplit("-", 1)[-1]
    return tail.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", tail) else None


def find_node(policy, node_id):
    for entity in entities(policy):
        if entity.get("id") == node_id:
            return entity
    return None


def group_nodes(policy, uid):
    return [e for e in entities(policy) if e.get("type") == GROUP and e.get("name") == uid]


def own_node_enabled(policy, own_uid):
    """The hub's own CA node, only if it's enabled. A disabled one makes the broker refuse
    Raven's own bridge just like a missing one (G1), so callers treat both as missing."""
    for node in group_nodes(policy, own_uid) if own_uid else []:
        if _enabled(node):
            return node
    return None


def own_node(policy, own_uid):
    nodes = group_nodes(policy, own_uid) if own_uid else []
    return nodes[0] if nodes else None


def _enabled(entity):
    return bool(entity) and (entity.get("config") or {}).get("enabled", True) is not False


def _display(entity):
    return entity.get("displayName") or entity.get("name") or entity.get("id")


def filter_from_rule(rule):
    f = (rule or {}).get("filter") or {}
    ftype = f.get("groupsFilterType") or "allGroups"
    return {
        "type": ftype,
        "allowed": list(f.get("allowedGroups") or []),
        "disallowed": list(f.get("disallowedGroups") or []),
    }


def _hub_filter(spec):
    return {
        "groupsFilterType": spec["type"],
        "allowedGroups": list(spec["allowed"]),
        "disallowedGroups": list(spec["disallowed"]),
    }


NO_RULE = {"type": "none", "allowed": [], "disallowed": []}
ALL_GROUPS = {"type": "allGroups", "allowed": [], "disallowed": []}


# --- validation -------------------------------------------------------------


def validate_name(name):
    name = (name or "").strip() if isinstance(name, str) else ""
    if not name:
        raise PartnerError("invalid_name", gettext("Enter a name for this server"))
    if len(name) > MAX_NAME_LENGTH:
        raise PartnerError(
            "invalid_name",
            gettext("The name can be at most %(n)s characters", n=MAX_NAME_LENGTH),
        )
    if any(ord(c) < 32 for c in name):
        raise PartnerError("invalid_name", gettext("The name can't contain control characters"))
    return name


def validate_kind(kind):
    if kind in (None, ""):
        return "other"
    if kind not in KINDS:
        raise PartnerError("invalid_kind", gettext("Unknown server type"))
    return kind


def validate_direction(direction):
    if direction not in DIRECTIONS:
        raise PartnerError(
            "invalid_direction", gettext("Choose whether we connect to them or they connect to us")
        )
    return direction


def validate_host(host):
    host = host.strip() if isinstance(host, str) else ""
    if not host:
        raise PartnerError("invalid_host", gettext("Enter the other server's address"))
    if "://" in host or "/" in host:
        raise PartnerError(
            "invalid_host",
            gettext("Enter only the host name or IP address, without https:// or a path"),
        )
    if any(c.isspace() for c in host):
        raise PartnerError("invalid_host", gettext("The address can't contain spaces"))
    if len(host) > 253:
        raise PartnerError("invalid_host", gettext("That address is too long"))
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if ":" in host:
        raise PartnerError(
            "invalid_host", gettext("Enter the port in the port field, not after the address")
        )
    if not _HOST_RE.match(host):
        raise PartnerError("invalid_host", gettext("That isn't a valid host name or IP address"))
    return host


def validate_port(port):
    try:
        if isinstance(port, bool):
            raise ValueError
        value = int(str(port).strip())
    except (TypeError, ValueError):
        raise PartnerError("invalid_port", gettext("The port must be a number from 1 to 65535"))
    if not 1 <= value <= 65535:
        raise PartnerError("invalid_port", gettext("The port must be a number from 1 to 65535"))
    return value


def parse_bool(value, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("true", "1", "yes", "on"):
        return True
    if text in ("false", "0", "no", "off"):
        return False
    raise PartnerError("invalid_value", gettext("Expected true or false"))


def validate_filter(value, field):
    """A share/receive filter from the UI: a dict or its JSON string. None = allGroups."""
    if value is None or value == "":
        return dict(ALL_GROUPS)
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise PartnerError(
                "invalid_filter", gettext("The %(field)s setting isn't valid JSON", field=field)
            )
    if not isinstance(value, dict):
        raise PartnerError("invalid_filter", gettext("The %(field)s setting is invalid", field=field))
    ftype = value.get("type") or "allGroups"
    if ftype not in FILTER_TYPES:
        raise PartnerError(
            "invalid_filter", gettext("Unknown group filter for %(field)s", field=field)
        )

    def groups(key):
        items = value.get(key) or []
        if not isinstance(items, list) or not all(isinstance(g, str) for g in items):
            raise PartnerError(
                "invalid_filter", gettext("Group lists for %(field)s must be text", field=field)
            )
        return list(dict.fromkeys(g.strip() for g in items if g.strip()))

    allowed = groups("allowed") if ftype in ("allowed", "allowedAndDisallowed") else []
    disallowed = groups("disallowed") if ftype in ("disallowed", "allowedAndDisallowed") else []
    if ftype in ("allowed", "allowedAndDisallowed") and not allowed:
        raise PartnerError(
            "invalid_filter", gettext("Add at least one allowed group for %(field)s", field=field)
        )
    if ftype == "disallowed" and not disallowed:
        raise PartnerError(
            "invalid_filter", gettext("Add at least one blocked group for %(field)s", field=field)
        )
    return {"type": ftype, "allowed": allowed, "disallowed": disallowed}


# --- CA certificates ----------------------------------------------------------


def parse_ca_file(data):
    """Parses one X.509 certificate (PEM or DER) as the hub would.

    Returns {pem, sha256, subject, issuer, uid, not_after, is_ca}. ``uid`` is computed the
    hub's way (RFC 2253 subject + "-" + sha256); the hub's own value (from getKnownCaGroups)
    is authoritative once the CA is uploaded.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    if not data:
        raise PartnerError("invalid_ca", gettext("Choose the other server's CA certificate file"))
    if len(data) > MAX_CA_BYTES:
        raise PartnerError("invalid_ca", gettext("The CA certificate file is larger than 1 MB"))
    try:
        if b"-----BEGIN" in data:
            if data.count(b"-----BEGIN CERTIFICATE-----") > 1:
                raise PartnerError(
                    "multiple_certs",
                    gettext(
                        "That file holds more than one certificate. Upload only the CA that "
                        "issued the other server's certificate"
                    ),
                )
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except PartnerError:
        raise
    except Exception:
        raise PartnerError(
            "invalid_ca", gettext("That file isn't an X.509 certificate in PEM or DER format")
        )

    # The loaders are lazy: a malformed name, extension or date only fails when it's read
    try:
        der = cert.public_bytes(Encoding.DER)
        sha256 = hashlib.sha256(der).hexdigest()
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        try:
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = bool(basic.ca)
        except x509.ExtensionNotFound:
            is_ca = False
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        pem = cert.public_bytes(Encoding.PEM)
    except Exception:
        raise PartnerError(
            "bad_certificate",
            gettext("That certificate is damaged or uses a format the hub can't read"),
        )
    return {
        "pem": pem,
        "sha256": sha256,
        "subject": subject,
        "issuer": issuer,
        "uid": f"{subject}-{sha256}",
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "is_ca": is_ca,
    }


def fingerprint(sha256):
    """sha256 hex as colon-separated upper-case pairs (how TAK Server shows fingerprints)."""
    sha = (sha256 or "").upper()
    return ":".join(sha[i : i + 2] for i in range(0, len(sha), 2))


def _parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def days_left(expires, now=None):
    parsed = _parse_time(expires)
    if parsed is None:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return (parsed - now).total_seconds() / 86400.0


# --- partner discovery ------------------------------------------------------------------


def partner_entries(policy, own_uid):
    """Groups the active policy's nodes into partners.

    Every FederationGroup node other than the own-CA node is a partner (keyed by CA uid;
    duplicates of the same uid fold into one). An outgoing node belongs to the CA partner
    named in its Raven metadata; any other outgoing node is a partner of its own (keyed by
    its node name), e.g. one created in the native console.
    """
    by_uid = {}
    order = []
    for entity in entities(policy):
        if entity.get("type") != GROUP:
            continue
        uid = entity.get("name")
        if not uid or uid == own_uid:
            continue
        if uid not in by_uid:
            by_uid[uid] = {"id": uid, "ca_uid": uid, "ca_node": entity, "outgoing": None}
            order.append(by_uid[uid])
    for entity in entities(policy):
        if entity.get("type") != OUTGOING:
            continue
        linked = node_meta(entity).get("ca")
        entry = by_uid.get(linked)
        if entry is not None and entry["outgoing"] is None:
            entry["outgoing"] = entity
            continue
        order.append({"id": entity.get("name") or entity.get("id"), "ca_uid": None, "ca_node": None, "outgoing": entity})
    return order


def find_entry(policy, own_uid, partner_id):
    for entry in partner_entries(policy, own_uid):
        if entry["id"] == partner_id:
            return entry
    return None


def _primary(entry):
    return entry["outgoing"] or entry["ca_node"]


def _entry_nodes(entry):
    return [n for n in (entry["ca_node"], entry["outgoing"]) if n]


def _rule(policy, source, destination):
    for rule in rules(policy):
        if rule.get("source") == source and rule.get("destination") == destination:
            return rule
    return None


def _kind(entry):
    for node in _entry_nodes(entry):
        kind = node_meta(node).get("kind")
        if kind in KINDS:
            return kind
    return "other"


def _expires(entry):
    for node in _entry_nodes(entry):
        expires = node_meta(node).get("expires")
        if expires:
            return expires
    return None


def connection_is(cid, name):
    """Whether a hub connection id belongs to the identity ``name`` (an outgoing node name such
    as "VPN Server_<uuid4>", or the bridge uid "raven-federate"). The hub builds ids as
    "<name>-<fingerprint>-<server id>" (live: "raven-federate-4149...-1339...",
    "Pub server_eb40...-c0dc...-6227...-MwccocTf"), so the name must be followed by "-" or end
    the id: a bare prefix test would take "V" for "VPN_...".
    """
    if not cid or not name:
        return False
    return cid == name or cid.startswith(name + "-")


def attribute_connections(entries, connections, own_uid, bridge_uid):
    """Splits live connections into per-partner lists, the bridge's and the rest."""
    by_partner = {e["id"]: [] for e in entries}
    own_bridge = []
    rest = []
    for conn in connections or []:
        cid = conn.get("connectionId") or ""
        groups = conn.get("groupIdentities") or []
        owner = None
        for entry in entries:
            out = entry["outgoing"]
            if out and connection_is(cid, out.get("name")):
                owner = entry
                break
        if owner is None:
            for entry in entries:
                if entry["ca_uid"] and entry["ca_uid"] in groups:
                    owner = entry
                    break
        if owner is not None:
            by_partner[owner["id"]].append(conn)
        elif connection_is(cid, bridge_uid) and (not own_uid or own_uid in groups):
            own_bridge.append(conn)
        else:
            rest.append(conn)
    return by_partner, own_bridge, rest


def traffic_for(entry, conns, metrics):
    """Message/byte counters for a partner from getBrokerMetrics channelInfos.

    A channel is one directed hop source -> target; its ``messagesWritten`` are the messages
    the hub delivered over it. Channels whose source is the partner count as inbound,
    channels whose target is the partner as outbound.
    """
    ids = {c.get("connectionId") for c in conns if c.get("connectionId")}
    uid = entry["ca_uid"]
    out = {"msgs_out": 0, "msgs_in": 0, "bytes_out": 0, "bytes_in": 0}
    for ch in (metrics or {}).get("channelInfos") or []:
        is_source = ch.get("sourceId") in ids or (uid and ch.get("sourceCert") == uid)
        is_target = ch.get("targetId") in ids or (uid and ch.get("targetCert") == uid)
        msgs = int(ch.get("messagesWritten") or 0)
        nbytes = int(ch.get("bytesWritten") or 0)
        if is_source and not is_target:
            out["msgs_in"] += msgs
            out["bytes_in"] += nbytes
        elif is_target and not is_source:
            out["msgs_out"] += msgs
            out["bytes_out"] += nbytes
    return out


def _incoming_from_ca(entry, connections):
    """Live connections from the partner's CA that aren't our own outgoing connection."""
    uid = entry["ca_uid"]
    out_name = (entry["outgoing"] or {}).get("name")
    if not uid:
        return []
    found = []
    for conn in connections or []:
        cid = conn.get("connectionId") or ""
        if uid in (conn.get("groupIdentities") or []) and not connection_is(cid, out_name):
            found.append(conn)
    return found


HUB_CLIENT = "FEDERATION_HUB_CLIENT"


def dial_conflicts(entries, connections):
    """Partner ids caught in "both sides dial" (G6).

    A partner whose own (linked) outgoing node dials it while a connection from its CA comes
    in is flagged. An outgoing node not linked to any CA (e.g. made in the native console)
    can't be matched to a CA, so while it dials anyone and another hub dials in
    (remoteConnectionType FEDERATION_HUB_CLIENT) from a partner's CA, both that outgoing
    partner and the CA partner are flagged.
    """
    flagged = set()
    dialing = [e for e in entries if e["outgoing"] and _enabled(e["outgoing"])]  # a disabled one doesn't dial
    for entry in dialing:
        if entry["ca_uid"] and _incoming_from_ca(entry, connections):
            flagged.add(entry["id"])
    unlinked = [e for e in dialing if not e["ca_uid"]]
    if not unlinked:
        return flagged
    out_names = [e["outgoing"].get("name") for e in entries if e["outgoing"] and e["outgoing"].get("name")]
    for conn in connections or []:
        if conn.get("remoteConnectionType") != HUB_CLIENT:
            continue
        cid = conn.get("connectionId") or ""
        if any(connection_is(cid, name) for name in out_names):
            continue  # that's one of our own outgoing connections
        groups = conn.get("groupIdentities") or []
        for entry in entries:
            if entry["ca_uid"] and entry["ca_uid"] in groups and not entry["outgoing"]:
                flagged.add(entry["id"])
                flagged.update(e["id"] for e in unlinked)
    return flagged


def partner_problems(entry, policy, own_uid, known_cas, conns, now=None, dial_conflict=False):
    problems = []
    if entry["ca_uid"] and not find_ca(known_cas, uid=entry["ca_uid"]):
        problems.append("ca_not_trusted")
    own = own_node(policy, own_uid)
    primary = _primary(entry)
    share = _rule(policy, own["id"], primary["id"]) if own else None
    receive = _rule(policy, primary["id"], own["id"]) if own else None
    if not share:
        problems.append("no_rule_out")
    if not receive:
        problems.append("no_rule_in")
    share_type = filter_from_rule(share)["type"] if share else "allGroups"
    receive_type = filter_from_rule(receive)["type"] if receive else "allGroups"
    if share_type != "allGroups" or (_kind(entry) == "raven_hub" and receive_type != "allGroups"):
        problems.append("filter_not_all_groups")
    if dial_conflict:
        problems.append("both_sides_dial")
    left = days_left(_expires(entry), now)
    if left is not None:
        if left <= 0:
            problems.append("ca_expired")
        elif left <= CA_EXPIRY_WARNING_DAYS:
            problems.append("ca_expiring")
    return problems


def build_partner(entry, policy, own_uid, known_cas, conns=None, metrics=None, now=None,
                  dial_conflict=False):
    conns = conns or []
    ca_node, outgoing = entry["ca_node"], entry["outgoing"]
    ca = None
    if entry["ca_uid"]:
        known = find_ca(known_cas, uid=entry["ca_uid"]) or {}
        uid = entry["ca_uid"]
        ca = {
            "uid": uid,
            "sha256": (known.get("alias") or sha256_from_uid(uid) or "").lower() or None,
            "subject": known.get("subject") or uid.rsplit("-", 1)[0],
            "nickname": known.get("nickname"),
            "expires": _expires(entry),
        }
    name = (ca or {}).get("nickname") or _display(ca_node or outgoing)
    out = None
    if outgoing:
        config = outgoing.get("config") or {}
        out = {
            "name": outgoing.get("name"),
            "host": config.get("host"),
            "port": config.get("port"),
            "enabled": _enabled(outgoing),
        }
    own = own_node(policy, own_uid)
    primary = _primary(entry)
    share = _rule(policy, own["id"], primary["id"]) if own else None
    receive = _rule(policy, primary["id"], own["id"]) if own else None
    enabled = all(_enabled(n) for n in _entry_nodes(entry))
    problems = partner_problems(entry, policy, own_uid, known_cas, conns, now, dial_conflict)
    if not enabled:
        status = "disabled"
    elif conns:
        status = "connected"
    elif any(p in ERROR_PROBLEMS for p in problems):
        status = "error"
    else:
        status = "waiting"
    return {
        "id": entry["id"],
        "name": name,
        "kind": _kind(entry),
        "direction": "we_dial" if outgoing else "they_dial",
        "ca": ca,
        "outgoing": out,
        "interconnected": bool((ca_node or {}).get("config", {}).get("interconnected", False)),
        "share": filter_from_rule(share) if share else dict(NO_RULE),
        "receive": filter_from_rule(receive) if receive else dict(NO_RULE),
        "enabled": enabled,
        "status": status,
        "connections": conns,
        "traffic": traffic_for(entry, conns, metrics),
        "problems": problems,
    }


def build_partners(policy, own_uid, known_cas, connections, metrics, bridge_uid, now=None):
    entries = partner_entries(policy, own_uid) if policy else []
    by_partner, bridge, rest = attribute_connections(entries, connections, own_uid, bridge_uid)
    conflicts = dial_conflicts(entries, connections)
    partners = [
        build_partner(e, policy, own_uid, known_cas, by_partner[e["id"]], metrics, now,
                      dial_conflict=e["id"] in conflicts)
        for e in entries
    ]
    return partners, bridge, rest


# --- policy edits ---------------------------------------------------------------------


def _new_id():
    return str(uuid.uuid4())


def empty_policy(name=DEFAULT_POLICY_NAME):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "name": name,
        "version": "v3",
        "type": None,
        "description": None,
        "creationDate": now,
        "modifiedDate": now,
        "policy": {"entities": [], "rules": [], "groupSets": []},
        "plugins": [],
        "views": {"graph": {"nodes": [], "settings": {"zoom": 1, "canvas_x": 0, "canvas_y": 0}}},
    }


def _graph_view(policy):
    views = policy.get("views")
    if not isinstance(views, dict):
        views = policy["views"] = {}
    graph = views.get("graph")
    if not isinstance(graph, dict):
        graph = views["graph"] = {}
    if "settings" not in graph:
        graph["settings"] = {"zoom": 1, "canvas_x": 0, "canvas_y": 0}
    nodes = graph.get("nodes")
    if nodes is None or nodes == {}:
        # the hub turns an empty list into {} on the way out
        nodes = graph["nodes"] = []
    return graph


def _view_positions(graph):
    nodes = graph["nodes"]
    items = nodes.values() if isinstance(nodes, dict) else nodes
    return [(n.get("x"), n.get("y")) for n in items if isinstance(n, dict)]


def add_view_node(policy, node_id):
    """Gives a new node a free spot on the native editor's canvas (a grid, 220 x 150)."""
    graph = _graph_view(policy)
    taken = {
        (round(x or 0), round(y or 0))
        for x, y in _view_positions(graph)
        if isinstance(x, (int, float)) and isinstance(y, (int, float))
    }
    index = 0
    while True:
        x, y = 120 + 220 * (index % 5), 90 + 150 * (index // 5)
        if not any(abs(x - tx) < 170 and abs(y - ty) < 80 for tx, ty in taken):
            break
        index += 1
    entry = {"id": node_id, "x": x, "y": y}
    if isinstance(graph["nodes"], dict):
        graph["nodes"][node_id] = entry
    else:
        graph["nodes"].append(entry)


def remove_view_nodes(policy, node_ids):
    views = policy.get("views")
    graph = views.get("graph") if isinstance(views, dict) else None
    if not isinstance(graph, dict):
        return
    nodes = graph.get("nodes")
    if isinstance(nodes, list):
        graph["nodes"] = [n for n in nodes if not (isinstance(n, dict) and n.get("id") in node_ids)]
    elif isinstance(nodes, dict):
        for key in [k for k, v in nodes.items() if k in node_ids or (isinstance(v, dict) and v.get("id") in node_ids)]:
            del nodes[key]


def _rule_name(source, destination):
    return f"{_display(source)} -> {_display(destination)}"


def set_rule(policy, source, destination, spec):
    """Makes exactly one rule source -> destination with the given filter (keeps its id)."""
    pair = [r for r in rules(policy) if r.get("source") == source["id"] and r.get("destination") == destination["id"]]
    if pair:
        rule = pair[0]
        rule["filter"] = _hub_filter(spec)
        drop = {id(r) for r in pair[1:]}
        _core(policy)["rules"] = [r for r in rules(policy) if id(r) not in drop]
        return rule
    rule = {
        "id": _new_id(),
        "name": _rule_name(source, destination),
        "source": source["id"],
        "destination": destination["id"],
        "filter": _hub_filter(spec),
    }
    rules(policy).append(rule)
    return rule


def new_group_node(uid, display_name, interconnected=False, kind=None, expires=None, enabled=True):
    node = {
        "id": _new_id(),
        "type": GROUP,
        "displayName": display_name,
        "name": uid,
        "description": None,
        "config": {
            "interconnected": bool(interconnected),
            "tokenAuthDuration": -1,
            "allowTokenAuth": False,
            "enabled": bool(enabled),
        },
    }
    if kind or expires:
        set_node_meta(node, kind=kind, expires=expires)
    return node


def new_outgoing_node(display_name, host, port, kind=None, ca_uid=None):
    node = {
        "id": _new_id(),
        "type": OUTGOING,
        "displayName": display_name,
        "name": f"{display_name}_{uuid.uuid4()}",
        "description": None,
        "config": {
            "host": host,
            "port": int(port),
            "tls": True,
            "enabled": True,
            "useToken": False,
            "tokenType": "manual",
            "token": None,
            "outgoing_uuid": None,
        },
    }
    set_node_meta(node, kind=kind, ca=ca_uid)
    return node


def ensure_own_node(policy, own):
    """Adds the hub's own CA node if the policy lacks it, or re-enables it if it's disabled.
    Returns (policy copy, changed?)."""
    policy = copy.deepcopy(policy)
    if own_node_enabled(policy, own["uid"]):
        return policy, False
    existing = own_node(policy, own["uid"])
    if existing is not None:
        existing.setdefault("config", {})["enabled"] = True
        return policy, True
    node = new_group_node(own["uid"], own.get("nickname") or "This hub")
    entities(policy).append(node)
    add_view_node(policy, node["id"])
    return policy, True


def outgoing_to(policy, host, port):
    host = (host or "").lower().rstrip(".")
    for entity in entities(policy):
        if entity.get("type") != OUTGOING:
            continue
        config = entity.get("config") or {}
        if (str(config.get("host") or "").lower().rstrip(".") == host and int(config.get("port") or 0) == int(port)):
            return entity
    return None


def add_partner(policy, own, *, name, kind, direction, ca_uid, host=None, port=None,
                interconnected=False, share=None, receive=None, expires=None):
    """Adds a partner: its CA node (+ outgoing node when we dial), rules both ways with the
    own-CA node and canvas positions. Returns (new policy, partner id)."""
    policy, _ = ensure_own_node(policy, own)
    own_entity = own_node(policy, own["uid"])
    share = share or dict(ALL_GROUPS)
    receive = receive or dict(ALL_GROUPS)

    ca_node = new_group_node(ca_uid, name, interconnected, kind=kind, expires=expires)
    entities(policy).append(ca_node)
    add_view_node(policy, ca_node["id"])
    nodes = [ca_node]
    if direction == "we_dial":
        out = new_outgoing_node(name, host, port, kind=kind, ca_uid=ca_uid)
        entities(policy).append(out)
        add_view_node(policy, out["id"])
        nodes.append(out)
    for node in nodes:
        set_rule(policy, own_entity, node, share)
        set_rule(policy, node, own_entity, receive)
    return policy, ca_uid


def _rename_rules(policy, node, old_display):
    for rule in rules(policy):
        if node["id"] not in (rule.get("source"), rule.get("destination")):
            continue
        src, dst = find_node(policy, rule.get("source")), find_node(policy, rule.get("destination"))
        if not src or not dst:
            continue
        old_src = old_display if src is node else _display(src)
        old_dst = old_display if dst is node else _display(dst)
        if rule.get("name") in (f"{old_src} -> {old_dst}", None, ""):
            rule["name"] = _rule_name(src, dst)


def update_partner(policy, own, partner_id, changes):
    """Applies validated ``changes`` (name, enabled, host, port, interconnected, share,
    receive, direction, kind) to a partner. Returns (new policy, new partner id)."""
    policy, _ = ensure_own_node(policy, own)
    entry = find_entry(policy, own["uid"], partner_id)
    if entry is None:
        raise PartnerError("not_found", gettext("That partner isn't in the active federation policy"), 404)
    own_entity = own_node(policy, own["uid"])

    direction = changes.get("direction")
    created_outgoing = False
    if direction == "they_dial" and entry["outgoing"]:
        if not entry["ca_node"]:
            raise PartnerError(
                "needs_ca",
                gettext("This connection has no trusted CA of its own, so it can only be removed, not switched"),
            )
        removed = entry["outgoing"]["id"]
        _core(policy)["entities"] = [e for e in entities(policy) if e.get("id") != removed]
        _core(policy)["rules"] = [r for r in rules(policy) if removed not in (r.get("source"), r.get("destination"))]
        remove_view_nodes(policy, {removed})
        entry["outgoing"] = None
    elif direction == "we_dial" and not entry["outgoing"]:
        if not changes.get("host") or not changes.get("port"):
            raise PartnerError("invalid_host", gettext("Enter the other server's address and port"))
        out = new_outgoing_node(
            _display(entry["ca_node"]), changes["host"], changes["port"], kind=_kind(entry), ca_uid=entry["ca_uid"]
        )
        entities(policy).append(out)
        add_view_node(policy, out["id"])
        share_rule = _rule(policy, own_entity["id"], entry["ca_node"]["id"])
        receive_rule = _rule(policy, entry["ca_node"]["id"], own_entity["id"])
        set_rule(policy, own_entity, out, filter_from_rule(share_rule) if share_rule else ALL_GROUPS)
        set_rule(policy, out, own_entity, filter_from_rule(receive_rule) if receive_rule else ALL_GROUPS)
        entry["outgoing"] = out
        created_outgoing = True

    if "name" in changes:
        for node in _entry_nodes(entry):
            old = _display(node)
            node["displayName"] = changes["name"]
            _rename_rules(policy, node, old)
    if "kind" in changes:
        for node in _entry_nodes(entry):
            set_node_meta(node, kind=changes["kind"])
    if "enabled" in changes:
        for node in _entry_nodes(entry):
            node.setdefault("config", {})["enabled"] = bool(changes["enabled"])
    if "interconnected" in changes:
        if not entry["ca_node"]:
            raise PartnerError("needs_ca", gettext("Only a partner with a trusted CA can be interconnected"))
        entry["ca_node"].setdefault("config", {})["interconnected"] = bool(changes["interconnected"])
    if ("host" in changes or "port" in changes) and direction != "they_dial":
        if entry["outgoing"] and not created_outgoing:
            config = entry["outgoing"].setdefault("config", {})
            if "host" in changes:
                config["host"] = changes["host"]
            if "port" in changes:
                config["port"] = int(changes["port"])
        elif not entry["outgoing"]:
            raise PartnerError(
                "not_dialing", gettext("We don't connect to this partner, so it has no address to change")
            )
    for key, outbound in (("share", True), ("receive", False)):
        if key in changes:
            for node in _entry_nodes(entry):
                if outbound:
                    set_rule(policy, own_entity, node, changes[key])
                else:
                    set_rule(policy, node, own_entity, changes[key])
    new_id = entry["ca_uid"] or entry["outgoing"]["name"]
    return policy, new_id


def remove_partner(policy, own_uid, partner_id):
    """Removes a partner's nodes (every CA node with its uid, its outgoing node), each rule
    touching them and their canvas positions. Returns (new policy, the CA uid or None)."""
    policy = copy.deepcopy(policy)
    entry = find_entry(policy, own_uid, partner_id)
    if entry is None:
        raise PartnerError("not_found", gettext("That partner isn't in the active federation policy"), 404)
    ids = {n["id"] for n in _entry_nodes(entry)}
    if entry["ca_uid"]:
        ids |= {n["id"] for n in group_nodes(policy, entry["ca_uid"])}
    core = _core(policy)
    core["entities"] = [e for e in entities(policy) if e.get("id") not in ids]
    core["rules"] = [r for r in rules(policy) if not ({r.get("source"), r.get("destination")} & ids)]
    remove_view_nodes(policy, ids)
    return policy, entry["ca_uid"]


def ca_referenced(policy, uid):
    """Whether any node of ``policy`` uses the CA: a CA node for it, or an outgoing node
    Raven linked to it."""
    if not uid:
        return False
    if group_nodes(policy, uid):
        return True
    return any(e.get("type") == OUTGOING and node_meta(e).get("ca") == uid for e in entities(policy))


def unlinked_outgoing(policy):
    """Outgoing nodes with no Raven link to a CA. The hub verifies each remote with some CA in
    its truststore, and for these Raven can't tell which."""
    return [e for e in entities(policy) if e.get("type") == OUTGOING and not node_meta(e).get("ca")]


def entity_ids(policy):
    return {e.get("id") for e in entities(policy)}


# --- diagnostics ---------------------------------------------------------------------


def resolve(host):
    """DNS lookup -> (ok, [addresses], error text)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as e:
        return False, [], str(e)
    return True, list(dict.fromkeys(info[4][0] for info in infos)), None


def tcp_connect(host, port, timeout=TCP_TIMEOUT_SECONDS):
    """TCP connect test -> (ok, error text)."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, None
    except (OSError, ValueError) as e:
        return False, str(e) or e.__class__.__name__


def address_allowed(address):
    """Whether Raven may probe this address for an admin. Private (RFC 1918) addresses are
    fine -- partners often sit on a LAN or VPN -- but loopback, link-local, multicast and
    unspecified addresses would let the probe poke at this box or its local segment."""
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def probe(host, port, resolver=resolve, connector=tcp_connect):
    """DNS + TCP probe of host:port -> {dns_ok, addresses, tcp_ok, error, blocked}.

    The TCP test connects to the resolved address (not the name again), and refuses
    addresses that :func:`address_allowed` rejects, before and after DNS."""
    result = {"dns_ok": False, "addresses": [], "tcp_ok": False, "error": None, "blocked": False}
    try:
        port = validate_port(port)
    except PartnerError as e:
        result["error"] = e.message
        return result
    dns_ok, addresses, error = resolver(host)
    result.update(dns_ok=dns_ok, addresses=addresses, error=error)
    if not dns_ok:
        return result
    if not addresses or not all(address_allowed(a) for a in addresses):
        result["blocked"] = True
        result["error"] = gettext(
            "Raven doesn't test loopback, link-local, multicast or unspecified addresses"
        )
        return result
    tcp_ok, error = connector(addresses[0], port)
    result.update(tcp_ok=tcp_ok, error=error)
    return result


def reachability(host, port, resolver=resolve, connector=tcp_connect):
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not address_allowed(literal):
        raise PartnerError(
            "address_not_allowed",
            gettext("Raven doesn't test loopback, link-local, multicast or unspecified addresses"),
        )
    result = probe(host, port, resolver, connector)
    blocked = result.pop("blocked")
    if blocked:
        raise PartnerError("address_not_allowed", result["error"], addresses=result["addresses"])
    return result


def _check(code, level, title, detail, fix=None):
    item = {"code": code, "ok": level in ("ok", "skipped"), "level": level, "title": title, "detail": detail}
    if fix:
        item["fix"] = fix
    return item


def build_checks(entry, partner, policy, own_uid, known_cas, connections, resolver=resolve,
                 connector=tcp_connect, now=None):
    """The ordered diagnostics list for one partner (see the spec's /check route)."""
    checks = []
    uid = entry["ca_uid"]
    title = gettext("Their CA certificate is trusted")
    if not uid:
        checks.append(_check("ca_trusted", "warning", title,
                             gettext("This connection isn't linked to a trusted CA, so Raven can't tell"),
                             gettext("Make sure the partner's CA is added under Advanced > Certificates")))
    elif find_ca(known_cas, uid=uid):
        checks.append(_check("ca_trusted", "ok", title,
                             gettext("Fingerprint %(fp)s", fp=fingerprint(partner["ca"]["sha256"]))))
    else:
        checks.append(_check("ca_trusted", "error", title,
                             gettext("The hub no longer trusts this CA"),
                             gettext("Remove this partner and connect it again with its CA file")))

    title = gettext("Their CA is in the active policy")
    if not uid:
        checks.append(_check("ca_in_policy", "skipped", title, gettext("Not needed: we connect to them")))
    elif not entry["ca_node"]:
        checks.append(_check("ca_in_policy", "error", title,
                             gettext("The partner's certificate isn't in the active policy, so the hub "
                                     "refuses its connections"),
                             gettext("Remove the partner and connect it again (its certificate is kept if still trusted)")))
    elif _enabled(entry["ca_node"]):
        checks.append(_check("ca_in_policy", "ok", title, gettext("Connections from this CA are accepted")))
    else:
        checks.append(_check("ca_in_policy", "error", title,
                             gettext("This partner is disabled, so the hub refuses its connections"),
                             gettext("Enable the partner")))

    own = own_node(policy, own_uid)
    primary = _primary(entry)
    out_rule = _rule(policy, own["id"], primary["id"]) if own else None
    in_rule = _rule(policy, primary["id"], own["id"]) if own else None
    fix = gettext("Edit the partner and save what to share, or use Repair if this hub's own CA is missing")
    checks.append(_check("rules_out", "ok" if out_rule else "error", gettext("We share data with them"),
                         gettext("A rule sends our data to them") if out_rule
                         else gettext("No rule sends our data to them"), None if out_rule else fix))
    checks.append(_check("rules_in", "ok" if in_rule else "error", gettext("We receive data from them"),
                         gettext("A rule delivers their data to us") if in_rule
                         else gettext("No rule delivers their data to us"), None if in_rule else fix))

    share = partner["share"]["type"]
    receive = partner["receive"]["type"]
    title = gettext("Group filters will let data through")
    if share not in ("allGroups", "none") or (partner["kind"] == "raven_hub" and receive not in ("allGroups", "none")):
        checks.append(_check("filter_compatible", "warning", title,
                             gettext("Raven doesn't send group names to the hub, so a group filter on data "
                                     "from Raven blocks everything"),
                             gettext("Share \"Everything\" unless both sides use federated group mapping")))
    else:
        checks.append(_check("filter_compatible", "ok", title, gettext("Everything is shared")))

    title = gettext("Only one side connects")
    if "both_sides_dial" in partner["problems"]:
        if entry["outgoing"] and entry["ca_uid"]:
            detail = gettext("We connect to them and they also connect to us; the hub drops one "
                             "of the two connections over and over")
        else:
            detail = gettext("This hub dials out to another hub while a hub this partner trusts also "
                             "dials in; if they're the same partner the hub drops one of the two "
                             "connections over and over")
        checks.append(_check("dial_direction", "error", title, detail,
                             gettext("Keep only one direction: remove the outgoing connection here, or "
                                     "ask the other admin to remove theirs")))
    else:
        checks.append(_check("dial_direction", "ok", title,
                             gettext("We connect to them") if entry["outgoing"] else gettext("They connect to us")))

    out = partner["outgoing"]
    if out:
        result = probe(out["host"], out["port"], resolver, connector)
        dns_ok, addresses, error = result["dns_ok"], result["addresses"], result["error"]
        checks.append(_check("dns", "ok" if dns_ok else "error", gettext("Their address resolves"),
                             ", ".join(addresses) if dns_ok
                             else gettext("%(host)s can't be resolved: %(error)s", host=out["host"], error=error),
                             None if dns_ok else gettext("Check the spelling; it must be the exact name in "
                                                         "their server certificate")))
        if dns_ok and result["blocked"]:
            checks.append(_check("tcp", "error", gettext("Their port is reachable"), error,
                                 gettext("Use the partner's real address, not a loopback or link-local one")))
        elif dns_ok:
            tcp_ok, error = result["tcp_ok"], result["error"]
            checks.append(_check("tcp", "ok" if tcp_ok else "error", gettext("Their port is reachable"),
                                 gettext("%(host)s:%(port)s accepts connections", host=out["host"], port=out["port"])
                                 if tcp_ok else gettext("Can't connect to %(host)s:%(port)s: %(error)s",
                                                        host=out["host"], port=out["port"], error=error),
                                 None if tcp_ok else gettext("Ask the other admin to open this port in their "
                                                             "firewall and check the port number")))
        else:
            checks.append(_check("tcp", "error", gettext("Their port is reachable"),
                                 gettext("Skipped because the address doesn't resolve")))
    else:
        checks.append(_check("dns", "skipped", gettext("Their address resolves"),
                             gettext("Not needed: they connect to us")))
        checks.append(_check("tcp", "skipped", gettext("Their port is reachable"),
                             gettext("Not needed: they connect to us")))

    connected = bool(partner["connections"])
    checks.append(_check("connected", "ok" if connected else "error", gettext("Connected"),
                         gettext("%(n)s live connection(s)", n=len(partner["connections"])) if connected
                         else gettext("No live connection yet"),
                         None if connected else (
                             gettext("Wait a few seconds; the hub retries every 5 seconds") if out
                             else gettext("Send the other admin the instructions so they connect to us"))))

    traffic = partner["traffic"]
    flowing = (traffic["msgs_in"] + traffic["msgs_out"]) > 0
    checks.append(_check("traffic_flowing", "ok" if flowing else "warning", gettext("Data is flowing"),
                         gettext("%(sent)s sent, %(received)s received", sent=traffic["msgs_out"],
                                 received=traffic["msgs_in"]) if flowing
                         else gettext("No messages yet"),
                         None if flowing else gettext("Move a device on either side; TAK Servers also need "
                                                      "Manage Groups set for the hub federate")))

    title = gettext("Their CA isn't about to expire")
    left = days_left(partner["ca"]["expires"] if partner["ca"] else None, now)
    if left is None:
        checks.append(_check("ca_expiry", "skipped", title, gettext("Expiry date unknown")))
    elif left <= 0:
        checks.append(_check("ca_expiry", "error", title, gettext("Their CA has expired"),
                             gettext("Ask the other admin for their new CA")))
    elif left <= CA_EXPIRY_WARNING_DAYS:
        checks.append(_check("ca_expiry", "warning", title,
                             gettext("Their CA expires in %(days)s days", days=int(left)),
                             gettext("Ask the other admin for their new CA")))
    else:
        checks.append(_check("ca_expiry", "ok", title,
                             gettext("Valid for %(days)s more days", days=int(left))))
    return checks


# --- hub client and orchestration ---------------------------------------------------------


def seg(value):
    """One URL path segment for the hub, fully escaped (CA uids hold commas, '=' and spaces)."""
    return quote(str(value), safe="")


class HubUnavailable(PartnerError):
    def __init__(self, timeout=False):
        if timeout:
            super().__init__("hub_timeout", gettext("Federation Hub timed out"), 504)
        else:
            super().__init__("hub_unreachable", gettext("Federation Hub is not running"), 503)


class HubError(PartnerError):
    def __init__(self, what, response):
        text = (getattr(response, "text", "") or "").strip()[:300]
        message = gettext("Federation Hub refused to %(what)s", what=what)
        if text:
            message = f"{message}: {text}"
        super().__init__("hub_error", message, 502, hub_status=getattr(response, "status_code", None))


NO_ACTIVE_POLICY_TEXT = "The active federation policy does not have any graph data"


class HubClient:
    """Typed calls to the hub admin API through ``request_fn(method, path, **kwargs)``."""

    def __init__(self, request_fn):
        self._request = request_fn

    def call(self, method, path, what, **kwargs):
        try:
            r = self._request(method, path, **kwargs)
        except requests.exceptions.Timeout:
            raise HubUnavailable(timeout=True)
        except requests.exceptions.RequestException:
            raise HubUnavailable()
        if r.status_code >= 400:
            raise HubError(what, r)
        return r

    def json(self, method, path, what, **kwargs):
        r = self.call(method, path, what, **kwargs)
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            raise HubError(what, r)

    def active_policy(self):
        """The active policy, or None when the hub has none."""
        try:
            r = self._request("GET", "/getActivePolicy")
        except requests.exceptions.Timeout:
            raise HubUnavailable(timeout=True)
        except requests.exceptions.RequestException:
            raise HubUnavailable()
        what = gettext("read the active policy")
        # The hub's one documented "no active policy" answer (FederationHubUIService.getActivePolicy):
        # 404 with this text. Anything else unexpected must stop a change before it writes.
        if r.status_code == 404 and NO_ACTIVE_POLICY_TEXT in (r.text or ""):
            return None
        if r.status_code >= 400:
            raise HubError(what, r)
        try:
            policy = r.json()
        except ValueError:
            raise HubError(what, r)
        if not isinstance(policy, dict) or not policy.get("name") or not isinstance(policy.get("policy"), dict):
            raise HubError(what, r)
        return policy

    def known_cas(self):
        return self.json("GET", "/getKnownCaGroups", gettext("list its CA certificates")) or []

    def connections(self):
        return self.json("GET", "/getActiveConnections", gettext("list connections")) or []

    def metrics(self):
        return self.json("GET", "/getBrokerMetrics", gettext("report metrics")) or {}

    def broker_config(self):
        return self.json("GET", "/getBrokerConfig", gettext("report its configuration")) or {}

    def stored_policies(self):
        return self.json("GET", "/federations", gettext("list policies")) or []

    def self_ca(self):
        return self.call("GET", "/getSelfCaFile", gettext("send its CA certificate")).content

    def add_ca(self, pem, nickname):
        self.call("POST", "/addNewGroupCa", gettext("add the CA certificate"),
                  files={"file": ("ca.pem", pem, "application/x-pem-file")}, data={"nickname": nickname})

    def delete_ca(self, uid):
        self.call("DELETE", f"/deleteGroupCa/{seg(uid)}", gettext("remove the CA certificate"))

    def rename_ca(self, ca, nickname):
        body = dict(ca)
        body["nickname"] = nickname
        self.call("POST", "/updateCaNickname", gettext("rename the CA certificate"), json=body)

    def save_policy(self, policy):
        self.call("POST", "/saveFederationPolicy", gettext("save the policy"), json=policy)

    def activate(self, name):
        # The hub's route is a GET that changes state (G15)
        self.call("GET", f"/activateFederationPolicy/{seg(name)}", gettext("activate the policy"))

    def disconnect(self, connection_id):
        self.call("DELETE", f"/disconnectFederate/{seg(connection_id)}", gettext("disconnect the connection"))


_POLICY_LOCK = threading.Lock()


@contextmanager
def policy_lock(timeout=30):
    """Serialises read-modify-write of the hub policy between admins."""
    if not _POLICY_LOCK.acquire(timeout=timeout):
        raise PartnerError(
            "busy", gettext("Another change to the Federation Hub is in progress. Try again in a moment"), 409
        )
    try:
        yield
    finally:
        _POLICY_LOCK.release()


def prepare_for_save(policy):
    policy = copy.deepcopy(policy)
    if not policy.get("version"):
        policy["version"] = "v3"
    return policy


def apply_policy(client, new_policy, previous=None, logger=None, own_uid=None):
    """Save + activate + confirm (re-read the active policy).

    On failure the previous policy (if there was one) is saved and activated again and the
    original error is re-raised with ``undo_safe = True``: the caller may undo its own other
    changes (e.g. delete a CA it added). When that isn't safe -- there was no previous policy
    to go back to and the hub may already enforce the new one, or restoring failed -- a
    500 error with ``undo_safe = False`` is raised instead and the caller must leave
    everything in place.
    """
    new_policy = prepare_for_save(new_policy)
    name = new_policy.get("name")
    stage = "save"
    try:
        client.save_policy(new_policy)
        stage = "activate"
        client.activate(name)
        stage = "confirm"
        active = client.active_policy()
        own_lost = bool(own_uid) and bool(own_node_enabled(new_policy, own_uid)) and not own_node_enabled(
            active or {}, own_uid
        )
        if not active or active.get("name") != name or entity_ids(active) != entity_ids(new_policy) or own_lost:
            raise PartnerError(
                "not_applied",
                gettext("Federation Hub accepted the change but isn't enforcing it"),
                502,
            )
        return active
    except PartnerError as error:
        if previous:
            try:
                client.save_policy(prepare_for_save(previous))
                client.activate(previous.get("name"))
                restored = client.active_policy()
            except PartnerError as e:
                if logger:
                    logger.error(f"Federation Hub: couldn't restore the previous policy: {e.message}")
                raise half_changed(error) from error
            if not restored or restored.get("name") != previous.get("name") or entity_ids(restored) != entity_ids(previous):
                if logger:
                    logger.error("Federation Hub: the restored policy isn't the one that's active")
                raise half_changed(error) from error
            error.undo_safe = True
            error.extra["restored"] = True
            raise
        if stage == "save":
            # Nothing was activated, so the hub still enforces what it did before
            error.undo_safe = True
            raise
        raise PartnerError(
            "partially_applied",
            gettext(
                "Federation Hub may already be enforcing part of this change (%(error)s). There was "
                "no earlier policy to go back to, so the policy and any CA certificate it uses were "
                "left in place. Check them under Advanced",
                error=error.message,
            ),
            500,
        ).with_undo(False) from error


def partially_applied(cause):
    return PartnerError(
        "partially_applied",
        gettext(
            "Federation Hub may already hold part of this change (%(error)s). A stored policy uses "
            "the CA certificate, so it was left in place. Check the hub under Advanced",
            error=cause.message,
        ),
        500,
    ).with_undo(False)


def stored_policy_uses_ca(client, uid):
    """True if any stored policy references the CA, or if that can't be checked."""
    try:
        stored = client.stored_policies()
    except PartnerError:
        return True
    return any(isinstance(p, dict) and isinstance(p.get("policy"), dict) and ca_referenced(p, uid) for p in stored)


def ca_users(policy, uid):
    """Display names of the nodes of ``policy`` that use the CA."""
    if not policy or not uid:
        return []
    return [
        _display(e)
        for e in entities(policy)
        if (e.get("type") == GROUP and e.get("name") == uid)
        or (e.get("type") == OUTGOING and node_meta(e).get("ca") == uid)
    ]


def half_changed(cause):
    return PartnerError(
        "rollback_failed",
        gettext(
            "Federation Hub may be half-changed: the change failed (%(error)s) and the previous "
            "policy couldn't be restored. Nothing else was undone; check the hub under Advanced",
            error=cause.message,
        ),
        500,
    ).with_undo(False)


def unique_policy_name(taken, base=DEFAULT_POLICY_NAME):
    taken = {str(t) for t in taken}
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def policy_to_change(client):
    """The active policy plus what to start from for a change: (previous, policy).

    With no active policy a fresh one is only made when the hub has no stored policies at
    all (under a name no stored policy uses). If stored policies exist, the admin has to
    activate one of them first: refuse rather than shadow them with a new one."""
    previous = client.active_policy()
    if previous:
        return previous, previous
    stored = [p for p in client.stored_policies() if isinstance(p, dict)]
    names = [p.get("name") for p in stored if p.get("name")]
    if names:
        raise PartnerError(
            "no_active_policy",
            gettext(
                "Federation Hub has no active policy, and Repair can't create one while stored "
                "policies exist. Activate one of them (%(names)s) under Advanced > Policy editor, "
                "or with its Activate button",
                names=", ".join(names),
            ),
            409,
            stored_policies=names,
        )
    return None, empty_policy(unique_policy_name(names))
