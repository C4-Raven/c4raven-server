"""
Tests for the guided Federation Hub page: raven/fedhub_partners.py (pure policy functions)
and the /api/fedhub/overview, /partners... routes in federation_hub_api.py.

The hub is a fake (FakeHub) swapped in for federation_hub_api._fedhub_request. Its JSON
shapes are copied from the live hub's read-only GETs (getActivePolicy, getKnownCaGroups,
getActiveConnections, getBrokerMetrics), with real CAs replaced by certs generated here and
addresses replaced by documentation ranges.
"""

import copy
import datetime
import hashlib
import importlib
import json
import threading
import time
from urllib.parse import unquote

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven import fedhub_partners as fp  # noqa: E402
from raven.audit import init_audit  # noqa: E402
# The raven_api package re-exports the blueprint under the module's name, so import the module
api = importlib.import_module("raven.blueprints.raven_api.federation_hub_api")
from raven.defaultconfig import DefaultConfig  # noqa: E402
from raven.models.AuditEvent import AuditEvent  # noqa: E402

# --- certificates ---------------------------------------------------------------------


def make_cert(cn="C4Raven-FedHub-CA", days=3650, ca=True, ou="C4Raven-FedHub"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZZ"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(Encoding.PEM)


def ca_record(pem, nickname, hub_group=False):
    info = fp.parse_ca_file(pem)
    return {
        "alias": info["sha256"],
        "nickname": nickname,
        "uid": info["uid"],
        "issuer": info["subject"],
        "subject": info["subject"],
        "hubGroup": hub_group,
    }


OWN_PEM = make_cert()
OTHER_PEM = make_cert()  # same DN as ours, different key (G7)
TAK_PEM = make_cert(cn="TAK-ROOT-CA", ou="TAK")
OWN = ca_record(OWN_PEM, "Pubserver", hub_group=True)
OTHER = ca_record(OTHER_PEM, "Pub Server")


def live_policy():
    """The live hub's active policy (2026-11-04), re-keyed to the generated CAs."""
    return {
        "name": "Tak",
        "version": "v3",
        "creationDate": "2026-11-04T03:49:39.518161963Z",
        "modifiedDate": "2026-11-04T04:33:21.885102445Z",
        "policy": {
            "entities": [
                {
                    "id": "own-node",
                    "type": "FederationGroup",
                    "displayName": "Pubserver",
                    "name": OWN["uid"],
                    "description": None,
                    "config": {
                        "interconnected": False,
                        "tokenAuthDuration": -1,
                        "allowTokenAuth": False,
                        "enabled": True,
                    },
                },
                {
                    "id": "vpn-node",
                    "type": "FederationGroup",
                    "displayName": "VPN",
                    "name": OTHER["uid"],
                    "description": None,
                    "config": {
                        "interconnected": True,
                        "tokenAuthDuration": -1,
                        "allowTokenAuth": False,
                        "enabled": True,
                    },
                },
                {
                    "id": "vpn-out",
                    "type": "FederationOutgoing",
                    "displayName": "VPN Server",
                    "name": "VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5",
                    "description": None,
                    "config": {
                        "useToken": False,
                        "port": 9102,
                        "host": "192.0.2.37",
                        "outgoing_uuid": None,
                        "tls": True,
                        "tokenType": "manual",
                        "enabled": True,
                        "token": None,
                    },
                },
            ],
            "rules": [
                _r("r1", "Pubserver -> VPN", "own-node", "vpn-node"),
                _r("r2", "Pubserver -> VPN Server", "own-node", "vpn-out"),
                _r("r3", "VPN -> VPN Server", "vpn-node", "vpn-out"),
                _r("r4", "VPN -> Pubserver", "vpn-node", "own-node"),
                _r("r5", "VPN Server -> VPN", "vpn-out", "vpn-node"),
                _r("r6", "VPN Server -> Pubserver", "vpn-out", "own-node"),
            ],
            "groupSets": [{"id": "gs1", "name": "Ops", "groups": ["a", "b"]}],
        },
        "plugins": [{"pluginName": "p", "sendTo": [], "dontSend": [], "receiveFrom": [],
                     "dontReceive": [], "sendByDefault": True, "receiveByDefault": True,
                     "disabled": False}],
        "views": {
            "graph": {
                "nodes": [
                    {"id": "own-node", "x": 540, "y": 90},
                    {"id": "vpn-node", "x": 678.5640646055102, "y": 330},
                    {"id": "vpn-out", "x": 401.43593539448983, "y": 330.00000000000006},
                ],
                "settings": {"zoom": 1, "canvas_x": 0, "canvas_y": 0},
            }
        },
    }


def _r(rid, name, src, dst, ftype="allGroups"):
    return {
        "id": rid,
        "name": name,
        "source": src,
        "destination": dst,
        "filter": {"groupsFilterType": ftype, "allowedGroups": [], "disallowedGroups": []},
    }


def minimal_policy():
    policy = fp.empty_policy("Tak")
    policy, _ = fp.ensure_own_node(policy, OWN)
    return policy


BRIDGE_CONN = {
    "connectionId": "raven-federate-414976d9344293b7e2cb488d4cd2e85e-133966942626776",
    "localConnectionType": "FEDERATION_HUB_SERVER",
    "remoteConnectionType": "FEDERATION_HUB_SERVER",
    "remoteServerId": "",
    "federationProtocolVersion": 2,
    "groupIdentities": [OWN["uid"]],
    "remoteAddress": "198.51.100.139:54248",
}
OTHER_HUB_CONN = {
    "connectionId": "Pub server_eb4007c1-e417-4755-8aba-b0d19021f421-c0dc4de9-622713fa-MwccocTf",
    "localConnectionType": "FEDERATION_HUB_SERVER",
    "remoteConnectionType": "FEDERATION_HUB_CLIENT",
    "remoteServerId": "622713fa68fa49d8a240dc3fe9d65545-MwccocTf",
    "federationProtocolVersion": 2,
    "groupIdentities": [OTHER["uid"]],
    "remoteAddress": "198.51.100.139:48026",
}


def live_metrics():
    return {
        "totalMessagesDropped": 0,
        "channelInfos": [
            {
                "sourceId": OTHER_HUB_CONN["connectionId"],
                "targetId": BRIDGE_CONN["connectionId"],
                "sourceCert": OTHER["uid"],
                "targetCert": OWN["uid"],
                "messagesWritten": 223,
                "messagesRead": 101,
                "totalMessages": 324,
                "bytesWritten": 145315,
                "bytesRead": 54284,
                "target": OWN["uid"],
            },
            {
                "sourceId": BRIDGE_CONN["connectionId"],
                "targetId": OTHER_HUB_CONN["connectionId"],
                "sourceCert": OWN["uid"],
                "targetCert": OTHER["uid"],
                "messagesWritten": 101,
                "messagesRead": 223,
                "totalMessages": 324,
                "bytesWritten": 54284,
                "bytesRead": 145315,
                "target": OTHER["uid"],
            },
        ],
        "totalWrites": 324,
        "totalReads": 335,
        "totalBytesWritten": 199599,
        "totalBytesRead": 404140,
    }


# --- fake hub -------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status=200, body=None, content_type="application/json"):
        self.status_code = status
        if body is None:
            self.content = b""
        elif isinstance(body, bytes):
            self.content = body
        elif isinstance(body, str):
            self.content = body.encode()
        else:
            self.content = json.dumps(body).encode()
        self.text = self.content.decode(errors="replace")
        self.headers = {"Content-Type": content_type}

    def json(self):
        return json.loads(self.content)


NO_POLICY_TEXT = "The active federation policy does not have any graph data associated with it"


class FakeHub:
    def __init__(self, policy=None, cas=None):
        policy = policy if policy is not None else live_policy()
        self.cas = copy.deepcopy(cas if cas is not None else [OWN, OTHER])
        self.policies = {policy["name"]: copy.deepcopy(policy)} if policy else {}
        self.active = copy.deepcopy(policy) if policy else None
        self.connections = []
        self.metrics = {"totalMessagesDropped": 0, "channelInfos": []}
        self.calls = []
        self.fail = {}  # "METHOD /path-prefix" -> status
        self.fail_once = {}  # same, but only for the next matching call
        self.down = False
        self.timeout = False

    def paths(self, *prefixes):
        return [c for c in self.calls if any(c.startswith(p) for p in prefixes)]

    def __call__(self, method, path, **kwargs):
        call = f"{method} {path}"
        self.calls.append(call)
        if self.down:
            raise requests.exceptions.ConnectionError("down")
        if self.timeout:
            raise requests.exceptions.Timeout("slow")
        for prefix, status in list(self.fail_once.items()):
            if call.startswith(prefix):
                del self.fail_once[prefix]
                return FakeResponse(status, "boom", "text/plain")
        for prefix, status in self.fail.items():
            if call.startswith(prefix):
                return FakeResponse(status, "boom", "text/plain")
        return self.route(method, path, kwargs)

    def route(self, method, path, kwargs):
        if path == "/getActivePolicy":
            if not self.active:
                # FederationHubUIService.getActivePolicy: NOT_FOUND with this text
                return FakeResponse(404, NO_POLICY_TEXT, "text/plain")
            return FakeResponse(200, self.active)
        if path == "/getKnownCaGroups":
            return FakeResponse(200, self.cas)
        if path == "/getActiveConnections":
            return FakeResponse(200, self.connections)
        if path == "/getBrokerMetrics":
            return FakeResponse(200, self.metrics)
        if path == "/getBrokerGlobalMetrics":
            return FakeResponse(200, {"numConnectedClients": len(self.connections), "cpuUtilized": -1.0})
        if path == "/getBrokerConfig":
            return FakeResponse(200, {"id": "broker-1", "v2Port": 9102, "keystorePassword": "x"})
        if path == "/federations":
            return FakeResponse(200, list(self.policies.values()))
        if path == "/getSelfCaFile":
            return FakeResponse(200, OWN_PEM, "application/octet-stream")
        if path == "/addNewGroupCa":
            pem = kwargs["files"]["file"][1]
            if hasattr(pem, "read"):
                pem = pem.read()
            record = ca_record(pem, kwargs["data"]["nickname"])
            self.cas.append(record)
            return FakeResponse(200)
        if path.startswith("/deleteGroupCa/"):
            uid = unquote(path[len("/deleteGroupCa/"):])
            self.cas = [c for c in self.cas if c["uid"] != uid]
            return FakeResponse(200)
        if path == "/updateCaNickname":
            for ca in self.cas:
                if ca["alias"] == kwargs["json"]["alias"]:
                    ca["nickname"] = kwargs["json"]["nickname"]
            return FakeResponse(200)
        if path == "/saveFederationPolicy":
            body = copy.deepcopy(kwargs["json"])
            self.policies[body["name"]] = body
            return FakeResponse(200, body)
        if path.startswith("/activateFederationPolicy/"):
            name = unquote(path.rsplit("/", 1)[1])
            if name not in self.policies:
                return FakeResponse(500, "Could save and activate policy", "text/plain")
            self.active = copy.deepcopy(self.policies[name])
            return FakeResponse(200)
        if path.startswith("/disconnectFederate/"):
            cid = unquote(path[len("/disconnectFederate/"):])
            self.connections = [c for c in self.connections if c["connectionId"] != cid]
            return FakeResponse(200)
        if path.startswith("/getKnownGroupsForGraphNode/"):
            return FakeResponse(200, [])
        if path.startswith("/federation/"):
            name = unquote(path.rsplit("/", 1)[1])
            return FakeResponse(200, self.policies[name]) if name in self.policies else FakeResponse(404, "nope")
        if path == "/policyToJson":
            return FakeResponse(200, json.dumps(kwargs["json"], indent=2), "text/plain")
        if path.startswith("/graphAsYaml/"):
            return FakeResponse(200, "name: Tak\n", "text/plain")
        if path == "/generateJwtToken":
            return FakeResponse(200, {"token": "eyJ.fake", "expiration": kwargs["json"]["expiration"]})
        return FakeResponse(404, f"no route {path}", "text/plain")


# --- app ------------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path):
    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_ENABLE_LDAP=False,
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        WTF_CSRF_ENABLED=False,
        SECURITY_PASSWORD_HASH="plaintext",
        SECURITY_USER_IDENTITY_ATTRIBUTES=[
            {"username": {"mapper": lambda x: x, "case_insensitive": True}}
        ],
        RAVEN_FEDHUB_API_ADDRESS="https://fed.example.net:9100/api",
        RAVEN_FEDHUB_BROKER_ADDRESS="tak.example.net:9102",
        RAVEN_FEDHUB_HOST="",
        RAVEN_FEDHUB_FEDERATE_ENABLE=True,
        RAVEN_FEDHUB_FEDERATE_UID="raven-federate",
        RAVEN_FEDHUB_ADMIN_P12=str(tmp_path / "missing.p12"),
        RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE=str(tmp_path / "missing.password"),
    )
    db.init_app(app)
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    init_audit(app)
    app.register_blueprint(api.federation_hub_api)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.create_user(username="admin", password=hash_password("adminpass"), roles=["administrator"])
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def hub(monkeypatch):
    fake = FakeHub()
    monkeypatch.setattr(api, "_fedhub_request", fake)
    monkeypatch.setattr(api, "_bridge_service_state", lambda: "active")
    monkeypatch.setitem(api._BROKER_CONFIG_CACHE, "value", None)
    monkeypatch.setattr(fp, "resolve", lambda host: (True, ["192.0.2.10"], None))
    monkeypatch.setattr(fp, "tcp_connect", lambda host, port, timeout=3: (True, None))
    return fake


@pytest.fixture
def admin(app):
    client = app.test_client()
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username="admin").fs_uniquifier
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()
    return client


def audit_rows(app):
    with app.app_context():
        return [(e.action, e.summary, e.success) for e in AuditEvent.query.order_by(AuditEvent.id).all()]


def post_partner(admin, pem=TAK_PEM, **fields):
    data = {"name": "TAK X", "kind": "tak_server", "direction": "they_dial"}
    data.update(fields)
    if pem is not None:
        import io

        data["ca_file"] = (io.BytesIO(pem), "ca.pem")
    return admin.post("/api/fedhub/partners", data=data, content_type="multipart/form-data")


def tak_uid():
    return fp.parse_ca_file(TAK_PEM)["uid"]


# --- pure functions ---------------------------------------------------------------------


def test_add_partner_they_dial_preserves_everything_else():
    policy = live_policy()
    policy["someFutureField"] = {"keep": True}
    before = copy.deepcopy(policy)
    new, pid = fp.add_partner(policy, OWN, name="TAK X", kind="tak_server", direction="they_dial",
                              ca_uid=tak_uid(), expires="2030-01-01T00:00:00Z")
    assert policy == before  # input untouched
    assert pid == tak_uid()
    assert new["someFutureField"] == {"keep": True}
    assert new["plugins"] == before["plugins"]
    assert new["policy"]["groupSets"] == before["policy"]["groupSets"]
    assert new["views"]["graph"]["settings"] == before["views"]["graph"]["settings"]
    node = fp.group_nodes(new, tak_uid())[0]
    assert node["displayName"] == "TAK X"
    assert node["config"] == {"interconnected": False, "tokenAuthDuration": -1,
                              "allowTokenAuth": False, "enabled": True}
    assert fp.node_meta(node) == {"kind": "tak_server", "expires": "2030-01-01T00:00:00Z"}
    added = [r for r in new["policy"]["rules"] if node["id"] in (r["source"], r["destination"])]
    assert {(r["source"], r["destination"]) for r in added} == {("own-node", node["id"]), (node["id"], "own-node")}
    assert all(r["filter"]["groupsFilterType"] == "allGroups" for r in added)
    assert added[0]["name"] == "Pubserver -> TAK X"
    assert node["id"] in {n["id"] for n in new["views"]["graph"]["nodes"]}
    assert len(new["policy"]["rules"]) == 8


def test_add_partner_we_dial_outgoing_follows_hub_conventions():
    new, _ = fp.add_partner(minimal_policy(), OWN, name="Raven B", kind="raven_hub", direction="we_dial",
                            ca_uid=OTHER["uid"], host="b.example.net", port=9102)
    out = [e for e in new["policy"]["entities"] if e["type"] == "FederationOutgoing"][0]
    prefix, _, suffix = out["name"].rpartition("_")
    assert prefix == "Raven B" and len(suffix) == 36
    assert out["config"] == {"host": "b.example.net", "port": 9102, "tls": True, "enabled": True,
                             "useToken": False, "tokenType": "manual", "token": None, "outgoing_uuid": None}
    assert fp.node_meta(out)["ca"] == OTHER["uid"]
    assert len(new["policy"]["rules"]) == 4
    entry = fp.find_entry(new, OWN["uid"], OTHER["uid"])
    assert entry["outgoing"] is out
    positions = [(n["x"], n["y"]) for n in new["views"]["graph"]["nodes"]]
    assert len(set(positions)) == len(positions) == 3


def test_add_partner_adds_missing_own_node_and_handles_empty_view_dict():
    policy = fp.empty_policy("Tak")
    policy["views"]["graph"]["nodes"] = {}
    new, _ = fp.add_partner(policy, OWN, name="X", kind="other", direction="they_dial", ca_uid=tak_uid())
    assert fp.own_node(new, OWN["uid"])
    assert len(new["views"]["graph"]["nodes"]) == 2


def test_remove_partner_drops_nodes_rules_and_positions():
    new, uid = fp.remove_partner(live_policy(), OWN["uid"], OTHER["uid"])
    assert uid == OTHER["uid"]
    ids = {e["id"] for e in new["policy"]["entities"]}
    assert ids == {"own-node", "vpn-out"}
    assert all("vpn-node" not in (r["source"], r["destination"]) for r in new["policy"]["rules"])
    assert "vpn-node" not in {n["id"] for n in new["views"]["graph"]["nodes"]}
    assert not fp.ca_referenced(new, OTHER["uid"])
    with pytest.raises(fp.PartnerError) as e:
        fp.remove_partner(live_policy(), OWN["uid"], "nope")
    assert e.value.code == "not_found"


def test_live_policy_partners():
    entries = fp.partner_entries(live_policy(), OWN["uid"])
    # The native-console outgoing has no Raven link to a CA, so it's a partner of its own
    assert [e["id"] for e in entries] == [OTHER["uid"], "VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5"]


def test_description_metadata_keeps_a_typed_note():
    node = {"description": "set up by Bob"}
    fp.set_node_meta(node, kind="other")
    assert json.loads(node["description"]) == {"note": "set up by Bob", "raven": {"kind": "other"}}
    fp.set_node_meta(node, ca="x")
    assert fp.node_meta(node) == {"kind": "other", "ca": "x"}


@pytest.mark.parametrize("host", ["tak.example.net", "192.0.2.1", "[2001:db8::1]", "a-b.c"])
def test_valid_hosts(host):
    assert fp.validate_host(host)


@pytest.mark.parametrize("host", ["", "https://x.net", "x.net:9102", "a b", "x.net/path", "-bad.net"])
def test_invalid_hosts(host):
    with pytest.raises(fp.PartnerError) as e:
        fp.validate_host(host)
    assert e.value.code == "invalid_host"


@pytest.mark.parametrize("port", [0, 65536, "abc", None, True])
def test_invalid_ports(port):
    with pytest.raises(fp.PartnerError):
        fp.validate_port(port)


def test_filters():
    assert fp.validate_filter(None, "share") == fp.ALL_GROUPS
    assert fp.validate_filter('{"type":"allowed","allowed":["a"," a ","b"]}', "share") == {
        "type": "allowed", "allowed": ["a", "b"], "disallowed": []}
    for bad in ('{"type":"allowed"}', '{"type":"x"}', "not json", '{"type":"disallowed","disallowed":[1]}'):
        with pytest.raises(fp.PartnerError) as e:
            fp.validate_filter(bad, "share")
        assert e.value.code == "invalid_filter"


def test_parse_ca_file_rejects_bundles_and_garbage():
    with pytest.raises(fp.PartnerError) as e:
        fp.parse_ca_file(TAK_PEM + OTHER_PEM)
    assert e.value.code == "multiple_certs"
    with pytest.raises(fp.PartnerError) as e:
        fp.parse_ca_file(b"hello")
    assert e.value.code == "invalid_ca"
    with pytest.raises(fp.PartnerError):
        fp.parse_ca_file(b"x" * (fp.MAX_CA_BYTES + 1))
    der = x509.load_pem_x509_certificate(TAK_PEM).public_bytes(Encoding.DER)
    info = fp.parse_ca_file(der)
    assert info["sha256"] == hashlib.sha256(der).hexdigest()
    assert info["uid"] == f"{info['subject']}-{info['sha256']}"
    assert info["is_ca"] is True
    assert info["subject"].startswith("CN=TAK-ROOT-CA,")


def test_parse_ca_file_malformed_extension():
    from cryptography.x509.oid import ExtensionOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Broken CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.UnrecognizedExtension(ExtensionOID.BASIC_CONSTRAINTS, b"\x05\x00garbage"), critical=True)
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(fp.PartnerError) as e:
        fp.parse_ca_file(cert.public_bytes(Encoding.PEM))
    assert e.value.code == "bad_certificate" and e.value.status == 400


def test_policy_lock_busy():
    with fp.policy_lock():
        result = []

        def other():
            try:
                with fp.policy_lock(timeout=0.01):
                    result.append("got it")
            except fp.PartnerError as e:
                result.append(e.code)

        t = threading.Thread(target=other)
        t.start()
        t.join()
    assert result == ["busy"]


# --- create ---------------------------------------------------------------------------


def test_create_they_dial(app, admin, hub):
    r = post_partner(admin, interconnected="true")
    assert r.status_code == 201, r.json
    p = r.json
    assert p["id"] == tak_uid()
    assert p["name"] == "TAK X"
    assert p["kind"] == "tak_server"
    assert p["direction"] == "they_dial"
    assert p["outgoing"] is None
    assert p["interconnected"] is True
    assert p["ca"]["sha256"] == fp.parse_ca_file(TAK_PEM)["sha256"]
    assert p["ca"]["nickname"] == "TAK X"
    assert p["ca"]["expires"]
    assert p["share"] == p["receive"] == {"type": "allGroups", "allowed": [], "disallowed": []}
    assert p["status"] == "waiting"
    assert p["problems"] == []
    assert p["traffic"] == {"msgs_out": 0, "msgs_in": 0, "bytes_out": 0, "bytes_in": 0}
    # CA uploaded, then the policy saved, then activated
    order = hub.paths("POST /addNewGroupCa", "POST /saveFederationPolicy", "GET /activateFederationPolicy")
    assert order == ["POST /addNewGroupCa", "POST /saveFederationPolicy", "GET /activateFederationPolicy/Tak"]
    assert fp.group_nodes(hub.active, tak_uid())
    # untouched parts of the live policy survive the round trip
    assert hub.active["plugins"] == live_policy()["plugins"]
    assert hub.active["policy"]["groupSets"] == live_policy()["policy"]["groupSets"]
    rows = audit_rows(app)
    assert rows[-1][0] == "create_partner" and rows[-1][1].startswith("Connected federation server")


def test_create_we_dial(admin, hub):
    r = post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    assert r.status_code == 201, r.json
    p = r.json
    assert p["direction"] == "we_dial"
    assert p["outgoing"]["host"] == "tak.partner.example"
    assert p["outgoing"]["port"] == 9001
    assert p["outgoing"]["name"].startswith("TAK X_")
    assert p["id"] == tak_uid()


def test_create_validation(admin, hub):
    r = post_partner(admin, direction="we_dial", host="https://x.net")
    assert r.status_code == 400 and r.json["code"] == "invalid_host"
    assert r.json["success"] is False and r.json["error"]
    r = post_partner(admin, pem=None)
    assert r.json["code"] == "invalid_ca"
    r = post_partner(admin, name="")
    assert r.json["code"] == "invalid_name"
    assert not hub.paths("POST /addNewGroupCa")


def test_create_duplicate_ca(admin, hub):
    r = post_partner(admin, pem=OTHER_PEM)
    assert r.status_code == 409
    assert r.json["code"] == "ca_exists"
    assert r.json["existing_partner_id"] == OTHER["uid"]
    r = post_partner(admin, pem=OWN_PEM)
    assert r.status_code == 409 and r.json["code"] == "own_ca"
    assert not hub.paths("POST /saveFederationPolicy")


def test_create_reuses_trusted_ca_not_in_policy(admin, hub):
    hub.cas.append(ca_record(TAK_PEM, "old name"))
    r = post_partner(admin)
    assert r.status_code == 201
    assert not hub.paths("POST /addNewGroupCa")
    assert r.json["ca"]["nickname"] == "TAK X"


def test_create_with_ca_uid_for_any_kind(admin, hub):
    hub.cas.append(ca_record(TAK_PEM, "TAK X"))
    r = post_partner(admin, pem=None, kind="other", ca_uid=tak_uid())
    assert r.status_code == 201, r.json
    assert r.json["id"] == tak_uid() and r.json["kind"] == "other"
    assert not hub.paths("POST /addNewGroupCa")
    r = post_partner(admin, pem=None, ca_uid="CN=Nobody-00")
    assert r.status_code == 404 and r.json["code"] == "ca_not_found"


def test_create_duplicate_outgoing(admin, hub):
    r = post_partner(admin, direction="we_dial", host="192.0.2.37", port="9102")
    assert r.status_code == 409
    assert r.json["code"] == "outgoing_exists"
    assert r.json["existing_partner_id"] == "VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5"


def test_create_we_dial_when_they_already_dial(admin, hub):
    hub.cas.append(ca_record(TAK_PEM, "TAK X"))
    hub.connections = [dict(OTHER_HUB_CONN, groupIdentities=[tak_uid()])]
    r = post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    assert r.status_code == 409 and r.json["code"] == "they_already_dial"


def test_create_rolls_back_when_activate_fails(admin, hub):
    before = copy.deepcopy(hub.active)
    hub.fail_once["GET /activateFederationPolicy"] = 500
    r = post_partner(admin)
    assert r.status_code == 502
    assert r.json["code"] == "hub_error"
    assert not fp.find_ca(hub.cas, uid=tak_uid())  # the CA this request added is gone again
    assert hub.policies["Tak"] == fp.prepare_for_save(before)  # previous policy saved back
    assert hub.paths("DELETE /deleteGroupCa/")


def test_create_rolls_back_when_not_confirmed(admin, hub, monkeypatch):
    # The hub says OK but keeps enforcing the old graph
    original = hub.route

    def stale(method, path, kwargs):
        if path.startswith("/activateFederationPolicy/"):
            return FakeResponse(200)
        return original(method, path, kwargs)

    monkeypatch.setattr(hub, "route", stale)
    r = post_partner(admin)
    assert r.status_code == 502 and r.json["code"] == "not_applied"
    assert not fp.find_ca(hub.cas, uid=tak_uid())


def test_create_with_no_active_policy(admin, hub):
    hub.active = None
    hub.policies = {}
    r = post_partner(admin)
    assert r.status_code == 201, r.json
    assert hub.active["name"] == fp.DEFAULT_POLICY_NAME
    assert fp.own_node(hub.active, OWN["uid"])


def test_no_active_policy_but_stored_ones_refuses(admin, hub):
    hub.active = None  # "Tak" is still stored
    for r in (post_partner(admin), admin.post("/api/fedhub/repair")):
        assert r.status_code == 409
        assert r.json["code"] == "no_active_policy"
        assert r.json["stored_policies"] == ["Tak"]
    assert not hub.paths("POST /addNewGroupCa", "POST /saveFederationPolicy", "GET /activateFederationPolicy")


def test_unique_policy_name():
    assert fp.unique_policy_name([]) == "C4Raven"
    assert fp.unique_policy_name(["C4Raven", "C4Raven-2"]) == "C4Raven-3"


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(400, NO_POLICY_TEXT, "text/plain"),  # right text, wrong status
        FakeResponse(500, NO_POLICY_TEXT, "text/plain"),
        FakeResponse(404, "Not Found", "text/plain"),
        FakeResponse(401, "", "text/plain"),
        FakeResponse(200, "<html>proxy error</html>", "text/html"),
        FakeResponse(200, {"version": "v3"}),  # no name
        FakeResponse(200, b""),
    ],
)
def test_unexpected_active_policy_answer_aborts_before_writing(admin, hub, monkeypatch, response):
    original = hub.route

    def odd(method, path, kwargs):
        return response if path == "/getActivePolicy" else original(method, path, kwargs)

    monkeypatch.setattr(hub, "route", odd)
    for r in (post_partner(admin), admin.post("/api/fedhub/repair")):
        assert r.status_code == 502, r.json
        assert r.json["code"] == "hub_error"
    assert not hub.paths("POST /addNewGroupCa", "POST /saveFederationPolicy", "GET /activateFederationPolicy",
                         "DELETE /deleteGroupCa")
    with pytest.raises(fp.HubError):
        fp.HubClient(hub).active_policy()


def test_no_previous_policy_confirm_failure_keeps_ca(admin, hub, monkeypatch):
    hub.active = None
    hub.policies = {}
    original = hub.route

    def stale(method, path, kwargs):
        if path.startswith("/activateFederationPolicy/"):
            return FakeResponse(200)  # says yes, enforces nothing
        return original(method, path, kwargs)

    monkeypatch.setattr(hub, "route", stale)
    r = post_partner(admin)
    assert r.status_code == 500
    assert r.json["code"] == "partially_applied"
    assert "left in place" in r.json["error"]
    assert fp.find_ca(hub.cas, uid=tak_uid())  # the stored policy still references it
    assert not hub.paths("DELETE /deleteGroupCa/")


def test_failed_restore_keeps_ca_and_reports_half_changed(admin, hub):
    hub.fail["GET /activateFederationPolicy"] = 500  # the new one AND the restore fail
    r = post_partner(admin)
    assert r.status_code == 500
    assert r.json["code"] == "rollback_failed"
    assert "half-changed" in r.json["error"] and "Advanced" in r.json["error"]
    assert fp.find_ca(hub.cas, uid=tak_uid())
    assert not hub.paths("DELETE /deleteGroupCa/")


# --- update / delete ----------------------------------------------------------------------


def test_rename_updates_ca_nickname_nodes_and_rules(admin, hub):
    r = admin.patch(f"/api/fedhub/partners/{OTHER['uid']}", json={"name": "Raven B"})
    assert r.status_code == 200, r.json
    assert r.json["name"] == "Raven B"
    assert fp.find_ca(hub.cas, uid=OTHER["uid"])["nickname"] == "Raven B"
    node = fp.group_nodes(hub.active, OTHER["uid"])[0]
    assert node["displayName"] == "Raven B"
    names = {r["name"] for r in hub.active["policy"]["rules"]}
    assert "Pubserver -> Raven B" in names and "Raven B -> VPN Server" in names
    assert "Pubserver -> VPN" not in names


def test_patch_share_enabled_and_interconnected(admin, hub):
    r = admin.patch(
        f"/api/fedhub/partners/{OTHER['uid']}",
        json={"share": {"type": "allowed", "allowed": ["Ops"]}, "enabled": False, "interconnected": False},
    )
    assert r.status_code == 200, r.json
    p = r.json
    assert p["share"] == {"type": "allowed", "allowed": ["Ops"], "disallowed": []}
    assert p["enabled"] is False and p["status"] == "disabled"
    assert p["interconnected"] is False
    assert "filter_not_all_groups" in p["problems"]


def test_patch_direction_round_trip(admin, hub):
    uid = OTHER["uid"]
    r = admin.patch(f"/api/fedhub/partners/{uid}", json={"direction": "we_dial", "host": "b.example.net"})
    assert r.status_code == 200, r.json
    assert r.json["direction"] == "we_dial"
    assert r.json["outgoing"]["port"] == 9102
    r = admin.patch(f"/api/fedhub/partners/{uid}", json={"host": "c.example.net", "port": 9200})
    assert r.json["outgoing"]["host"] == "c.example.net" and r.json["outgoing"]["port"] == 9200
    r = admin.patch(f"/api/fedhub/partners/{uid}", json={"direction": "they_dial"})
    assert r.json["direction"] == "they_dial" and r.json["outgoing"] is None
    assert len([e for e in hub.active["policy"]["entities"] if e["type"] == "FederationOutgoing"]) == 1


def test_patch_errors(admin, hub):
    assert admin.patch("/api/fedhub/partners/nope", json={"name": "x"}).status_code == 404
    r = admin.patch(f"/api/fedhub/partners/{OTHER['uid']}", json={})
    assert r.json["code"] == "nothing_to_change"
    r = admin.patch(f"/api/fedhub/partners/{OTHER['uid']}", json={"port": 0})
    assert r.json["code"] == "invalid_port"


def test_patch_rolls_back_nickname(admin, hub):
    hub.fail_once["POST /saveFederationPolicy"] = 500
    r = admin.patch(f"/api/fedhub/partners/{OTHER['uid']}", json={"name": "Raven B"})
    assert r.status_code == 502
    assert fp.find_ca(hub.cas, uid=OTHER["uid"])["nickname"] == "Pub Server"


def without_native_outgoing(hub):
    policy = live_policy()
    policy["policy"]["entities"] = [e for e in policy["policy"]["entities"] if e["id"] != "vpn-out"]
    policy["policy"]["rules"] = [r for r in policy["policy"]["rules"] if "vpn-out" not in (r["source"], r["destination"])]
    hub.active = copy.deepcopy(policy)
    hub.policies = {"Tak": copy.deepcopy(policy)}


def test_delete_removes_policy_before_ca(app, admin, hub):
    without_native_outgoing(hub)
    r = admin.delete(f"/api/fedhub/partners/{OTHER['uid']}")
    assert r.status_code == 200, r.json
    assert r.json == {"success": True, "id": OTHER["uid"], "ca_removed": True}
    calls = hub.paths("GET /activateFederationPolicy", "DELETE /deleteGroupCa")
    assert calls[0].startswith("GET /activateFederationPolicy") and calls[1].startswith("DELETE /deleteGroupCa/")
    assert not fp.group_nodes(hub.active, OTHER["uid"])
    assert not fp.find_ca(hub.cas, uid=OTHER["uid"])
    assert audit_rows(app)[-1][0] == "delete_partner"


def test_delete_keep_ca(admin, hub):
    r = admin.delete(f"/api/fedhub/partners/{OTHER['uid']}?keep_ca=1")
    assert r.json["ca_removed"] is False
    assert fp.find_ca(hub.cas, uid=OTHER["uid"])
    assert not hub.paths("DELETE /deleteGroupCa/")


def test_delete_keeps_ca_while_an_unlinked_outgoing_exists(admin, hub):
    # Live layout: the native-console outgoing "VPN Server" isn't linked to any CA
    r = admin.delete(f"/api/fedhub/partners/{OTHER['uid']}")
    assert r.status_code == 200
    assert r.json["ca_removed"] is False and "VPN Server" in r.json["warning"]
    assert fp.find_ca(hub.cas, uid=OTHER["uid"])
    assert not hub.paths("DELETE /deleteGroupCa/")


def test_delete_keeps_ca_still_used_in_active_policy(admin, hub):
    without_native_outgoing(hub)
    post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    # a second outgoing linked to the same CA stays behind
    policy = copy.deepcopy(hub.active)
    extra = fp.new_outgoing_node("TAK X backup", "tak2.partner.example", 9001, ca_uid=tak_uid())
    policy["policy"]["entities"].append(extra)
    hub.active = copy.deepcopy(policy)
    hub.policies["Tak"] = copy.deepcopy(policy)
    r = admin.delete(f"/api/fedhub/partners/{tak_uid()}")
    assert r.json["ca_removed"] is False and "active policy still uses it" in r.json["warning"]
    assert fp.find_ca(hub.cas, uid=tak_uid())


def test_delete_escapes_ca_uid(admin, hub):
    without_native_outgoing(hub)
    admin.delete(f"/api/fedhub/partners/{OTHER['uid']}")
    from urllib.parse import quote

    assert hub.paths("DELETE /deleteGroupCa/") == [f"DELETE /deleteGroupCa/{quote(OTHER['uid'], safe='')}"]
    assert "," not in hub.paths("DELETE /deleteGroupCa/")[0]


def test_delete_keeps_ca_used_by_another_policy(admin, hub):
    without_native_outgoing(hub)
    hub.policies["Spare"] = dict(live_policy(), name="Spare")
    r = admin.delete(f"/api/fedhub/partners/{OTHER['uid']}")
    assert r.json["ca_removed"] is False and "Spare" in r.json["warning"]


def test_delete_outgoing_only_partner(admin, hub):
    pid = "VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5"
    r = admin.delete(f"/api/fedhub/partners/{pid}")
    assert r.status_code == 200 and r.json["ca_removed"] is False
    assert "vpn-out" not in fp.entity_ids(hub.active)


def test_delete_activate_failure_keeps_ca(admin, hub):
    hub.fail_once["GET /activateFederationPolicy"] = 500
    r = admin.delete(f"/api/fedhub/partners/{OTHER['uid']}")
    assert r.status_code == 502
    assert fp.find_ca(hub.cas, uid=OTHER["uid"])
    assert not hub.paths("DELETE /deleteGroupCa/")


# --- check / reconnect ------------------------------------------------------------------


def test_check_codes_and_order(admin, hub, monkeypatch):
    post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    r = admin.get(f"/api/fedhub/partners/{tak_uid()}/check")
    assert r.status_code == 200, r.json
    codes = [c["code"] for c in r.json]
    assert codes == ["ca_trusted", "ca_in_policy", "rules_out", "rules_in", "filter_compatible",
                     "dial_direction", "dns", "tcp", "connected", "traffic_flowing", "ca_expiry"]
    by = {c["code"]: c for c in r.json}
    assert all(by[c]["ok"] for c in ("ca_trusted", "ca_in_policy", "rules_out", "rules_in",
                                     "filter_compatible", "dial_direction", "dns", "tcp", "ca_expiry"))
    assert by["connected"]["ok"] is False and by["connected"]["fix"]
    assert by["traffic_flowing"]["level"] == "warning"

    # both sides dial + DNS failure
    hub.connections = [dict(OTHER_HUB_CONN, groupIdentities=[tak_uid()])]
    monkeypatch.setattr(fp, "resolve", lambda host: (False, [], "Name or service not known"))
    by = {c["code"]: c for c in admin.get(f"/api/fedhub/partners/{tak_uid()}/check").json}
    assert by["dial_direction"]["ok"] is False and by["dial_direction"]["level"] == "error"
    assert by["dns"]["ok"] is False and "Name or service not known" in by["dns"]["detail"]
    assert by["tcp"]["ok"] is False


def test_check_they_dial_skips_network(admin, hub):
    r = admin.get(f"/api/fedhub/partners/{OTHER['uid']}/check")
    by = {c["code"]: c for c in r.json}
    assert by["dns"]["level"] == by["tcp"]["level"] == "skipped"
    assert by["ca_expiry"]["level"] == "skipped"  # not uploaded through Raven: expiry unknown
    assert admin.get("/api/fedhub/partners/nope/check").status_code == 404


def test_check_flags_filters(admin, hub):
    admin.patch(f"/api/fedhub/partners/{OTHER['uid']}", json={"share": {"type": "disallowed", "disallowed": ["x"]}})
    by = {c["code"]: c for c in admin.get(f"/api/fedhub/partners/{OTHER['uid']}/check").json}
    assert by["filter_compatible"]["ok"] is False and by["filter_compatible"]["level"] == "warning"


def test_reconnect(admin, hub):
    hub.connections = [BRIDGE_CONN, OTHER_HUB_CONN]
    r = admin.post(f"/api/fedhub/partners/{OTHER['uid']}/reconnect")
    assert r.json == {"success": True, "disconnected": 1}
    assert hub.connections == [BRIDGE_CONN]
    # "Pub server_..." has a space: escaped as one path segment
    assert hub.paths("DELETE /disconnectFederate/Pub%20server_")


def test_activate_escapes_policy_name(admin, hub):
    policy = dict(live_policy(), name="My/Policy, v2")
    hub.active = copy.deepcopy(policy)
    hub.policies = {policy["name"]: copy.deepcopy(policy)}
    r = admin.patch(f"/api/fedhub/partners/{OTHER['uid']}", json={"enabled": False})
    assert r.status_code == 200, r.json
    assert hub.paths("GET /activateFederationPolicy/My%2FPolicy%2C%20v2")


def test_legacy_proxy_routes_escape_segments(admin, hub):
    admin.delete("/api/fedhub/ca_groups/CN=a b,O=x&y")
    admin.post("/api/fedhub/federations/a b/activate")  # looked up first, then activated
    admin.get("/api/fedhub/federations/a&b")
    admin.delete("/api/fedhub/connections/x y")
    assert hub.paths("DELETE /deleteGroupCa/CN%3Da%20b%2CO%3Dx%26y")
    assert hub.paths("GET /federation/a%20b")
    assert hub.paths("GET /federation/a%26b")
    assert hub.paths("DELETE /disconnectFederate/x%20y")


# --- overview / repair ----------------------------------------------------------------------


def test_overview_attributes_connections_and_metrics(admin, hub):
    stray = dict(OTHER_HUB_CONN, connectionId="stranger-1", groupIdentities=["CN=Unknown-abc"])
    hub.connections = [BRIDGE_CONN, OTHER_HUB_CONN, stray]
    hub.metrics = live_metrics()
    r = admin.get("/api/fedhub/overview")
    assert r.status_code == 200
    o = r.json
    assert o["hub"] == {"reachable": True, "active_policy": "Tak", "broker_id": "broker-1",
                        "v2_port": 9102, "host": "tak.example.net"}
    assert o["own"]["uid"] == OWN["uid"] and o["own"]["connected"] is True
    assert o["own"]["sha256"] == OWN["alias"]
    assert o["bridge"] == {"enabled": True, "service_state": "active"}
    assert o["problems"] == []
    assert [c["connectionId"] for c in o["unattributed_connections"]] == ["stranger-1"]
    vpn, out = o["partners"]
    assert vpn["id"] == OTHER["uid"] and vpn["name"] == "Pub Server"
    assert vpn["status"] == "connected"
    assert vpn["interconnected"] is True
    assert [c["connectionId"] for c in vpn["connections"]] == [OTHER_HUB_CONN["connectionId"]]
    assert vpn["traffic"] == {"msgs_out": 101, "msgs_in": 223, "bytes_out": 54284, "bytes_in": 145315}
    assert out["direction"] == "we_dial" and out["ca"] is None
    # G6, live layout: the native outgoing "VPN Server" dials while hub "VPN" dials in
    assert "both_sides_dial" in vpn["problems"] and "both_sides_dial" in out["problems"]
    assert out["status"] == "error"
    assert out["outgoing"] == {"name": "VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5",
                               "host": "192.0.2.37", "port": 9102, "enabled": True}


def test_overview_flags_both_sides_dialing(admin, hub):
    post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    hub.connections = [dict(OTHER_HUB_CONN, groupIdentities=[tak_uid()])]
    p = [p for p in admin.get("/api/fedhub/overview").json["partners"] if p["id"] == tak_uid()][0]
    assert "both_sides_dial" in p["problems"]


def test_overview_no_dial_conflict_without_incoming_hub(admin, hub):
    hub.connections = [BRIDGE_CONN, dict(OTHER_HUB_CONN, remoteConnectionType="FEDERATION_HUB_SERVER")]
    partners = admin.get("/api/fedhub/overview").json["partners"]
    assert all("both_sides_dial" not in p["problems"] for p in partners)


def test_check_flags_native_outgoing_and_incoming_hub(admin, hub):
    hub.connections = [OTHER_HUB_CONN]
    pid = "VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5"
    for partner_id in (pid, OTHER["uid"]):
        by = {c["code"]: c for c in admin.get(f"/api/fedhub/partners/{partner_id}/check").json}
        assert by["dial_direction"]["ok"] is False, partner_id


def test_overview_hub_down(admin, hub):
    hub.down = True
    o = admin.get("/api/fedhub/overview").json
    assert o["hub"]["reachable"] is False
    assert o["problems"] == ["hub_unreachable"]
    assert o["partners"] == []


def test_overview_own_ca_missing_and_repair(app, admin, hub):
    policy = live_policy()
    policy["policy"]["entities"] = [e for e in policy["policy"]["entities"] if e["id"] != "own-node"]
    hub.active = copy.deepcopy(policy)
    hub.policies["Tak"] = copy.deepcopy(policy)
    o = admin.get("/api/fedhub/overview").json
    assert "own_ca_missing" in o["problems"]
    assert "no_rule_out" in o["partners"][0]["problems"]
    assert o["partners"][0]["status"] == "error"

    r = admin.post("/api/fedhub/repair")
    assert r.json == {"success": True, "changed": True, "policy": "Tak"}
    assert fp.own_node(hub.active, OWN["uid"])
    assert len(hub.active["policy"]["entities"]) == 3  # nothing else added
    assert "own_ca_missing" not in admin.get("/api/fedhub/overview").json["problems"]
    assert admin.post("/api/fedhub/repair").json == {"success": True, "changed": False}
    assert audit_rows(app)[-1][0] == "repair_policy"


def test_overview_no_active_policy(admin, hub):
    hub.active = None
    o = admin.get("/api/fedhub/overview").json
    assert o["hub"]["active_policy"] is None
    assert "no_active_policy" in o["problems"] and "own_ca_missing" in o["problems"]


# --- wizard helpers -------------------------------------------------------------------


def test_ca_inspect(admin, hub):
    import io

    r = admin.post("/api/fedhub/ca_inspect", data={"file": (io.BytesIO(OTHER_PEM), "x.pem")},
                   content_type="multipart/form-data")
    assert r.status_code == 200
    j = r.json
    assert j["sha256"] == OTHER["alias"]
    assert j["uid"] == OTHER["uid"]
    assert j["already_trusted"] is True and j["existing_partner_id"] == OTHER["uid"]
    assert j["is_ca"] is True and j["days_left"] > 3000
    r = admin.post("/api/fedhub/ca_inspect", data={"file": (io.BytesIO(TAK_PEM), "x.pem")},
                   content_type="multipart/form-data")
    assert r.json["already_trusted"] is False and r.json["existing_partner_id"] is None
    assert not hub.paths("POST /addNewGroupCa")


def test_reachability(admin, hub, monkeypatch):
    r = admin.post("/api/fedhub/reachability", json={"host": "tak.partner.example", "port": 9001})
    assert r.json == {"dns_ok": True, "addresses": ["192.0.2.10"], "tcp_ok": True, "error": None,
                      "host": "tak.partner.example", "port": 9001}
    monkeypatch.setattr(fp, "tcp_connect", lambda host, port, timeout=3: (False, "timed out"))
    assert admin.post("/api/fedhub/reachability", json={"host": "x.net", "port": 9}).json["tcp_ok"] is False
    r = admin.post("/api/fedhub/reachability", json={"host": "x y", "port": 9})
    assert r.status_code == 400 and r.json["code"] == "invalid_host"


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "ff02::1", "0.0.0.0", "::1", "fe80::1"])
def test_reachability_rejects_local_addresses(admin, hub, host):
    r = admin.post("/api/fedhub/reachability", json={"host": host, "port": 9102})
    assert r.status_code == 400 and r.json["code"] == "address_not_allowed"


def test_reachability_rejects_names_resolving_locally(admin, hub, monkeypatch):
    calls = []
    monkeypatch.setattr(fp, "resolve", lambda host: (True, ["127.0.0.1"], None))
    monkeypatch.setattr(fp, "tcp_connect", lambda host, port, timeout=3: calls.append(host) or (True, None))
    r = admin.post("/api/fedhub/reachability", json={"host": "evil.example", "port": 22})
    assert r.status_code == 400 and r.json["code"] == "address_not_allowed"
    assert calls == []


def test_reachability_allows_private_and_connects_to_resolved_address(admin, hub, monkeypatch):
    calls = []
    monkeypatch.setattr(fp, "resolve", lambda host: (True, ["10.0.0.5"], None))
    monkeypatch.setattr(fp, "tcp_connect", lambda host, port, timeout=3: calls.append((host, port)) or (True, None))
    r = admin.post("/api/fedhub/reachability", json={"host": "lan.example", "port": 9102})
    assert r.json["tcp_ok"] is True
    assert calls == [("10.0.0.5", 9102)]
    assert admin.post("/api/fedhub/reachability", json={"host": "192.168.1.9", "port": 70000}).json["code"] == "invalid_port"


def test_check_refuses_tcp_to_loopback(admin, hub, monkeypatch):
    post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    monkeypatch.setattr(fp, "resolve", lambda host: (True, ["127.0.0.1"], None))
    monkeypatch.setattr(fp, "tcp_connect", lambda *a, **k: pytest.fail("must not connect"))
    by = {c["code"]: c for c in admin.get(f"/api/fedhub/partners/{tak_uid()}/check").json}
    assert by["dns"]["ok"] is True and by["tcp"]["ok"] is False


def test_probe_rejects_bad_port_from_policy():
    result = fp.probe("192.0.2.1", 0, resolver=lambda h: pytest.fail("no dns"), connector=None)
    assert result["tcp_ok"] is False and result["error"]


def test_reachability_real_functions_locally():
    import socket

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        assert fp.tcp_connect("127.0.0.1", port) == (True, None)
    finally:
        server.close()


def test_handoff(admin, hub):
    j = admin.get("/api/fedhub/handoff").json
    assert j["sha256"] == OWN["alias"]
    assert j["host"] == "tak.example.net" and j["port"] == 9102
    assert j["ca_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert set(j["steps"]) == {"raven_hub", "tak_server", "other"}
    assert any("__ANON__" in s for s in j["steps"]["tak_server"])
    r = admin.get("/api/fedhub/handoff?format=txt&kind=tak_server")
    assert r.headers["Content-Type"].startswith("text/plain")
    assert "attachment" in r.headers["Content-Disposition"]
    text = r.get_data(as_text=True)
    assert "tak.example.net" in text and fp.fingerprint(OWN["alias"]) in text
    assert "If you run TAK Server" in text and "own Federation Hub" not in text


def test_handoff_prefers_configured_host(app, admin, hub):
    app.config["RAVEN_FEDHUB_HOST"] = "hub.example.org"
    assert admin.get("/api/fedhub/handoff").json["host"] == "hub.example.org"


def test_native_url(app, admin, hub):
    assert admin.get("/api/fedhub/native_url").json == {"url": "https://fed.example.net:9100"}
    app.config["RAVEN_FEDHUB_API_ADDRESS"] = "https://127.0.0.1:9100/api"
    assert admin.get("/api/fedhub/native_url").json == {"url": "https://tak.example.net:9100"}


def test_known_groups_export_tokens(admin, hub):
    assert admin.get("/api/fedhub/known_groups/own-node").json == []
    assert hub.paths("GET /getKnownGroupsForGraphNode/own-node")


def test_known_groups_by_partner_id(admin, hub, monkeypatch):
    post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    entry = fp.find_entry(hub.active, OWN["uid"], tak_uid())
    ca_id, out_id = entry["ca_node"]["id"], entry["outgoing"]["id"]
    original = hub.route

    def groups(method, path, kwargs):
        if path == f"/getKnownGroupsForGraphNode/{ca_id}":
            return FakeResponse(200, ["a", "b"])
        if path == f"/getKnownGroupsForGraphNode/{out_id}":
            return FakeResponse(200, ["b", "c"])
        return original(method, path, kwargs)

    monkeypatch.setattr(hub, "route", groups)
    from urllib.parse import quote

    r = admin.get(f"/api/fedhub/known_groups/{quote(tak_uid(), safe='')}")
    assert r.json == ["a", "b", "c"]
    assert admin.get(f"/api/fedhub/known_groups/{ca_id}").json == ["a", "b"]
    assert admin.get("/api/fedhub/known_groups/nope").status_code == 404
    r = admin.get("/api/fedhub/federations/Tak/export?format=json")
    assert r.status_code == 200 and json.loads(r.data)["name"] == "Tak"
    assert "Tak.json" in r.headers["Content-Disposition"]
    r = admin.get("/api/fedhub/federations/Tak/export?format=yaml")
    assert r.data == b"name: Tak\n"
    assert admin.get("/api/fedhub/federations/Tak/export?format=xml").json["code"] == "invalid_format"
    r = admin.post("/api/fedhub/tokens", json={"clientGroup": "tokens"})
    assert r.json["token"] and r.json["expiration"] == -1
    assert admin.post("/api/fedhub/tokens", json={}).json["code"] == "invalid_request"


# --- fixes on existing routes -------------------------------------------------------------


def test_policy_activate_refuses_policy_without_own_ca(admin, hub):
    policy = live_policy()
    policy["policy"]["entities"] = [e for e in policy["policy"]["entities"] if e["id"] != "own-node"]
    r = admin.post("/api/fedhub/policy?activate=1", json=policy)
    assert r.status_code == 400 and r.json["code"] == "own_ca_missing_from_policy"
    assert not hub.paths("POST /saveFederationPolicy")
    r = admin.post("/api/fedhub/policy?activate=1&force_without_own_ca=1", json=policy)
    assert r.status_code == 200, r.json
    assert not fp.own_node(hub.active, OWN["uid"])


def test_policy_activate_rolls_back(admin, hub):
    before = copy.deepcopy(hub.active)
    policy = live_policy()
    policy["policy"]["entities"].append(fp.new_group_node(tak_uid(), "TAK X"))
    hub.fail_once["GET /activateFederationPolicy"] = 500
    r = admin.post("/api/fedhub/policy?activate=1", json=policy)
    assert r.status_code == 502 and r.json["code"] == "hub_error"
    assert hub.policies["Tak"] == fp.prepare_for_save(before)
    assert hub.active == before


def test_policy_save_and_activate(admin, hub):
    policy = live_policy()
    policy["description"] = "edited"
    r = admin.post("/api/fedhub/policy?activate=1", json=policy)
    assert r.json == {"success": True, "activated": True, "name": "Tak"}
    assert hub.active["description"] == "edited"
    hub.calls.clear()
    admin.post("/api/fedhub/policy", json=policy)
    assert not hub.paths("GET /activateFederationPolicy")


def test_timeouts_are_504(admin, hub):
    hub.timeout = True
    for path in ("/api/fedhub/metrics", "/api/fedhub/config", "/api/fedhub/ca_self", "/api/fedhub/connections"):
        r = admin.get(path)
        assert r.status_code == 504, path
    r = post_partner(admin)
    assert r.status_code == 504 and r.json["code"] == "hub_timeout"


def test_admin_cert_gets_are_audited(app, admin, hub, tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("secret-pass\n")
    app.config["RAVEN_FEDHUB_ADMIN_P12_PASSWORD_FILE"] = str(pw)
    with admin.session_transaction() as session:
        session["fedhub_cert_2fa_verified_at"] = time.time() - 200  # inside the 300 s window
    assert admin.get("/api/fedhub/admin_cert/password").json == {"password": "secret-pass"}
    assert admin.get("/api/fedhub/admin_cert").status_code == 500  # no file here
    rows = audit_rows(app)
    assert rows[-2] == ("get_admin_cert_password", "Viewed federation admin certificate password", True)
    assert rows[-1][0] == "get_admin_cert" and rows[-1][2] is False
    with app.app_context():
        assert all("secret-pass" not in (e.details or "") for e in AuditEvent.query.all())


def test_new_labels_match_views():
    from raven.audit import ADMIN_ACTION_LABELS

    for view in ("create_partner", "update_partner", "delete_partner", "reconnect_partner",
                 "repair_policy", "inspect_ca", "generate_token", "check_reachability",
                 "get_admin_cert", "get_admin_cert_password"):
        assert callable(getattr(api, view)), view
        assert isinstance(ADMIN_ACTION_LABELS[view], str), view


# --- a disabled own-CA node counts as missing (G1) ------------------------------------------


def with_own_disabled(policy):
    policy = copy.deepcopy(policy)
    for entity in policy["policy"]["entities"]:
        if entity["id"] == "own-node":
            entity["config"]["enabled"] = False
    return policy


def test_disabled_own_node_counts_as_missing():
    assert fp.own_node(with_own_disabled(live_policy()), OWN["uid"])
    assert fp.own_node_enabled(with_own_disabled(live_policy()), OWN["uid"]) is None
    assert fp.own_node_enabled(live_policy(), OWN["uid"])["id"] == "own-node"


def test_policy_activate_refuses_disabled_own_node(admin, hub):
    policy = with_own_disabled(live_policy())
    r = admin.post("/api/fedhub/policy?activate=1", json=policy)
    assert r.status_code == 400 and r.json["code"] == "own_ca_missing_from_policy"
    assert not hub.paths("POST /saveFederationPolicy")
    r = admin.post("/api/fedhub/policy?activate=1&force_without_own_ca=1", json=policy)
    assert r.status_code == 200, r.json


def test_overview_and_repair_with_disabled_own_node(admin, hub):
    policy = with_own_disabled(live_policy())
    hub.active = copy.deepcopy(policy)
    hub.policies["Tak"] = copy.deepcopy(policy)
    assert "own_ca_missing" in admin.get("/api/fedhub/overview").json["problems"]

    r = admin.post("/api/fedhub/repair")
    assert r.json == {"success": True, "changed": True, "policy": "Tak"}
    own = fp.own_node(hub.active, OWN["uid"])
    assert own["id"] == "own-node" and own["config"]["enabled"] is True  # re-enabled, not duplicated
    assert len(fp.group_nodes(hub.active, OWN["uid"])) == 1
    assert "own_ca_missing" not in admin.get("/api/fedhub/overview").json["problems"]


def test_apply_policy_confirm_requires_enabled_own_node(hub, monkeypatch):
    original = hub.route

    def disables_own(method, path, kwargs):
        response = original(method, path, kwargs)
        if path.startswith("/activateFederationPolicy/") and hub.active:
            hub.active = with_own_disabled(hub.active)
        return response

    monkeypatch.setattr(hub, "route", disables_own)
    client = fp.HubClient(hub)
    previous = client.active_policy()
    with pytest.raises(fp.PartnerError) as e:
        fp.apply_policy(client, live_policy(), previous, own_uid=OWN["uid"])
    assert e.value.code == "not_applied"
    # without own_uid the old behaviour holds
    monkeypatch.setattr(hub, "route", original)
    assert fp.apply_policy(client, live_policy(), previous)["name"] == "Tak"


# --- handoff follows who connects (G6) ------------------------------------------------------


def handoff_steps(admin, query):
    r = admin.get(f"/api/fedhub/handoff?{query}")
    assert r.status_code == 200, r.json
    return r.json


def test_handoff_when_we_dial(admin, hub):
    j = handoff_steps(admin, "direction=we_dial")
    assert j["direction"] == "we_dial"
    raven = " ".join(j["steps"]["raven_hub"])
    assert '"They connect to us"' in raven and "add nothing outgoing" in raven
    assert '"We connect to them"' not in raven
    tak = " ".join(j["steps"]["tak_server"])
    assert "Don't add an Outgoing Connection" in tak and "port 9102" not in tak
    assert "Don't connect to us" in " ".join(j["steps"]["other"])


def test_handoff_when_they_dial(admin, hub):
    j = handoff_steps(admin, "direction=they_dial")
    raven = " ".join(j["steps"]["raven_hub"])
    assert '"We connect to them"' in raven and "tak.example.net:9102" in raven
    assert '"They connect to us"' not in raven
    tak = " ".join(j["steps"]["tak_server"])
    assert "Add an Outgoing Connection: address tak.example.net, port 9102" in tak
    assert "tak.example.net:9102" in " ".join(j["steps"]["other"])


def test_handoff_without_direction_asks_to_agree(admin, hub):
    j = handoff_steps(admin, "")
    assert j["direction"] is None
    for kind in ("raven_hub", "tak_server", "other"):
        text = " ".join(j["steps"][kind])
        assert "which ONE side connects" in text, kind
        assert "If you connect to us" in text and "If we connect to you" in text, kind
    txt = admin.get("/api/fedhub/handoff?format=txt").get_data(as_text=True)
    assert "which ONE side connects" in txt


def test_handoff_uses_partner_direction(admin, hub):
    post_partner(admin, direction="we_dial", host="tak.partner.example", port="9001")
    from urllib.parse import quote

    j = handoff_steps(admin, f"partner_id={quote(tak_uid(), safe='')}&direction=they_dial")
    assert j["direction"] == "we_dial"  # the partner's real setup wins
    assert list(j["steps"]) == ["tak_server"]
    assert "Don't add an Outgoing Connection" in " ".join(j["steps"]["tak_server"])
    assert admin.get("/api/fedhub/handoff?partner_id=nope").status_code == 404
    r = admin.get("/api/fedhub/handoff?direction=sideways")
    assert r.status_code == 400 and r.json["code"] == "invalid_direction"


def test_check_wording_says_partner(admin, hub):
    admin.patch(f"/api/fedhub/partners/{OTHER['uid']}", json={"enabled": False})
    by = {c["code"]: c for c in admin.get(f"/api/fedhub/partners/{OTHER['uid']}/check").json}
    assert by["ca_in_policy"]["detail"].startswith("This partner is disabled")
    assert by["ca_in_policy"]["fix"] == "Enable the partner"


def test_ca_in_policy_missing_node_wording():
    policy = minimal_policy()
    out = fp.new_outgoing_node("X", "x.example", 9102)
    policy["policy"]["entities"].append(out)
    entry = {"id": "x", "ca_uid": tak_uid(), "ca_node": None, "outgoing": out}
    partner = fp.build_partner(entry, policy, OWN["uid"], [OWN])
    checks = fp.build_checks(entry, partner, policy, OWN["uid"], [OWN], [],
                             resolver=lambda h: (True, ["192.0.2.1"], None),
                             connector=lambda h, p: (True, None))
    item = [c for c in checks if c["code"] == "ca_in_policy"][0]
    assert "isn't in the active policy" in item["detail"]
    # Repair only restores our own CA node, so it is not the fix for a partner's certificate
    assert item["fix"] == "Remove the partner and connect it again (its certificate is kept if still trusted)"
    assert "Repair" not in item["fix"]


def test_no_active_policy_text_points_to_policy_editor(admin, hub):
    hub.active = None
    r = admin.post("/api/fedhub/repair")
    assert "Advanced > Policy editor" in r.json["error"] and "Repair can't create one" in r.json["error"]


# --- re-review: legacy activate / CA delete, disabled outgoings, restore confirm, ids ---------


def test_legacy_activate_goes_through_apply_policy(admin, hub):
    spare = dict(live_policy(), name="Spare")
    hub.policies["Spare"] = copy.deepcopy(spare)
    r = admin.post("/api/fedhub/federations/Spare/activate")
    assert r.status_code == 200, r.json
    assert r.json == {"success": True, "activated": True, "name": "Spare"}
    assert hub.active["name"] == "Spare"


def test_legacy_activate_refuses_policy_without_enabled_own_ca(admin, hub):
    hub.policies["Bad"] = with_own_disabled(dict(live_policy(), name="Bad"))
    r = admin.post("/api/fedhub/federations/Bad/activate")
    assert r.status_code == 400 and r.json["code"] == "own_ca_missing_from_policy"
    assert hub.active["name"] == "Tak"
    assert not hub.paths("GET /activateFederationPolicy")
    r = admin.post("/api/fedhub/federations/Bad/activate?force_without_own_ca=1")
    assert r.status_code == 200 and hub.active["name"] == "Bad"
    assert admin.post("/api/fedhub/federations/Nope/activate").status_code in (404, 502)


def test_legacy_activate_rolls_back(admin, hub):
    before = copy.deepcopy(hub.active)
    hub.policies["Spare"] = dict(live_policy(), name="Spare")
    hub.fail_once["GET /activateFederationPolicy/Spare"] = 500
    r = admin.post("/api/fedhub/federations/Spare/activate")
    assert r.status_code == 502
    assert hub.active == before


def test_legacy_ca_delete_guards(admin, hub):
    from urllib.parse import quote

    r = admin.delete(f"/api/fedhub/ca_groups/{quote(OWN['uid'], safe='')}")
    assert r.status_code == 400 and r.json["code"] == "own_ca"
    r = admin.delete(f"/api/fedhub/ca_groups/{quote(OTHER['uid'], safe='')}")
    assert r.status_code == 409 and r.json["code"] == "ca_in_use" and r.json["nodes"] == ["VPN"]
    assert not hub.paths("DELETE /deleteGroupCa/")
    r = admin.delete(f"/api/fedhub/ca_groups/{quote(OTHER['uid'], safe='')}?force=1")
    assert r.status_code == 200 and not fp.find_ca(hub.cas, uid=OTHER["uid"])


def test_disabled_unlinked_outgoing_is_no_dial_conflict(admin, hub):
    policy = live_policy()
    for e in policy["policy"]["entities"]:
        if e["id"] == "vpn-out":
            e["config"]["enabled"] = False
    hub.active = copy.deepcopy(policy)
    hub.policies["Tak"] = copy.deepcopy(policy)
    hub.connections = [OTHER_HUB_CONN]
    partners = admin.get("/api/fedhub/overview").json["partners"]
    assert all("both_sides_dial" not in p["problems"] for p in partners)


def test_restore_is_confirmed_by_rereading(admin, hub, monkeypatch):
    original = hub.route

    # first activate (the new policy) fails; the restore "succeeds" but the hub keeps nothing
    state = {"n": 0}

    def flaky(method, path, kwargs):
        if path.startswith("/activateFederationPolicy/"):
            state["n"] += 1
            if state["n"] == 1:
                return FakeResponse(500, "boom", "text/plain")
            hub.active = with_own_disabled(fp.empty_policy("Other"))  # not what we restored
            return FakeResponse(200)
        return original(method, path, kwargs)

    monkeypatch.setattr(hub, "route", flaky)
    r = post_partner(admin)
    assert r.status_code == 500 and r.json["code"] == "rollback_failed"
    assert fp.find_ca(hub.cas, uid=tak_uid())  # kept
    assert not hub.paths("DELETE /deleteGroupCa/")


def test_timed_out_save_that_was_stored_keeps_ca(admin, hub, monkeypatch):
    hub.active = None
    hub.policies = {}
    original = hub.route

    def save_then_time_out(method, path, kwargs):
        if path == "/saveFederationPolicy":
            original(method, path, kwargs)  # the hub wrote it...
            raise requests.exceptions.Timeout("slow")  # ...but the answer never came
        return original(method, path, kwargs)

    monkeypatch.setattr(hub, "route", save_then_time_out)
    r = post_partner(admin)
    assert r.status_code == 500 and r.json["code"] == "partially_applied"
    assert fp.find_ca(hub.cas, uid=tak_uid())
    assert not hub.paths("DELETE /deleteGroupCa/")


def test_timed_out_save_that_wasnt_stored_removes_ca(admin, hub, monkeypatch):
    hub.active = None
    hub.policies = {}
    original = hub.route

    def time_out(method, path, kwargs):
        if path == "/saveFederationPolicy":
            raise requests.exceptions.Timeout("slow")
        return original(method, path, kwargs)

    monkeypatch.setattr(hub, "route", time_out)
    r = post_partner(admin)
    assert r.status_code == 504 and r.json["code"] == "hub_timeout"
    assert not fp.find_ca(hub.cas, uid=tak_uid())


def test_connection_ids_match_exactly():
    assert fp.connection_is("VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5-c0dc-6227-x",
                            "VPN Server_7399fa0c-cbaa-40b6-9c3c-3184959715e5")
    assert fp.connection_is(BRIDGE_CONN["connectionId"], "raven-federate")
    assert not fp.connection_is("VPN_1234-abc", "V")
    assert not fp.connection_is("raven-federate2-abc", "raven-federate")
    assert not fp.connection_is("", "x") and not fp.connection_is("x", None)


def test_short_outgoing_name_doesnt_capture_other_connections():
    policy = minimal_policy()
    short = fp.new_outgoing_node("V", "v.example", 9102)
    short["name"] = "V"  # a native-console node without the uuid suffix
    policy["policy"]["entities"].append(short)
    entries = fp.partner_entries(policy, OWN["uid"])
    conn = dict(OTHER_HUB_CONN, connectionId="VPN_7399fa0c-abc-def", groupIdentities=["CN=x-1"])
    by_partner, _, rest = fp.attribute_connections(entries, [conn], OWN["uid"], "raven-federate")
    assert by_partner["V"] == [] and rest == [conn]
