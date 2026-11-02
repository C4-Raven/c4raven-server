"""Mission (Data Sync) archive and KML export, layers, external data and feeds
(raven/mission_export.py, raven/blueprints/marti_api/mission_data_marti_api.py,
raven/blueprints/raven_api/mission_detail_api.py).

Minimal sqlite Flask app, as in tests/test_group_policies.py: no RabbitMQ, Postgres or scheduler.
Mission tokens are signed with a throwaway RSA key written where verify_token() looks for it.
"""

import datetime
import io
import time
import zipfile
from xml.etree.ElementTree import fromstring

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven.audit import init_audit  # noqa: E402
from raven.blueprints.marti_api import mission_data_marti_api  # noqa: E402
from raven.blueprints.marti_api.mission_marti_api import mission_marti_api  # noqa: E402
from raven.blueprints.raven_api.mission_api import data_sync_api  # noqa: E402
from raven.models.AuditEvent import AuditEvent  # noqa: E402
from raven.models.CoT import CoT  # noqa: E402
from raven.models.Group import Group  # noqa: E402
from raven.models.GroupMission import GroupMission  # noqa: E402
from raven.models.GroupUser import GroupUser  # noqa: E402
from raven.models.Mission import Mission  # noqa: E402
from raven.models.MissionChange import MissionChange  # noqa: E402
from raven.models.MissionContent import MissionContent  # noqa: E402
from raven.models.MissionContentMission import MissionContentMission  # noqa: E402
from raven.models.MissionLayer import MissionLayer  # noqa: E402
from raven.models.MissionRole import MissionRole  # noqa: E402
from raven.models.MissionUID import MissionUID  # noqa: E402

KML = "{http://www.opengis.net/kml/2.2}"
MISSION = "op alpha"
GUID = "5b8f0d3e-0000-4000-8000-000000000001"
OWNER, SUBSCRIBER, READER = "ANDROID-owner", "ANDROID-sub", "ANDROID-ro"

POINT_COT = (
    '<event version="2.0" uid="marker-1" type="a-u-G" how="h-g-i-g-o" time="2026-11-01T10:00:00Z" '
    'start="2026-11-01T10:00:00Z" stale="2026-11-02T10:00:00Z"><point lat="51.5" lon="-0.12" '
    'hae="9999999.0" ce="9999999" le="9999999"/><detail><contact callsign="Rally &amp; Point"/>'
    '<color argb="-65536"/><remarks>meet here</remarks></detail></event>'
)
SHAPE_COT = (
    '<event version="2.0" uid="shape-1" type="u-d-f" how="h-e" time="2026-11-01T10:00:00Z" '
    'start="2026-11-01T10:00:00Z" stale="2026-11-02T10:00:00Z"><point lat="51.0" lon="0.0" hae="0" '
    'ce="9999999" le="9999999"/><detail><contact callsign="Area"/><link point="51.0,0.0"/>'
    '<link point="51.1,0.0"/><link point="51.1,0.1"/><link point="51.0,0.0"/></detail></event>'
)


@pytest.fixture
def app(tmp_path, monkeypatch):
    ca = tmp_path / "ca"
    (ca / "certs" / "raven").mkdir(parents=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (ca / "certs" / "raven" / "raven.nopass.key").write_bytes(private_pem)
    (ca / "certs" / "raven" / "raven.pub").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    (tmp_path / "missions").mkdir()

    app = Flask("raven-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
        RAVEN_CA_FOLDER=str(ca),
        UPLOAD_FOLDER=str(uploads),
        RAVEN_NODE_ID="node-1",
        RAVEN_ENABLE_LDAP=False,
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        WTF_CSRF_ENABLED=False,
        SECURITY_PASSWORD_HASH="plaintext",
        SECURITY_USER_IDENTITY_ATTRIBUTES=[
            {"username": {"mapper": lambda x: x, "case_insensitive": True}}
        ],
    )
    app.private_pem = private_pem
    db.init_app(app)
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    init_audit(app)
    app.register_blueprint(mission_marti_api)
    app.register_blueprint(data_sync_api)

    published = []
    monkeypatch.setattr(
        mission_data_marti_api,
        "_publish_mission_change_cot",
        lambda name, event, creator_uid=None: published.append((name, event)),
    )
    app.published = published

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        ds.create_user(username="admin", password=hash_password("x"), roles=["administrator"])
        ds.create_user(username="alice", password=hash_password("x"), roles=["user"])
        ds.create_user(username="bob", password=hash_password("x"), roles=["user"])

        mission = Mission(
            name=MISSION,
            guid=GUID,
            description="training",
            tool="public",
            default_role=MissionRole.MISSION_SUBSCRIBER,
            create_time=datetime.datetime(2026, 11, 1, 9, 0),
        )
        db.session.add(mission)
        now = datetime.datetime(2026, 11, 1, 9, 0)
        for uid, role in (
            (OWNER, MissionRole.MISSION_OWNER),
            (SUBSCRIBER, MissionRole.MISSION_SUBSCRIBER),
            (READER, MissionRole.MISSION_READ_ONLY),
        ):
            db.session.add(
                MissionRole(
                    clientUid=uid,
                    username=uid,
                    createTime=now,
                    role_type=role,
                    mission_name=MISSION,
                )
            )

        # Two rows for marker-1: only the newer one may be exported
        old = POINT_COT.replace('lat="51.5"', 'lat="10.0"')
        for xml, uid in ((old, "marker-1"), (POINT_COT, "marker-1"), (SHAPE_COT, "shape-1")):
            db.session.add(
                CoT(
                    uid=uid,
                    type="a-u-G",
                    how="h-e",
                    timestamp=now,
                    start=now,
                    stale=now,
                    xml=xml,
                    mission_name=MISSION,
                )
            )
        db.session.add(
            MissionUID(
                uid="marker-1",
                mission_name=MISSION,
                cot_type="a-u-G",
                latitude=51.5,
                longitude=-0.12,
                callsign="Rally",
            )
        )
        # Known only from mission_uids, no CoT row
        db.session.add(
            MissionUID(
                uid="bare-1",
                mission_name=MISSION,
                cot_type="a-f-G",
                latitude=40.0,
                longitude=-70.0,
                callsign="Bare",
            )
        )

        (uploads / "abc123.jpg").write_bytes(b"\xff\xd8photo")
        content = MissionContent(
            uid="content-1",
            filename="photo.jpg",
            hash="abc123",
            mime_type="image/jpeg",
            size=7,
            submission_time=now,
            submitter="alice",
            keywords=[],
        )
        missing = MissionContent(
            uid="content-2",
            filename="gone.pdf",
            hash="def456",
            mime_type="application/pdf",
            size=1,
            submission_time=now,
            submitter="alice",
            keywords=[],
        )
        db.session.add_all([content, missing])
        db.session.flush()
        db.session.add_all(
            [
                MissionContentMission(mission_content_id=content.id, mission_name=MISSION),
                MissionContentMission(mission_content_id=missing.id, mission_name=MISSION),
            ]
        )
        db.session.add(Mission(name="other", guid="other-guid", tool="public"))
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def token_for(app, eud_uid, mission_name=MISSION, guid=GUID):
    return jwt.encode(
        {
            "sub": eud_uid,
            "MISSION_NAME": mission_name,
            "MISSION_GUID": guid,
            "iat": int(time.time()),
        },
        app.private_pem,
        algorithm="RS256",
    )


class Marti:
    """A Data Sync client holding a mission token"""

    def __init__(self, app, eud_uid, mission_name=MISSION):
        self.client = app.test_client()
        self.headers = {"Authorization": f"Bearer {token_for(app, eud_uid, mission_name)}"}
        self.uid = eud_uid

    def __getattr__(self, method):
        def call(path, **kwargs):
            kwargs.setdefault("headers", self.headers)
            query = kwargs.setdefault("query_string", {})
            query.setdefault("creatorUid", self.uid)
            return getattr(self.client, method)(path, **kwargs)

        return call


@pytest.fixture
def owner(app):
    return Marti(app, OWNER)


@pytest.fixture
def subscriber(app):
    return Marti(app, SUBSCRIBER)


@pytest.fixture
def reader(app):
    return Marti(app, READER)


def web_client(app, username):
    with app.app_context():
        uniquifier = app.security.datastore.find_user(username=username).fs_uniquifier
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()
    return client


def base(path=""):
    return f"/Marti/api/missions/{MISSION}{path}"


def changes(app, **filters):
    with app.app_context():
        return [
            (c.change_type, c.external_data, c.mission_feed, c.mission_layer)
            for c in db.session.query(MissionChange)
            .filter_by(mission_name=MISSION, **filters)
            .order_by(MissionChange.id)
        ]


# --- Archive -----------------------------------------------------------------------------------


def test_archive_is_a_mission_package(owner):
    r = owner.get(base("/archive"))
    assert r.status_code == 200
    assert r.mimetype == "application/zip"
    assert 'filename="op_alpha.zip"' in r.headers["Content-Disposition"]
    assert r.is_streamed

    archive = zipfile.ZipFile(io.BytesIO(r.data))
    assert archive.testzip() is None
    names = archive.namelist()
    assert names[0] == "MANIFEST/manifest.xml"
    assert "content-1/photo.jpg" in names
    assert "marker-1/marker-1.cot" in names
    assert "shape-1/shape-1.cot" in names
    # The file missing on disk is left out rather than breaking the archive
    assert not any("gone.pdf" in name for name in names)
    assert archive.read("content-1/photo.jpg") == b"\xff\xd8photo"

    # The newest CoT row of marker-1, not the older one
    marker = fromstring(archive.read("marker-1/marker-1.cot"))
    assert marker.get("uid") == "marker-1"
    assert marker.find("point").get("lat") == "51.5"

    manifest = fromstring(archive.read("MANIFEST/manifest.xml"))
    assert manifest.tag == "MissionPackageManifest"
    params = {p.get("name"): p.get("value") for p in manifest.find("Configuration")}
    assert params["uid"] == GUID
    assert params["name"] == MISSION
    assert params["mission_guid"] == GUID
    entries = {c.get("zipEntry") for c in manifest.find("Contents")}
    # Every manifest entry is in the zip and every zip entry (bar the manifest) is in the manifest
    assert entries == set(names) - {"MANIFEST/manifest.xml"}


def test_archive_guid_route_and_permissions(app, owner, reader):
    assert owner.get(f"/Marti/api/missions/guid/{GUID}/archive").status_code == 200
    # Read-only subscribers can read
    assert reader.get(base("/archive")).status_code == 200
    # No token, or a token for another mission
    assert app.test_client().get(base("/archive")).status_code == 401
    other = Marti(app, OWNER, mission_name="other")
    assert other.get(base("/archive")).status_code == 401
    assert owner.get("/Marti/api/missions/nope/archive").status_code == 404


# --- KML ---------------------------------------------------------------------------------------


def test_kml_export(owner):
    r = owner.get(base("/kml"))
    assert r.status_code == 200
    assert r.mimetype == "application/vnd.google-earth.kml+xml"
    kml = fromstring(r.data)
    assert kml.tag == f"{KML}kml"
    document = kml.find(f"{KML}Document")
    assert document.find(f"{KML}name").text == MISSION
    placemarks = {p.find(f"{KML}name").text: p for p in document.iter(f"{KML}Placemark")}
    assert set(placemarks) == {"Rally & Point", "Area", "Bare"}

    point = placemarks["Rally & Point"]
    # lon,lat,alt order; the CoT "unknown" hae becomes 0
    assert point.find(f"{KML}Point/{KML}coordinates").text == "-0.12,51.5,0.0"
    assert point.find(f"{KML}description").text == "meet here"
    # ATAK ARGB -65536 (opaque red) is ff0000ff in KML's aabbggrr
    assert point.find(f"{KML}Style/{KML}IconStyle/{KML}color").text == "ff0000ff"

    ring = placemarks["Area"].find(f"{KML}Polygon/{KML}outerBoundaryIs/{KML}LinearRing")
    coords = ring.find(f"{KML}coordinates").text.split()
    assert coords[0] == coords[-1] and len(coords) == 4

    assert placemarks["Bare"].find(f"{KML}Point/{KML}coordinates").text == "-70.0,40.0,0.0"


def test_kml_requires_token(app):
    assert app.test_client().get(base("/kml")).status_code == 401


# --- Layers ------------------------------------------------------------------------------------


def create_layer(client, name, layer_type="GROUP", **params):
    r = client.put(base("/layers"), query_string={"name": name, "type": layer_type, **params})
    assert r.status_code == 200, r.json
    assert r.json["type"] == "MissionLayer"
    return r.json["data"]


def tree(client):
    r = client.get(base("/layers"))
    assert r.status_code == 200
    return r.json["data"]


def test_layers_crud_and_order(app, owner):
    alpha = create_layer(owner, "Alpha")
    bravo = create_layer(owner, "Bravo")
    first = create_layer(owner, "First", after=None)
    assert [layer["name"] for layer in tree(owner)] == ["Alpha", "Bravo", "First"]

    # Move First to the front, then Bravo after it
    r = owner.put(base(f"/layers/{first['uid']}/position"))
    assert r.status_code == 200, r.json
    r = owner.put(base(f"/layers/{bravo['uid']}/position"), query_string={"after": first["uid"]})
    assert r.status_code == 200, r.json
    assert [layer["name"] for layer in tree(owner)] == ["First", "Bravo", "Alpha"]

    # A UID layer under Alpha, filled with a mission item
    markers = create_layer(owner, "Markers", "UID", parentUid=alpha["uid"])
    assert markers["parentUid"] == alpha["uid"]
    r = owner.put(base(f"/layers/{markers['uid']}/items"), json={"uids": ["marker-1"]})
    assert r.status_code == 200, r.json
    assert [u["data"] for u in r.json["data"]["uids"]] == ["marker-1"]
    # Items must belong to the mission, and only fit the right layer type
    r = owner.put(base(f"/layers/{markers['uid']}/items"), json={"uids": ["not-in-mission"]})
    assert r.status_code == 404
    r = owner.put(base(f"/layers/{markers['uid']}/items"), json={"hashes": ["abc123"]})
    assert r.status_code == 400
    files = create_layer(owner, "Files", "CONTENTS")
    r = owner.put(base(f"/layers/{files['uid']}/items"), json={"hashes": ["abc123"]})
    assert r.status_code == 200
    assert r.json["data"]["contents"][0]["data"]["hash"] == "abc123"

    alpha_node = next(layer for layer in tree(owner) if layer["uid"] == alpha["uid"])
    assert [child["name"] for child in alpha_node["children"]] == ["Markers"]

    r = owner.get(base(f"/layers/{markers['uid']}"))
    assert r.status_code == 200 and r.json["data"]["name"] == "Markers"

    # Rename, then move Markers to the top level after Alpha
    r = owner.put(base(f"/layers/{markers['uid']}/name"), query_string={"name": "Pins"})
    assert r.status_code == 200 and r.json["data"]["name"] == "Pins"
    r = owner.put(base(f"/layers/{markers['uid']}/parent"), query_string={"after": alpha["uid"]})
    assert r.status_code == 200, r.json
    assert [layer["name"] for layer in tree(owner)] == ["First", "Bravo", "Alpha", "Pins", "Files"]

    # Removing a layer from the middle keeps the rest in order
    r = owner.delete(base(f"/layers/{markers['uid']}/items"), query_string={"uid": "marker-1"})
    assert r.status_code == 200 and r.json["data"]["uids"] == []
    r = owner.delete(base(f"/layers/{bravo['uid']}"))
    assert r.status_code == 200
    assert [layer["name"] for layer in tree(owner)] == ["First", "Alpha", "Pins", "Files"]


def test_layer_validation(owner):
    group = create_layer(owner, "Group")
    child = create_layer(owner, "Child", parentUid=group["uid"])
    assert (
        owner.put(base("/layers"), query_string={"name": "x", "type": "FOLDER"}).status_code == 400
    )
    assert owner.put(base("/layers"), query_string={"type": "GROUP"}).status_code == 400
    r = owner.put(base("/layers"), query_string={"name": "x", "type": "GROUP", "parentUid": "nope"})
    assert r.status_code == 404
    # after must be a sibling under the same parent
    r = owner.put(
        base("/layers"), query_string={"name": "x", "type": "GROUP", "after": child["uid"]}
    )
    assert r.status_code == 400
    # A layer can't become its own descendant
    r = owner.put(base(f"/layers/{group['uid']}/parent"), query_string={"parentUid": child["uid"]})
    assert r.status_code == 400
    assert owner.delete(base("/layers/nope")).status_code == 404


def test_deleting_a_layer_deletes_its_subtree(app, owner):
    group = create_layer(owner, "Group")
    child = create_layer(owner, "Child", parentUid=group["uid"])
    create_layer(owner, "Grandchild", parentUid=child["uid"])
    r = owner.delete(base(f"/layers/{group['uid']}"))
    assert r.status_code == 200
    assert r.json["data"]["children"][0]["name"] == "Child"
    assert tree(owner) == []
    with app.app_context():
        assert db.session.query(MissionLayer).count() == 0


def test_layer_changes_are_recorded_but_hidden_from_marti(app, owner):
    layer = create_layer(owner, "Alpha")
    owner.put(base(f"/layers/{layer['uid']}/name"), query_string={"name": "Bravo"})
    owner.delete(base(f"/layers/{layer['uid']}"))

    recorded = changes(app)
    assert [c[0] for c in recorded] == [
        MissionChange.ADD_MISSION_LAYER,
        MissionChange.UPDATE_MISSION_LAYER,
        MissionChange.REMOVE_MISSION_LAYER,
    ]
    assert recorded[1][3]["name"] == "Bravo"
    # Subscribers are told to refetch, with a metadata notification rather than a MissionChange
    assert [event.get("type") for _, event in app.published] == ["t-x-m-c-m"] * 3
    assert app.published[0][1].find("detail/mission").get("name") == MISSION

    # TAK clients parse change types into a closed enum, so these never reach them
    r = owner.get(base("/changes"))
    assert r.status_code == 200 and r.json["data"] == []
    with app.test_request_context():
        mission = db.session.get(Mission, MISSION)
        assert mission.to_marti_json()["missionChanges"] == []


def test_layer_permissions(app, owner, subscriber, reader):
    # MISSION_MANAGE_LAYERS is an owner permission
    for client in (subscriber, reader):
        r = client.put(base("/layers"), query_string={"name": "x", "type": "GROUP"})
        assert r.status_code == 403
    layer = create_layer(owner, "Alpha")
    assert subscriber.delete(base(f"/layers/{layer['uid']}")).status_code == 403
    assert (
        subscriber.put(base(f"/layers/{layer['uid']}/name"), query_string={"name": "y"}).status_code
        == 403
    )
    # Everyone subscribed can read the tree
    assert [layer["name"] for layer in tree(reader)] == ["Alpha"]
    no_token = app.test_client()
    assert (
        no_token.put(base("/layers"), query_string={"name": "x", "type": "GROUP"}).status_code
        == 401
    )
    assert no_token.get(base("/layers")).status_code == 401
    # A token for another mission can't touch this one's layers
    other = Marti(app, OWNER, mission_name="other")
    assert other.delete(base(f"/layers/{layer['uid']}")).status_code == 401


# --- External data -----------------------------------------------------------------------------

EXTERNAL = {
    "id": "ext-1",
    "name": "Weather",
    "tool": "wx",
    "urlData": "https://wx.example/data.json",
    "urlView": "https://wx.example/",
    "notes": "hourly",
}


def test_external_data_crud_emits_changes(app, subscriber):
    r = subscriber.post(base("/externaldata"), json=EXTERNAL)
    assert r.status_code == 200, r.json
    assert r.json["type"] == "ExternalMissionData"
    assert r.json["data"] == EXTERNAL

    # Updating the same id edits it in place
    r = subscriber.post(base("/externaldata"), json={**EXTERNAL, "notes": "every 30 minutes"})
    assert r.status_code == 200
    listed = subscriber.get(base("/externaldata")).json["data"]
    assert len(listed) == 1 and listed[0]["notes"] == "every 30 minutes"

    # And it's in the mission JSON clients already read
    mission = subscriber.get(base()).json["data"][0]
    assert mission["externalData"] == listed

    r = subscriber.post(base("/externaldata/ext-1/change"), query_string={"notes": "new run"})
    assert r.status_code == 200 and r.json["data"]["notes"] == "new run"

    r = subscriber.delete(base("/externaldata/ext-1"))
    assert r.status_code == 200
    assert subscriber.get(base("/externaldata")).json["data"] == []
    assert subscriber.delete(base("/externaldata/ext-1")).status_code == 404

    recorded = changes(app)
    assert [c[0] for c in recorded] == [
        "ADD_CONTENT",
        "ADD_CONTENT",
        "ADD_CONTENT",
        "REMOVE_CONTENT",
    ]
    # The REMOVE change still describes what was removed
    assert recorded[-1][1]["name"] == "Weather"

    # Change notifications carry the external data
    assert len(app.published) == 4
    element = app.published[-1][1].find("detail/mission/MissionChanges/MissionChange")
    assert element.find("type").text == "REMOVE_CONTENT"
    assert element.find("externalData/name").text == "Weather"
    assert element.find("externalData/urlData").text == EXTERNAL["urlData"]

    # And GET .../changes shows them with an externalData object
    marti_changes = subscriber.get(base("/changes")).json["data"]
    assert [c["type"] for c in marti_changes] == ["ADD_CONTENT"] * 3 + ["REMOVE_CONTENT"]
    assert marti_changes[0]["externalData"]["id"] == "ext-1"


def test_external_data_validation_and_permissions(app, subscriber, reader):
    assert subscriber.post(base("/externaldata"), json={}).status_code == 400
    r = subscriber.post(base("/externaldata"), json={"name": "x", "urlData": "javascript:alert(1)"})
    assert r.status_code == 400
    # Read-only subscribers lack MISSION_WRITE
    assert reader.post(base("/externaldata"), json=EXTERNAL).status_code == 403
    subscriber.post(base("/externaldata"), json=EXTERNAL)
    assert reader.delete(base("/externaldata/ext-1")).status_code == 403
    assert app.test_client().post(base("/externaldata"), json=EXTERNAL).status_code == 401
    assert [c[0] for c in changes(app)] == ["ADD_CONTENT"]


# --- Feeds -------------------------------------------------------------------------------------


def test_feeds(app, owner, subscriber):
    params = {"dataFeedUid": "adsb", "filterCallsign": "N123", "filterCotTypes": ["a-f-A", "a-n-A"]}
    assert subscriber.post(base("/feed"), query_string=params).status_code == 403
    r = owner.post(base("/feed"), query_string=params)
    assert r.status_code == 200, r.json
    feed = r.json["data"]
    assert feed["dataFeedUid"] == "adsb"
    assert feed["filterType"] == "a-f-A,a-n-A"
    assert owner.get(base()).json["data"][0]["feeds"] == [feed]
    assert owner.get(base("/feeds")).json["data"] == [feed]

    assert owner.delete(base(f"/feed/{feed['uid']}")).status_code == 200
    assert owner.get(base("/feeds")).json["data"] == []
    assert owner.delete(base(f"/feed/{feed['uid']}")).status_code == 404

    recorded = changes(app)
    assert [c[0] for c in recorded] == ["CREATE_DATA_FEED", "DELETE_DATA_FEED"]
    assert recorded[1][2]["dataFeedUid"] == "adsb"
    element = app.published[0][1].find("detail/mission/MissionChanges/MissionChange")
    assert element.find("missionFeed/dataFeedUid").text == "adsb"


# --- Web API -----------------------------------------------------------------------------------


def test_web_detail(app, owner):
    create_layer(owner, "Alpha")
    owner.post(base("/externaldata"), json=EXTERNAL)
    admin = web_client(app, "admin")
    r = admin.get("/api/missions/detail", query_string={"name": MISSION})
    assert r.status_code == 200, r.json
    data = r.json
    assert data["mission"]["name"] == MISSION
    assert "password" not in data["mission"]
    assert {s["clientUid"] for s in data["subscribers"]} == {OWNER, SUBSCRIBER, READER}
    assert {c["hash"] for c in data["contents"]} == {"abc123", "def456"}
    items = {i["uid"]: i for i in data["items"]}
    assert set(items) == {"marker-1", "shape-1", "bare-1"}
    assert items["marker-1"]["callsign"] == "Rally & Point"
    assert items["marker-1"]["latitude"] == 51.5
    assert [layer["name"] for layer in data["layers"]] == ["Alpha"]
    assert data["external_data"][0]["id"] == "ext-1"
    # The web change log includes layer changes, newest first
    assert [c["type"] for c in data["changes"]] == ["ADD_CONTENT", "ADD_MISSION_LAYER"]

    assert admin.get("/api/missions/detail", query_string={"name": "nope"}).status_code == 404
    # Not logged in (this bare app redirects to a login view instead of answering 401)
    r = app.test_client().get("/api/missions/detail", query_string={"name": MISSION})
    assert r.status_code in (302, 401)


def test_web_downloads_are_audited(app):
    admin = web_client(app, "admin")
    r = admin.get("/api/missions/archive", query_string={"name": MISSION})
    assert r.status_code == 200
    assert "MANIFEST/manifest.xml" in zipfile.ZipFile(io.BytesIO(r.data)).namelist()
    r = admin.get("/api/missions/kml", query_string={"name": MISSION})
    assert r.status_code == 200 and fromstring(r.data).tag == f"{KML}kml"
    with app.app_context():
        actions = [e.action for e in db.session.query(AuditEvent).order_by(AuditEvent.id)]
    assert actions == ["mission_archive_export", "mission_kml_export"]


def test_web_group_visibility(app):
    with app.app_context():
        red, blue = Group(), Group()
        red.name, blue.name = "red", "blue"
        red.type = blue.type = Group.SYSTEM
        db.session.add_all([red, blue])
        db.session.flush()
        alice = app.security.datastore.find_user(username="alice")
        db.session.add(GroupUser(user_id=alice.id, group_id=blue.id, direction=Group.IN))
        db.session.add(GroupMission(group_id=red.id, mission_name=MISSION))
        db.session.commit()

    # alice is only in blue, the mission is red's: it's hidden like a missing one
    alice = web_client(app, "alice")
    for path in ("/api/missions/detail", "/api/missions/archive", "/api/missions/kml"):
        assert alice.get(path, query_string={"name": MISSION}).status_code == 404
    # bob is in no group and sees every mission, as on the mission list
    bob = web_client(app, "bob")
    assert bob.get("/api/missions/detail", query_string={"name": MISSION}).status_code == 200


def test_web_delete_mission_removes_new_rows(app, owner):
    group = create_layer(owner, "Group")
    create_layer(owner, "Child", parentUid=group["uid"])
    owner.post(base("/externaldata"), json=EXTERNAL)
    owner.post(base("/feed"), query_string={"dataFeedUid": "adsb"})

    import pika

    class FakeChannel:
        def basic_publish(self, **kwargs):
            pass

        def close(self):
            pass

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            pass

        def channel(self):
            return FakeChannel()

        def close(self):
            pass

    pika_connection = pika.BlockingConnection
    pika.BlockingConnection = FakeConnection
    try:
        r = web_client(app, "admin").delete("/api/missions", query_string={"name": MISSION})
    finally:
        pika.BlockingConnection = pika_connection
    assert r.status_code == 200, r.json
    with app.app_context():
        from raven.models.MissionExternalData import MissionExternalData
        from raven.models.MissionFeed import MissionFeed

        assert db.session.query(MissionLayer).count() == 0
        assert db.session.query(MissionExternalData).count() == 0
        assert db.session.query(MissionFeed).count() == 0
