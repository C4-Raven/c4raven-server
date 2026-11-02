"""MediaMTX authentication (mediamtx_api.external_auth) and group isolation of playback/publish.

MediaMTX POSTs a JSON body ({user, password, ip, action, path, protocol, id, query}) for every
read, playback and publish; these tests send the same bodies. Minimal sqlite Flask app as in
tests/test_group_isolation.py: no RabbitMQ, Postgres or MediaMTX (its API is mocked).
"""

import importlib
import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

import pytest
from bs4 import BeautifulSoup
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore, hash_password
from flask_security.models import fsqla_v3 as fsqla

from raven.defaultconfig import DefaultConfig
from raven.extensions import babel, db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven import stream_tokens  # noqa: E402

# The package __init__ re-exports the blueprints under the module names
mediamtx_api = importlib.import_module("raven.blueprints.raven_api.mediamtx_api")
video_marti = importlib.import_module("raven.blueprints.marti_api.video_marti_api")
from raven.blueprints.raven_api.video_api import video_api_blueprint  # noqa: E402
from raven.models.Group import Group  # noqa: E402
from raven.models.GroupUser import GroupUser  # noqa: E402
from raven.models.VideoStream import VideoStream  # noqa: E402

WEB_COPY = mediamtx_api.WEB_COPY_SUFFIX
SERVER_TOKEN = "server-token"
OUTSIDE_IP = "203.0.113.5"


class _FakeCert:
    def __init__(self, cn):
        self._cn = cn

    def get_subject(self):
        cn = self._cn
        return type(
            "Subject",
            (),
            {"commonName": cn, "get_components": lambda self: [(b"CN", cn.encode())]},
        )()


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
        RAVEN_MEDIAMTX_TOKEN=SERVER_TOKEN,
        RAVEN_MEDIAMTX_API_ADDRESS="http://mediamtx.invalid:9997",
        SECURITY_TWO_FACTOR=False,
        SECURITY_CSRF_PROTECT_MECHANISMS=[],
        WTF_CSRF_ENABLED=False,
        SECURITY_PASSWORD_HASH="plaintext",
        SECURITY_USER_IDENTITY_ATTRIBUTES=[
            {"username": {"mapper": lambda x: x, "case_insensitive": True}}
        ],
    )
    db.init_app(app)
    babel.init_app(app)

    from raven.models.role import Role
    from raven.models.user import User
    from raven.models.WebAuthn import WebAuthn

    app.security = Security(app, SQLAlchemyUserDatastore(db, User, Role, WebAuthn))
    app.register_blueprint(mediamtx_api.mediamtx_api_blueprint)
    app.register_blueprint(video_api_blueprint)
    app.register_blueprint(video_marti.video_marti_api)

    with app.app_context():
        db.create_all()
        ds = app.security.datastore
        ds.find_or_create_role("administrator")
        ds.find_or_create_role("user")
        for name, role in (("admin", "administrator"), ("alice", "user"), ("rita", "user"),
                           ("ivan", "user"), ("bob", "user"), ("gone", "user")):
            ds.create_user(username=name, password=hash_password("x"), roles=[role])
        ds.find_user(username="gone").active = False
        db.session.commit()

        for group_name in ("red", "blue"):
            group = Group()
            group.name = group_name
            group.type = Group.SYSTEM
            db.session.add(group)
        db.session.commit()
        red = db.session.query(Group).filter_by(name="red").one()
        blue = db.session.query(Group).filter_by(name="blue").one()

        # alice: red both ways; rita only reads red; ivan only sends to red; bob is blue
        memberships = {
            "alice": [(red, "IN"), (red, "OUT")],
            "rita": [(red, "OUT")],
            "ivan": [(red, "IN")],
            "bob": [(blue, "IN"), (blue, "OUT")],
            "gone": [(red, "IN"), (red, "OUT")],
        }
        for username, rows in memberships.items():
            user = ds.find_user(username=username)
            for group, direction in rows:
                db.session.add(
                    GroupUser(user_id=user.id, group_id=group.id, direction=direction, enabled=True)
                )

        def stream(path, owner=None, groups=(), settings=None):
            v = VideoStream(
                path=path,
                username=owner,
                uid=f"uid-{path}",
                port=8554,
                mediamtx_settings=json.dumps({"source": None, "record": False, **(settings or {})}),
            )
            v.groups = list(groups)
            v.generate_xml("10.0.0.1")
            db.session.add(v)

        stream("redcam", owner="alice", groups=[red])  # red's stream
        stream("opencam")  # legacy: no owner, no groups
        stream("bobcam", owner="bob")  # ungrouped but owned
        stream("redyt", owner="alice", groups=[red], settings={"runOnDemand": "ffmpeg ..."})
        db.session.commit()

    with mock.patch.object(mediamtx_api.requests, "post") as post:
        post.return_value.status_code = 200
        app.mediamtx_post = post
        yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


def user_of(app, username):
    return app.security.datastore.find_user(username=username)


def jwt(app, username):
    with app.app_context():
        return user_of(app, username).get_auth_token()


def stream_token(app, username, path, max_age=None):
    with app.app_context():
        return stream_tokens.make_token(path, user_of(app, username), max_age=max_age)


def auth(app, action, protocol, path, user="", password="", query="", ip=OUTSIDE_IP, headers=None):
    body = {
        "user": user,
        "password": password,
        "ip": ip,
        "action": action,
        "path": path,
        "protocol": protocol,
        "id": "conn-1",
        "query": query,
    }
    return app.test_client().post("/api/external_auth", json=body, headers=headers or {}).status_code


# Each principal as MediaMTX would present it: (user, password, query)
def principal(app, who, path="redcam"):
    if who == "anonymous":
        return "", "", ""
    if who == "server":
        return "", "", f"token={SERVER_TOKEN}"
    kind, username = who.split(":")
    if kind == "pw":
        return username, "x", ""
    if kind == "jwt":
        return "", "", f"jwt={jwt(app, username)}"
    if kind == "st":
        return "", "", f"{stream_tokens.PARAM}={stream_token(app, username, 'redcam')}"
    raise AssertionError(who)


READ_ACTIONS = [(a, p) for a in ("read", "playback") for p in ("rtsp", "hls", "webrtc")]


@pytest.mark.parametrize("action,protocol", READ_ACTIONS)
@pytest.mark.parametrize(
    "who,expected",
    [
        ("pw:admin", 200),
        ("jwt:admin", 200),
        ("pw:alice", 200),
        ("jwt:alice", 200),
        ("pw:rita", 200),  # an OUT membership is enough to watch
        ("st:rita", 200),
        ("server", 200),
        ("pw:bob", 401),
        ("jwt:bob", 401),
        ("st:bob", 401),  # validly signed, but bob can't see red's stream
        ("pw:ivan", 401),  # IN only: may publish to red, not watch it
        ("pw:gone", 401),  # inactive
        ("anonymous", 401),
    ],
)
def test_watching_a_grouped_stream(app, action, protocol, who, expected):
    user, password, query = principal(app, who)
    assert auth(app, action, protocol, "redcam", user, password, query) == expected
    # The browser copy of a stream is guarded like the stream
    assert auth(app, action, protocol, "redcam" + WEB_COPY, user, password, query) == expected


@pytest.mark.parametrize("action,protocol", READ_ACTIONS)
def test_watching_an_ungrouped_stream(app, action, protocol):
    anonymous_ok = action == "read" and protocol == "rtsp"
    assert auth(app, action, protocol, "opencam") == (200 if anonymous_ok else 401)
    assert auth(app, action, protocol, "opencam", query="jwt=garbage") == (
        200 if anonymous_ok else 401
    )
    for who in ("pw:bob", "jwt:bob", "pw:rita", "server"):
        user, password, query = principal(app, who)
        assert auth(app, action, protocol, "opencam", user, password, query) == 200
    # Same for a path Raven has no row for
    assert auth(app, action, protocol, "unknown") == (200 if anonymous_ok else 401)


def test_stream_token_expired_wrong_path_or_tampered(app):
    expired = stream_token(app, "rita", "redcam", max_age=-10)
    assert auth(app, "read", "rtsp", "redcam", query=f"st={expired}") == 401

    other_path = stream_token(app, "rita", "opencam")
    assert auth(app, "read", "rtsp", "redcam", query=f"st={other_path}") == 401

    good = stream_token(app, "rita", "redcam")
    user_id, expires, signature = good.split(".")
    for bad in (
        f"{user_id}.{int(expires) + 3600}.{signature}",  # extended expiry
        f"{user_of_id(app, 'alice')}.{expires}.{signature}",  # someone else's id
        f"{user_id}.{expires}.{signature[:-2]}AA",
        "nonsense",
    ):
        assert auth(app, "read", "rtsp", "redcam", query=f"st={bad}") == 401
    assert auth(app, "read", "rtsp", "redcam", query=f"st={good}") == 200
    # The token travels alongside other query parameters
    assert auth(app, "read", "hls", "redcam", query=f"foo=1&st={good}&bar=2") == 200


def user_of_id(app, username):
    with app.app_context():
        return user_of(app, username).id


def test_stream_token_stops_working_when_membership_ends(app):
    token = stream_token(app, "rita", "redcam")
    assert auth(app, "read", "rtsp", "redcam", query=f"st={token}") == 200
    with app.app_context():
        db.session.query(GroupUser).filter_by(user_id=user_of(app, "rita").id).update(
            {"enabled": False}
        )
        db.session.commit()
    assert auth(app, "read", "rtsp", "redcam", query=f"st={token}") == 401


def test_stream_token_cannot_publish(app):
    token = stream_token(app, "alice", "redcam")
    for protocol in ("rtsp", "rtmp", "webrtc"):
        assert auth(app, "publish", protocol, "redcam", query=f"st={token}") == 401


@pytest.mark.parametrize("protocol", ["rtsp", "rtmp", "webrtc", "srt"])
@pytest.mark.parametrize(
    "path,who,expected",
    [
        ("redcam", "pw:alice", 200),  # owner
        ("redcam", "jwt:alice", 200),
        ("redcam", "pw:ivan", 200),  # IN member of red
        ("redcam", "pw:admin", 200),
        ("redcam", "server", 200),
        ("redcam", "pw:rita", 401),  # OUT only
        ("redcam", "pw:bob", 401),
        ("redcam", "jwt:bob", 401),
        ("redcam", "pw:gone", 401),
        ("redcam", "anonymous", 401),
        ("redcam" + WEB_COPY, "pw:bob", 401),
        ("redcam" + WEB_COPY, "server", 200),
        ("bobcam", "pw:bob", 200),  # ungrouped, but owned
        ("bobcam", "pw:alice", 401),
        ("bobcam", "pw:admin", 200),
        ("opencam", "pw:bob", 200),  # no owner, no groups
        ("opencam", "anonymous", 401),
    ],
)
def test_publishing_onto_an_existing_path(app, protocol, path, who, expected):
    user, password, query = principal(app, who)
    assert auth(app, "publish", protocol, path, user, password, query) == expected
    with app.app_context():
        assert db.session.query(VideoStream).count() == 4  # nothing registered
    app.mediamtx_post.assert_not_called()


def test_publishing_a_new_path_registers_it_with_the_publishers_groups(app):
    assert auth(app, "publish", "rtsp", "bobnew", "bob", "x") == 200
    with app.app_context():
        stream = db.session.get(VideoStream, "bobnew")
        assert stream.username == "bob"
        assert stream.group_names == ["blue"]
        assert stream.uid == "conn-1"
    assert app.mediamtx_post.call_args.args[0].endswith("/v3/config/paths/add/bobnew")

    # Now it's bob's: alice can't take it over, nor watch it
    assert auth(app, "publish", "rtsp", "bobnew", "alice", "x") == 401
    assert auth(app, "read", "rtsp", "bobnew") == 401
    assert auth(app, "read", "rtsp", "bobnew", "alice", "x") == 401
    assert auth(app, "read", "rtsp", "bobnew", "bob", "x") == 200


def test_web_ui_browser_publish(app):
    """VideoStreams.tsx opens :8889/<username>_browser/publish?jwt=<token> (WHIP)."""
    query = f"jwt={jwt(app, 'alice')}"
    assert auth(app, "publish", "webrtc", "alice_browser", query=query) == 200
    with app.app_context():
        stream = db.session.get(VideoStream, "alice_browser")
        assert stream.username == "alice"
        assert stream.group_names == ["red"]
    # Publishing again later works; another user can't hijack it
    assert auth(app, "publish", "webrtc", "alice_browser", query=query) == 200
    assert auth(app, "publish", "webrtc", "alice_browser", query=f"jwt={jwt(app, 'bob')}") == 401


def test_anonymous_and_bad_credentials_cannot_publish(app):
    for user, password, query in (
        ("", "", ""),
        ("bob", "wrong", ""),
        ("nobody", "x", ""),
        ("", "", "jwt=garbage"),
        ("", "", "token=wrong"),
    ):
        assert auth(app, "publish", "rtsp", "newpath", user, password, query) == 401
    app.mediamtx_post.assert_not_called()


def test_users_cannot_publish_new_web_copy_paths(app):
    assert auth(app, "publish", "rtsp", "elsewhere" + WEB_COPY, "bob", "x") == 401
    assert auth(app, "publish", "rtsp", "elsewhere" + WEB_COPY, query=f"token={SERVER_TOKEN}") == 200


def test_localhost_publisher(app):
    """Uncredentialed publishers from 127.0.0.1 (MediaMTX's runOnDemand ffmpeg, but also
    nginx's RTSPS/RTMPS proxies) keep working except onto another group's stream."""
    for path in ("newpath", "opencam", "bobcam", "redyt"):
        assert auth(app, "publish", "rtsp", path, ip="127.0.0.1") == 200
    assert auth(app, "publish", "rtsp", "redcam", ip="127.0.0.1") == 401
    # Never for reading: nginx's HLS/WebRTC proxying comes from 127.0.0.1 too
    assert auth(app, "read", "hls", "opencam", ip="127.0.0.1") == 401


def test_not_reachable_through_nginx(app):
    headers = {"X-Forwarded-For": "198.51.100.7"}
    assert auth(app, "read", "rtsp", "opencam", query=f"token={SERVER_TOKEN}", headers=headers) == 401


def test_api_actions_only_for_admins(app):
    assert auth(app, "api", "", "", "admin", "x") == 200
    assert auth(app, "api", "", "", "bob", "x") == 401
    assert auth(app, "metrics", "", "") == 401


# --- the feed URLs handed out carry what's needed to play them ---


def _query_of(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def test_marti_vcm_feed_paths_carry_stream_tokens(app, monkeypatch):
    monkeypatch.setattr(video_marti, "verify_client_cert", lambda: _FakeCert("rita"))
    r = app.test_client().get("/Marti/vcm")
    assert r.status_code == 200
    feeds = {
        f.find("uid").text: f.find("path").text
        for f in BeautifulSoup(r.data, "xml").find_all("feed")
    }
    assert feeds["uid-opencam"] == "opencam"  # ungrouped: unchanged
    red_path = feeds["uid-redcam"]
    assert red_path.startswith("redcam?st=")
    token = _query_of(red_path)["st"]
    # What ATAK then sends MediaMTX: rtsp://host:8554/redcam?st=...
    assert auth(app, "read", "rtsp", "redcam", query=f"st={token}") == 200
    with app.app_context():
        assert stream_tokens.verify_token(token, "redcam") == user_of(app, "rita").id


def test_marti_video_list_urls_play_for_their_user_only(app, monkeypatch):
    monkeypatch.setattr(video_marti, "verify_client_cert", lambda: _FakeCert("alice"))
    r = app.test_client().get("/Marti/api/video")
    assert r.status_code == 200
    urls = {v["uuid"]: v["feeds"][0]["url"] for v in r.json["videoConnections"]}
    query = urlparse(urls["uid-redcam"]).query
    assert auth(app, "read", "hls", "redcam", query=query) == 200
    # bob's token in the same URL doesn't play it
    assert auth(app, "read", "hls", "redcam", query=f"jwt={jwt(app, 'bob')}") == 401


def test_web_listing_rtsp_link_carries_the_viewers_token(app):
    with app.app_context():
        uniquifier = user_of(app, "alice").fs_uniquifier
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = uniquifier
        session["_fresh"] = True
        session["fs_cc"] = "set"
        session["fs_paa"] = time.time()
    r = client.get("/api/video_streams", query_string={"per_page": 50})
    assert r.status_code == 200
    links = {s["path"]: s["rtsp_link"] for s in r.json["results"]}
    assert "?" not in links["opencam"]
    token = _query_of(links["redcam"])["st"]
    assert auth(app, "read", "rtsp", "redcam", query=f"st={token}") == 200
    # The web/HLS links stay bare: the UI appends ?jwt= itself
    hls = {s["path"]: s["hls_link"] for s in r.json["results"]}
    assert "?" not in hls["redcam"]
