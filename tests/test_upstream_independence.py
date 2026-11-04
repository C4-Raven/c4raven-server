"""Raven never reaches out to the upstream project's infrastructure.

- The icon sets are loaded from the sqlite file bundled in the package (raven/data/iconsets.sqlite),
  not downloaded on first start.
- No plugin repository is configured by default; installing a plugin by name is refused with a
  clear error until RAVEN_PLUGIN_REPO is set, and /api/plugins/repo reports "".
"""

import hashlib
import os
import socket
import subprocess
import sys

import pytest
from flask import Flask, request
from flask_security.models import fsqla_v3 as fsqla

import raven
from raven.extensions import db

try:
    fsqla.FsModels.set_db_info(db)
except Exception:
    pass

from raven import app as raven_app  # noqa: E402
from raven.blueprints.raven_api import plugin_api  # noqa: E402
from raven.defaultconfig import DefaultConfig  # noqa: E402
from raven.models.Icon import Icon  # noqa: E402
from raven.plugins import PluginManager as plugin_manager_module  # noqa: E402
from raven.plugins.plugin_repo import NO_PLUGIN_REPO_MESSAGE, get_plugin_repo  # noqa: E402

BUNDLED_ICONSETS_SHA256 = "7733ac2d1959d2ab68b1e23d5b886b2847a5551f121110be59e6ef9a0299ce3a"
BUNDLED_ICON_COUNT = 3743


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test on any attempt to open a network connection or resolve a name."""
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise AssertionError(f"unexpected network access: {args!r}")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    import requests

    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(requests, "request", refuse)
    monkeypatch.setattr(requests.Session, "request", refuse)
    return attempts


@pytest.fixture
def icon_app(tmp_path):
    app = Flask("raven-icons-test")
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'test.db'}",
        RAVEN_DATA_FOLDER=str(tmp_path),
    )
    db.init_app(app)
    with app.app_context():
        Icon.__table__.create(bind=db.engine)
        yield app


# ---------------------------------------------------------------------------------------------
# Icon sets
# ---------------------------------------------------------------------------------------------


def test_iconsets_file_is_bundled_in_the_package():
    path = raven_app.BUNDLED_ICONSETS_PATH
    package_dir = os.path.dirname(os.path.abspath(raven.__file__))
    assert path == os.path.join(package_dir, "data", "iconsets.sqlite")
    with open(path, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == BUNDLED_ICONSETS_SHA256


def test_load_bundled_icons_reads_package_file_without_network(icon_app, no_network, tmp_path):
    inserted = raven_app.load_bundled_icons()

    assert inserted == BUNDLED_ICON_COUNT
    assert db.session.query(Icon).count() == BUNDLED_ICON_COUNT
    assert db.session.query(Icon).filter(Icon.bitmap.isnot(None)).count() > 0
    assert no_network == []
    # Nothing is written to the data folder any more; the bundled file is read in place.
    assert not os.path.exists(tmp_path / "icons.sqlite")


def test_load_bundled_icons_opens_file_read_only(icon_app, no_network):
    # mode=ro: loading must never modify the file shipped with the package.
    with open(raven_app.BUNDLED_ICONSETS_PATH, "rb") as f:
        before = hashlib.sha256(f.read()).hexdigest()
    raven_app.load_bundled_icons()
    with open(raven_app.BUNDLED_ICONSETS_PATH, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == before


def test_package_source_has_no_upstream_hosts():
    package_dir = os.path.dirname(os.path.abspath(raven.__file__))
    offenders = []
    for root, _dirs, files in os.walk(package_dir):
        for name in files:
            if not name.endswith((".py", ".po", ".xml", ".html", ".txt", ".yml", ".yaml")):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read().lower()
            for needle in ("opentakserver", "brian7704"):
                if needle in text:
                    offenders.append((os.path.relpath(path, package_dir), needle))
    assert offenders == []


# ---------------------------------------------------------------------------------------------
# Plugin repository
# ---------------------------------------------------------------------------------------------


def _default_plugin_repo(env_value=None):
    env = dict(os.environ)
    env.pop("RAVEN_PLUGIN_REPO", None)
    if env_value is not None:
        env["RAVEN_PLUGIN_REPO"] = env_value
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "from raven.defaultconfig import DefaultConfig; print(repr(DefaultConfig.RAVEN_PLUGIN_REPO))",
        ],
        env=env,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(raven.__file__))),
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def test_plugin_repo_defaults_to_empty():
    assert _default_plugin_repo() == "''"


def test_plugin_repo_env_override():
    assert _default_plugin_repo("https://plugins.example.net/simple/") == (
        "'https://plugins.example.net/simple/'"
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, ""),
        ("", ""),
        ("   ", ""),
        (42, ""),
        (" https://plugins.example.net/simple/ ", "https://plugins.example.net/simple/"),
    ],
)
def test_get_plugin_repo(value, expected):
    assert get_plugin_repo({"RAVEN_PLUGIN_REPO": value}) == expected


@pytest.fixture
def plugin_app():
    app = Flask("raven-plugin-test")
    app.config.from_object(DefaultConfig)
    app.config.update(TESTING=True, RAVEN_PLUGIN_REPO="")
    return app


def test_repo_api_reports_empty_repo(plugin_app):
    view = plugin_api.get_plugin_repo.__wrapped__  # skip roles_required
    with plugin_app.test_request_context("/api/plugins/repo"):
        assert view().get_json() == {"success": True, "repo_url": ""}
        plugin_app.config["RAVEN_PLUGIN_REPO"] = "https://plugins.example.net/simple/"
        assert view().get_json() == {
            "success": True,
            "repo_url": "https://plugins.example.net/simple/",
        }


class FakeSocketIO:
    def __init__(self):
        self.emitted = []

    def emit(self, event, data, **kwargs):
        self.emitted.append((event, data))


def _run_install(app, monkeypatch, repo):
    app.config["RAVEN_PLUGIN_REPO"] = repo
    fake = FakeSocketIO()
    popen_calls = []

    def fake_popen(args, **kwargs):
        popen_calls.append(args)
        raise RuntimeError("stop before running pip")

    monkeypatch.setattr(plugin_manager_module, "socketio", fake)
    monkeypatch.setattr(plugin_manager_module.subprocess, "Popen", fake_popen)
    handler = plugin_manager_module.PluginManager.install_plugin.__wrapped__  # skip admin check
    with app.test_request_context("/socket.io"):
        request.sid = "test-sid"
        handler({"action": "install", "plugin_distro": "raven-example"})
    return fake.emitted, popen_calls


def test_install_refused_without_repo(plugin_app, monkeypatch):
    emitted, popen_calls = _run_install(plugin_app, monkeypatch, "")
    assert popen_calls == []
    assert emitted == [
        ("plugin_package_manager", {"success": False, "message": NO_PLUGIN_REPO_MESSAGE})
    ]
    assert NO_PLUGIN_REPO_MESSAGE == "No plugin repository configured; set RAVEN_PLUGIN_REPO"


def test_install_uses_configured_repo(plugin_app, monkeypatch):
    _emitted, popen_calls = _run_install(
        plugin_app, monkeypatch, "https://plugins.example.net/simple/"
    )
    assert len(popen_calls) == 1
    args = popen_calls[0]
    assert args[-2:] == ["-i", "https://plugins.example.net/simple/"]
    assert "raven-example" in args
