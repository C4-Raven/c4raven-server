"""The shared `app` fixture in conftest.py must never reach the server's own database or data
folder (tests/tests.py uses it)."""

import os

from raven.defaultconfig import DefaultConfig
from tests.conftest import is_test_database, test_database_uri


def test_shared_fixture_uses_a_throwaway_database_and_folder(app, tmp_path):
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if not os.environ.get("RAVEN_TEST_DATABASE_URI"):
        assert uri.startswith("sqlite:///") and str(tmp_path) in uri
    assert is_test_database(uri)
    assert app.config["RAVEN_DATA_FOLDER"].startswith(str(tmp_path))
    assert app.config["UPLOAD_FOLDER"].startswith(str(tmp_path))
    assert app.config["RAVEN_CA_FOLDER"].startswith(str(tmp_path))


def test_live_database_is_not_a_test_database(monkeypatch, tmp_path):
    monkeypatch.delenv("RAVEN_TEST_DATABASE_URI", raising=False)
    assert not is_test_database("postgresql+psycopg://ots:pw@127.0.0.1/ots")
    assert test_database_uri(tmp_path).startswith("sqlite:///")
    monkeypatch.setenv("RAVEN_TEST_DATABASE_URI", "postgresql+psycopg://t:t@127.0.0.1/scratch")
    assert test_database_uri(tmp_path) == "postgresql+psycopg://t:t@127.0.0.1/scratch"
    assert is_test_database("postgresql+psycopg://t:t@127.0.0.1/scratch")


def test_default_config_is_restored_after_the_fixture():
    # monkeypatch undoes the class patch, so nothing leaks into other test modules
    assert not DefaultConfig.SQLALCHEMY_DATABASE_URI.startswith("sqlite:///" + os.sep + "tmp")
