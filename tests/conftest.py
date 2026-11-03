import os

import pytest
import sqlalchemy
import yaml
from flask_security import hash_password

from raven.app import create_app
from raven.defaultconfig import DefaultConfig
from raven.extensions import db, logger


class AuthActions:
    def __init__(self, app, client, username="TestUser", password="TestPass"):
        self.app = app
        self.client = client
        self.username = username
        self.password = password
        self.headers = {}
        self.create()
        self.login()

    def create(self):
        try:
            with self.client.application.app_context():
                self.app.security.datastore.create_user(
                    username=self.username,
                    password=hash_password(self.password),
                    roles=["administrator"],
                )
                db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            logger.warning("{} already exists".format(self.username))

    def login(self):
        response = self.get("/api/login")
        csrf_token = response.json["response"]["csrf_token"]
        self.headers["X-CSRFToken"] = csrf_token
        response = self.client.post(
            "/api/login", json={"username": self.username, "password": self.password}
        )

        return response

    def logout(self):
        return self.client.get("/api/logout")

    def get(self, path, headers=None, json=None):
        if json is None:
            json = {}

        if headers is None:
            headers = self.headers
        return self.client.get(path, headers=headers, json=json)

    def post(self, path, headers=None):
        if headers is None:
            headers = self.headers
        return self.client.post(path, headers=headers)


def test_database_uri(tmp_path) -> str:
    """The database the shared app fixture may use: RAVEN_TEST_DATABASE_URI (a scratch
    PostgreSQL/MySQL database you set up for this) or a throwaway SQLite file. Never the server's
    own database: DefaultConfig would otherwise point create_app() at the live one."""
    return os.environ.get("RAVEN_TEST_DATABASE_URI") or f"sqlite:///{tmp_path / 'test.db'}"


def is_test_database(uri: str) -> bool:
    return uri == os.environ.get("RAVEN_TEST_DATABASE_URI") or uri.startswith("sqlite")


test_database_uri.__test__ = False
is_test_database.__test__ = False


@pytest.fixture
def app(tmp_path, monkeypatch):
    uri = test_database_uri(tmp_path)
    data_folder = tmp_path / "ots"
    data_folder.mkdir()

    # DefaultConfig reads its paths and database at import time, so patch the class: everything
    # under the real RAVEN_DATA_FOLDER (CA, uploads...) moves to the temporary one
    real_folder = DefaultConfig.RAVEN_DATA_FOLDER
    for name in dir(DefaultConfig):
        value = getattr(DefaultConfig, name)
        if name.isupper() and isinstance(value, str) and value.startswith(real_folder):
            monkeypatch.setattr(
                DefaultConfig, name, str(data_folder) + value[len(real_folder) :]
            )
    monkeypatch.setattr(DefaultConfig, "SQLALCHEMY_DATABASE_URI", uri)
    # create_app() reads RAVEN_DATA_FOLDER/config.yml (and only then sets up the database): give
    # it one that names the test database, never the server's own
    with open(data_folder / "config.yml", "w") as config:
        config.write(
            yaml.safe_dump(
                {
                    "SQLALCHEMY_DATABASE_URI": uri,
                    "RAVEN_DATA_FOLDER": str(data_folder),
                    "UPLOAD_FOLDER": str(data_folder / "uploads"),
                    "RAVEN_CA_FOLDER": str(data_folder / "ca"),
                }
            )
        )

    app = create_app()
    configured = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
    if configured != uri or not is_test_database(configured):
        pytest.exit(
            "Refusing to run: the test app is configured with a database that isn't a test "
            "database. Set RAVEN_TEST_DATABASE_URI to a scratch database, or leave it unset to "
            "use a temporary SQLite file.",
            returncode=1,
        )
    if not str(app.config.get("RAVEN_DATA_FOLDER", "")).startswith(str(data_folder)):
        pytest.exit("Refusing to run: RAVEN_DATA_FOLDER isn't the test's temporary folder.")
    app.config["TESTING"] = True
    app.config["PRESERVE_CONTEXT_ON_EXCEPTION"] = False
    if configured.startswith("sqlite"):
        with app.app_context():
            db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture()
def client(app):
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["Authorization"] = "redacted"
        print(session)  # will be populated SecureCookieSession
        yield client


@pytest.fixture
def auth(app, client):
    return AuthActions(app, client)
