"""Every scheduled job must work in a process that hasn't imported the models yet.

The scheduler starts in init_extensions, before create_app registers the blueprints that import
most of the models, and jobs fire right away on a restart. On 2026-11-03 13:51 one did:
"When initializing mapper Mapper[EUD(euds)], expression 'EUDStats' failed to locate a name",
which broke every later query in the process and crashed the service's startup twice.

Each job runs here in a fresh interpreter that, like APScheduler, imports only
raven.blueprints.scheduled_jobs. RabbitMQ and MediaMTX are stubbed; the database is a throwaway
sqlite file whose schema another fresh process creates.
"""

import os
import subprocess
import sys
import textwrap

import pytest

from raven.defaultconfig import DefaultConfig

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APP_SETUP = textwrap.dedent(
    """
    import os, sys
    from flask import Flask
    from raven.defaultconfig import DefaultConfig
    from raven.extensions import db

    folder = sys.argv[1]
    app = Flask("raven-job-test")
    app.config.from_object(DefaultConfig)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test",
        SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(folder, "test.db"),
        RAVEN_DATA_FOLDER=folder,
        UPLOAD_FOLDER=os.path.join(folder, "uploads"),
        RAVEN_CA_FOLDER=os.path.join(folder, "ca"),
        RAVEN_MEDIAMTX_API_ADDRESS="http://127.0.0.1:9",
        RAVEN_RABBITMQ_SERVER_ADDRESS="127.0.0.1",
    )
    db.init_app(app)
    """
)

CREATE_SCHEMA = APP_SETUP + textwrap.dedent(
    """
    from raven.models import import_all_models

    import_all_models()
    with app.app_context():
        db.create_all()
    """
)

RUN_JOB = APP_SETUP + textwrap.dedent(
    """
    import logging
    from unittest import mock

    import pika
    import requests
    import sqlalchemy.orm

    func = sys.argv[2]
    module_name, name = func.split(":")
    assert "raven.models.EUDStats" not in sys.modules

    import importlib
    module = importlib.import_module(module_name)

    messages = []

    class Collect(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    logging.getLogger().addHandler(Collect())
    from raven.extensions import apscheduler, logger
    logger.addHandler(Collect())
    apscheduler.app = app

    with mock.patch.object(pika, "BlockingConnection"), \\
            mock.patch.object(requests, "get", side_effect=OSError("no mediamtx")), \\
            mock.patch.object(requests, "delete", side_effect=OSError("no mediamtx")):
        try:
            getattr(module, name)()
        except Exception as e:
            messages.append(f"raised {type(e).__name__}: {e}")

    try:
        sqlalchemy.orm.configure_mappers()
    except Exception as e:
        messages.append(f"configure_mappers: {e}")
    print("\\n".join(messages))
    """
)


def _run(script, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", script, *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.fixture(scope="module")
def schema(tmp_path_factory):
    folder = tmp_path_factory.mktemp("jobs")
    for sub in ("uploads", "ca", "logs"):
        os.makedirs(folder / sub, exist_ok=True)
    result = _run(CREATE_SCHEMA, str(folder))
    assert result.returncode == 0, result.stderr
    return folder


@pytest.mark.parametrize("func", sorted({job["func"] for job in DefaultConfig.JOBS}))
def test_job_runs_without_prior_model_imports(schema, func):
    result = _run(RUN_JOB, str(schema), func)
    assert result.returncode == 0, result.stderr
    output = result.stdout + result.stderr
    assert "failed to locate a name" not in output
    assert "mappers failed to initialize" not in output
    assert "configure_mappers:" not in output
    assert "outside of application context" not in output
