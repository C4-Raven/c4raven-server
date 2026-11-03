"""A test run must never write into the live server's logs (~/ots/logs). raven.cot_parser.cot_parser
builds its app when imported, which attaches a cot_parser.log file handler under RAVEN_DATA_FOLDER to
the shared "Raven" logger, so with the real data folder every later test logged into the server's
cot_parser.log (conftest.py points RAVEN_DATA_FOLDER at a throwaway folder before raven is imported)."""

import logging
import os
from pathlib import Path

from raven.defaultconfig import DefaultConfig
from raven.extensions import logger
from tests.conftest import TEST_DATA_FOLDER

REAL_DATA_FOLDER = os.path.realpath(os.path.join(Path.home(), "ots"))


def file_handler_paths():
    return [
        os.path.realpath(h.baseFilename)
        for h in logger.handlers
        if isinstance(h, logging.FileHandler)
    ]


def test_data_folder_is_not_the_servers():
    assert os.path.realpath(DefaultConfig.RAVEN_DATA_FOLDER) == os.path.realpath(TEST_DATA_FOLDER)
    assert os.path.realpath(DefaultConfig.RAVEN_DATA_FOLDER) != REAL_DATA_FOLDER
    assert not os.path.realpath(DefaultConfig.RAVEN_CA_FOLDER).startswith(REAL_DATA_FOLDER + os.sep)
    assert not os.path.realpath(DefaultConfig.UPLOAD_FOLDER).startswith(REAL_DATA_FOLDER + os.sep)


def test_importing_cot_parser_logs_to_the_test_folder():
    from raven.cot_parser import cot_parser

    assert os.path.realpath(cot_parser.app.config["RAVEN_DATA_FOLDER"]) == os.path.realpath(
        TEST_DATA_FOLDER
    )
    paths = file_handler_paths()
    assert os.path.join(os.path.realpath(TEST_DATA_FOLDER), "logs", "cot_parser.log") in paths
    for path in paths:
        assert not path.startswith(REAL_DATA_FOLDER + os.sep), path

    logger.error("logging isolation probe")
    with open(os.path.join(TEST_DATA_FOLDER, "logs", "cot_parser.log")) as log:
        assert "logging isolation probe" in log.read()


def test_app_fixture_drops_its_log_handler(app):
    # The fixture's raven.log handler is in this test's own folder while it runs...
    assert any(
        p.startswith(os.path.realpath(app.config["RAVEN_DATA_FOLDER"]) + os.sep)
        for p in file_handler_paths()
    )


def test_app_fixture_handlers_do_not_pile_up(app):
    # ...and the previous test's is gone again: one raven.log handler at a time
    raven_logs = [p for p in file_handler_paths() if p.endswith(os.sep + "raven.log")]
    assert len(raven_logs) == 1
    assert raven_logs[0].startswith(os.path.realpath(app.config["RAVEN_DATA_FOLDER"]) + os.sep)
