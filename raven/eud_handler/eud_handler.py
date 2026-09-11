import argparse
import logging
import os
import platform
import sys
from logging.handlers import TimedRotatingFileHandler

import colorlog
import flask_wtf
import yaml
from apscheduler.jobstores import sqlalchemy
from flask import Flask, jsonify
from flask_babel import gettext
from flask_security import SQLAlchemyUserDatastore, Security
from flask_security.models import fsqla
from sqlalchemy import update

from raven.EmailValidator import EmailValidator
from raven.PasswordValidator import PasswordValidator
from raven.defaultconfig import DefaultConfig
from raven.eud_handler.EudHandler import EudHandler
from raven.eud_handler.EudHandlerSSL import EudHandlerSSL
from raven.eud_handler.EudServer import EudServer
from raven.eud_handler.EudServerSSL import EudServerSSL
from raven.eud_handler.EudServerUdp import EudServerUdp
from raven.extensions import logger, db, ldap_manager
from raven.models.EUD import EUD


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ssl", help="Enable SSL", default=False, action=argparse.BooleanOptionalAction
    )
    parser.add_argument(
        "--udp", help=gettext("UDP Server"), default=False, action=argparse.BooleanOptionalAction
    )
    return parser.parse_args()


def setup_logging(app):
    level = logging.INFO
    if app.config.get("DEBUG"):
        level = logging.DEBUG
    logger.setLevel(level)

    if sys.stdout.isatty():
        color_log_handler = colorlog.StreamHandler()
        color_log_formatter = colorlog.ColoredFormatter(
            "%(log_color)s[%(asctime)s] - eud_handler[%(process)d] - %(module)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S %Z",
        )
        color_log_handler.setFormatter(color_log_formatter)
        color_log_handler.set_name("eud_handler")
        logger.addHandler(color_log_handler)

    opts = args()
    log_file_name = "eud_handler_tcp.log"
    if opts.ssl:
        log_file_name = "eud_handler_ssl.log"
    if opts.udp:
        log_file_name = "eud_handler_udp.log"

    os.makedirs(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs"), exist_ok=True)
    fh = TimedRotatingFileHandler(
        os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs", log_file_name),
        when=app.config.get("RAVEN_LOG_ROTATE_WHEN"),
        interval=app.config.get("RAVEN_LOG_ROTATE_INTERVAL"),
        backupCount=app.config.get("RAVEN_BACKUP_COUNT"),
    )
    fh.setFormatter(
        logging.Formatter(
            "[%(asctime)s] - eud_handler[%(process)d] - %(module)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s"
        )
    )
    logger.addHandler(fh)
    return logger


def create_app():
    app = Flask(__name__)
    app.config.from_object(DefaultConfig)

    # Load config.yml if it exists
    if os.path.exists(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "config.yml")):
        app.config.from_file(
            os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "config.yml"), load=yaml.safe_load
        )
    else:
        # First run, created config.yml based on default settings
        logger.info("Creating config.yml")
        with open(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "config.yml"), "w") as config:
            conf = {}
            for option in DefaultConfig.__dict__:
                # Fix the sqlite DB path on Windows
                if (
                    option == "SQLALCHEMY_DATABASE_URI"
                    and platform.system() == "Windows"
                    and DefaultConfig.__dict__[option].startswith("sqlite")
                ):
                    conf[option] = (
                        DefaultConfig.__dict__[option].replace("////", "///").replace("\\", "/")
                    )
                elif option.isupper():
                    conf[option] = DefaultConfig.__dict__[option]
            config.write(yaml.safe_dump(conf))

    setup_logging(app)
    db.init_app(app)

    if app.config.get("RAVEN_ENABLE_LDAP"):
        logger.info("Enabling LDAP")
        ldap_manager.init_app(app)

    # The rest is required by flask, leave it in
    try:
        fsqla.FsModels.set_db_info(db)
    except sqlalchemy.exc.InvalidRequestError:
        pass

    from raven.models.role import Role
    from raven.models.user import User

    flask_wtf.CSRFProtect(app)
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    app.security = Security(
        app, user_datastore, mail_util_cls=EmailValidator, password_util_cls=PasswordValidator
    )

    return app


app = create_app()


@app.route("/status")
def status():
    return jsonify({"status": "ok"})


def main():
    opts = args()
    if opts.ssl and opts.udp:
        logger.error("Cannot use --ssl and --udp at the same time")
        return

    # Every socket this process was holding is gone the instant it
    # (re)starts, but nothing else ever tells cot_parser a uid disconnected
    # except that uid's own handler thread noticing (a clean close, or a
    # TCP keepalive/recv failure) -- neither of which gets a chance to run
    # when the process itself dies (a deploy, a crash, `systemctl
    # restart`). Left alone, a device's EUD row can stay "Connected"
    # forever once it stops reconnecting, since nothing after this point
    # would ever flip it back. Reconcile it here instead: any row still
    # marked "Connected" predates this process, so it's stale by definition.
    with app.app_context():
        db.session.execute(
            update(EUD).where(EUD.last_status == "Connected").values(last_status="Disconnected")
        )
        db.session.commit()

    if opts.ssl:
        socket_server = EudServerSSL(
            (app.config.get("RAVEN_STREAMING_INTERFACE"), app.config.get("RAVEN_SSL_STREAMING_PORT")),
            EudHandlerSSL,
            logger,
            app,
        )
        logger.info(f"Started SSL server on port {app.config.get('RAVEN_SSL_STREAMING_PORT')}")
    elif opts.udp:
        socket_server = EudServerUdp(
            (app.config.get("RAVEN_STREAMING_INTERFACE"), app.config.get("RAVEN_UDP_PORT")),
            EudHandler,
            logger,
            app,
        )
    else:
        socket_server = EudServer(
            (app.config.get("RAVEN_STREAMING_INTERFACE"), app.config.get("RAVEN_TCP_STREAMING_PORT")),
            EudHandler,
            logger,
            app,
        )
        logger.info(f"Started TCP server on port {app.config.get('RAVEN_TCP_STREAMING_PORT')}")

    try:
        socket_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server")


if __name__ == "__main__":
    main()
