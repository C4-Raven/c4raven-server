from gevent import monkey

monkey.patch_all()

import logging
import os
import platform
import sqlite3
import sys
import traceback
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import quote

import colorlog
import flask_wtf
import pika
import pytz
import requests
import sqlalchemy
import yaml
from flask import Flask, current_app, g, request, session
from flask_cors import CORS
from flask_migrate import Migrate, upgrade
from flask_security import (
    Security,
    SQLAlchemyUserDatastore,
    hash_password,
    uia_email_mapper,
    uia_username_mapper,
)
from flask_security.models import fsqla_v3
from flask_security.models import fsqla_v3 as fsqla
from flask_security.signals import user_registered
from sqlalchemy import insert
from werkzeug.middleware.proxy_fix import ProxyFix

import raven
from raven.certificate_authority import CertificateAuthority
from raven.controllers.meshtastic_controller import MeshtasticController
from raven.defaultconfig import DefaultConfig
from raven.EmailValidator import EmailValidator
from raven.forms.SiteAccessLoginForm import SiteAccessLoginForm
from raven.extensions import apscheduler, babel, db, ldap_manager, logger, mail, socketio
from raven.models.Group import Group, GroupTypeEnum
from raven.models.Icon import Icon
from raven.models.role import Role
from raven.models.WebAuthn import WebAuthn
from raven.models.CITrap import CITrap
from raven.PasswordValidator import PasswordValidator
from raven.plugins.Plugin import Plugin
from raven.plugins.PluginManager import PluginManager
from raven.sql_jobstore import SQLJobStore
from raven.UsernameValidator import UsernameValidator

try:
    from raven.mumble.mumble_ice_app import MumbleIceDaemon
except ModuleNotFoundError:
    print("Mumble auth not supported on this platform")


def get_locale():
    if "language" in session:
        return session["language"]
    return request.accept_languages.best_match(current_app.config.get("RAVEN_LANGUAGES").keys())


def get_timezone():
    # Always return UTC and let the frontend handle converting timezones
    return pytz.timezone("UTC")


def init_extensions(app):
    db.init_app(app)
    Migrate(app, db)

    logger.info(f"Raven {raven.__version__}")
    logger.info("Loading the database...")
    with app.app_context():
        upgrade(
            directory=os.path.join(
                os.path.dirname(os.path.realpath(raven.__file__)), "migrations"
            )
        )
        # Flask-Migrate does weird things to the logger
        logger.disabled = False
        logger.parent.handlers.pop()
        if app.config.get("DEBUG"):
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

    # Handle config options that can't be serialized to yaml
    app.config.update(
        {
            "SCHEDULER_JOBSTORES": {
                "default": SQLJobStore(url=app.config.get("SQLALCHEMY_DATABASE_URI"))
            }
        }
    )
    identity_attributes = [{"username": {"mapper": uia_username_mapper, "case_insensitive": True}}]

    # Don't allow registration unless email is enabled
    if app.config.get("RAVEN_ENABLE_EMAIL"):
        identity_attributes.append(
            {"email": {"mapper": uia_email_mapper, "case_insensitive": True}}
        )
        app.config.update(
            {
                "SECURITY_REGISTERABLE": True,
                "SECURITY_CONFIRMABLE": True,
                "SECURITY_RECOVERABLE": True,
                "SECURITY_TWO_FACTOR_ENABLED_METHODS": ["authenticator", "email"],
            }
        )
    else:
        app.config.update(
            {
                "SECURITY_REGISTERABLE": False,
                "SECURITY_CONFIRMABLE": False,
                "SECURITY_RECOVERABLE": False,
                "SECURITY_TWO_FACTOR_ENABLED_METHODS": ["authenticator"],
            }
        )

    if app.config.get("RAVEN_ENABLE_LDAP"):
        logger.info("Enabling LDAP")
        ldap_manager.init_app(app)
        identity_attributes.append({"ldap": {}})

    app.config.update({"SECURITY_USER_IDENTITY_ATTRIBUTES": identity_attributes})

    ca = CertificateAuthority(logger, app)
    ca.create_ca()

    cors = CORS(
        app,
        resources={
            r"/api/*": {"origins": "*"},
            r"/Marti/*": {"origins": "*"},
            r"/*": {"origins": "*"},
        },
        supports_credentials=True,
    )
    flask_wtf.CSRFProtect(app)

    socketio_logger = False
    if app.config.get("DEBUG"):
        socketio_logger = logger
    socketio.init_app(
        app,
        logger=socketio_logger,
        ping_timeout=1,
        message_queue="amqp://{}:{}@{}".format(
            quote(app.config.get("RAVEN_RABBITMQ_USERNAME"), safe=""),
            quote(app.config.get("RAVEN_RABBITMQ_PASSWORD"), safe=""),
            app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS"),
        ),
    )

    rabbit_credentials = pika.PlainCredentials(
        app.config.get("RAVEN_RABBITMQ_USERNAME"), app.config.get("RAVEN_RABBITMQ_PASSWORD")
    )
    rabbit_host = app.config.get("RAVEN_RABBITMQ_SERVER_ADDRESS")
    rabbit_connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=rabbit_host, credentials=rabbit_credentials)
    )

    channel = rabbit_connection.channel()
    channel.exchange_declare("dms", durable=True, exchange_type="direct")
    channel.exchange_declare("cot_parser", durable=True, exchange_type="direct")
    channel.exchange_declare("chatrooms", durable=True, exchange_type="direct")
    channel.exchange_declare(
        "missions", durable=True, exchange_type="topic"
    )  # For Data Sync mission feeds
    channel.exchange_declare("groups", durable=True, exchange_type="topic")  # For channels/groups
    channel.exchange_declare(
        "firehose", durable=True, exchange_type="fanout"
    )  # A firehose of all CoT data
    channel.exchange_declare("flask-socketio", durable=False, exchange_type="fanout")
    channel.close()
    rabbit_connection.close()

    if not apscheduler.running:
        apscheduler.init_app(app)
        apscheduler.start(paused=False)

    try:
        fsqla.FsModels.set_db_info(db)
    except sqlalchemy.exc.InvalidRequestError:
        pass

    from raven.models.role import Role
    from raven.models.user import User

    user_datastore = SQLAlchemyUserDatastore(db, User, Role, WebAuthn)
    app.security = Security(
        app,
        user_datastore,
        mail_util_cls=EmailValidator,
        password_util_cls=PasswordValidator,
        username_util_cls=UsernameValidator,
        login_form=SiteAccessLoginForm,
    )

    mail.init_app(app)

    babel.init_app(app, locale_selector=get_locale, timezone_selector=get_timezone)


def setup_logging(app):
    level = logging.INFO
    if app.config.get("DEBUG"):
        level = logging.DEBUG
    logger.setLevel(level)

    if sys.stdout.isatty():
        color_log_handler = colorlog.StreamHandler()
        color_log_formatter = colorlog.ColoredFormatter(
            "%(log_color)s[%(asctime)s] - Raven[%(process)d] - %(module)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S %Z",
        )
        color_log_handler.setFormatter(color_log_formatter)
        logger.addHandler(color_log_handler)
        logger.info("Added color logger")

    os.makedirs(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs"), exist_ok=True)
    fh = TimedRotatingFileHandler(
        os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "logs", "raven.log"),
        when=app.config.get("RAVEN_LOG_ROTATE_WHEN"),
        interval=app.config.get("RAVEN_LOG_ROTATE_INTERVAL"),
        backupCount=app.config.get("RAVEN_BACKUP_COUNT"),
    )
    fh.setFormatter(
        logging.Formatter(
            "[%(asctime)s] - Raven[%(process)d] - %(module)s - %(funcName)s - %(lineno)d - %(levelname)s - %(message)s"
        )
    )
    logger.addHandler(fh)


def create_app(cli=True):
    app = Flask(__name__)
    app.config.from_object(DefaultConfig)
    setup_logging(app)

    if not cli:
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
                    # Don't save a list of languages to the config, use the list in defaultconfig.py instead
                    if option == "RAVEN_LANGUAGES":
                        continue

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

        # Try to set the MediaMTX token
        if app.config.get("RAVEN_MEDIAMTX_ENABLE"):
            try:
                new_conf = None
                with open(
                    os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "mediamtx", "mediamtx.yml"), "r"
                ) as mediamtx_config:
                    conf = mediamtx_config.read()
                    if "MTX_TOKEN" in conf:
                        new_conf = conf.replace("MTX_TOKEN", app.config.get("RAVEN_MEDIAMTX_TOKEN"))
                if new_conf:
                    with open(
                        os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "mediamtx", "mediamtx.yml"),
                        "w",
                    ) as mediamtx_config:
                        mediamtx_config.write(new_conf)
            except BaseException as e:
                logger.error("Failed to set MediaMTX token: {}".format(e))
        else:
            logger.info("MediaMTX disabled")

        init_extensions(app)

        # CUSTOM: force_password_change patch -- new users (see user_api.create_user)
        # are created with force_password_change=True. The Login page (see
        # Raven-UI src/pages/Login/Login.tsx) reads a force_password_change
        # field on the login/tf-validate success response and shows an inline
        # "set a new password" step when it's true, instead of navigating to the
        # dashboard. Everything else stays hard-blocked server-side regardless of
        # what the frontend does, as the actual enforcement boundary.
        _force_pw_change_url = app.config.get("SECURITY_URL_PREFIX", "") + app.config.get(
            "SECURITY_CHANGE_URL", "/password/change"
        )
        _force_pw_logout_url = app.config.get("SECURITY_URL_PREFIX", "") + app.config.get(
            "SECURITY_LOGOUT_URL", "/logout"
        )
        _login_url = app.config.get("SECURITY_URL_PREFIX", "") + app.config.get(
            "SECURITY_LOGIN_URL", "/login"
        )
        _tf_validate_url = app.config.get("SECURITY_URL_PREFIX", "") + app.config.get(
            "SECURITY_TWO_FACTOR_TOKEN_VALIDATION_URL", "/tf-validate"
        )

        @app.after_request
        def _force_password_change_hook(response):
            import json as _json

            from flask import request as _req
            from flask_security import current_user as _current_user

            path = _req.path

            # Unconditional exemption: login/tf-validate/change-password/logout
            # must never be blocked, regardless of what current_user resolves to.
            # In particular, if the browser still carries a session cookie for a
            # DIFFERENT, previously-logged-in flagged account (e.g. switching
            # accounts without logging out first), current_user reflects that
            # OLD identity until this request's own login_user() call replaces
            # it -- which for an account requiring 2FA doesn't happen until
            # tf-validate succeeds. Blocking here would wrongly refuse a brand
            # new login attempt because of an unrelated stale session.
            if path in (_login_url, _tf_validate_url, _force_pw_change_url, _force_pw_logout_url):
                if path in (_login_url, _tf_validate_url) and response.status_code == 200 and response.is_json:
                    try:
                        if _current_user.is_authenticated:
                            data = response.get_json()
                            data.setdefault("response", {})["force_password_change"] = bool(
                                getattr(_current_user, "force_password_change", False)
                            )
                            response.set_data(_json.dumps(data))
                    except Exception:
                        pass
                return response

            try:
                authenticated = _current_user.is_authenticated
            except Exception:
                authenticated = False

            flagged = authenticated and getattr(_current_user, "force_password_change", False)
            if not flagged:
                return response

            response.set_data(
                _json.dumps(
                    {
                        "meta": {"code": 403},
                        "response": {
                            "errors": [
                                "You must change your password before continuing. "
                                "Go to " + _force_pw_change_url + " to set a new one, "
                                "then log in again."
                            ]
                        },
                    }
                )
            )
            response.status_code = 403
            response.mimetype = "application/json"
            return response

        from flask_security.signals import password_changed as _password_changed_signal

        @_password_changed_signal.connect_via(app)
        def _clear_force_password_change(sender, user, **extra):
            if getattr(user, "force_password_change", False):
                user.force_password_change = False
                db.session.add(user)
                db.session.commit()

        from raven.blueprints.marti_api import marti_blueprint

        app.register_blueprint(marti_blueprint)

        from raven.blueprints.raven_api import raven_api

        app.register_blueprint(raven_api)

        from raven.blueprints.raven_socketio import raven_socketio_blueprint

        app.register_blueprint(raven_socketio_blueprint)

        from raven.blueprints.scheduled_jobs import scheduler_blueprint

        app.register_blueprint(scheduler_blueprint)

        # x_proto=1 is this werkzeug version's default already, but pinned
        # explicitly since request.url_root (and everything built from it,
        # e.g. VideoStream.to_json()'s webrtc_link/hls_link) depends on
        # nginx's X-Forwarded-Proto being honored here -- a site block that
        # doesn't set that header makes every such URL come out http:// on
        # an https:// page, which the browser silently blocks as mixed
        # content. (The actual bug hitting that today was a missing
        # X-Forwarded-Proto in nginx itself, not here -- see the certbot
        # site block for tak.c4raven.net.)
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1)

    else:
        from raven.blueprints.cli import raven_cli, translate

        app.cli.add_command(raven_cli, name="raven")
        app.cli.add_command(translate, name="translate")

        if os.path.exists(os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "config.yml")):
            app.config.from_file(
                os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "config.yml"), load=yaml.safe_load
            )
            db.init_app(app)
            Migrate(app, db)

        flask_wtf.CSRFProtect(app)

        try:
            fsqla.FsModels.set_db_info(db)
        except sqlalchemy.exc.InvalidRequestError:
            pass

        from raven.models.role import Role
        from raven.models.user import User

        user_datastore = SQLAlchemyUserDatastore(db, User, Role, WebAuthn)
        app.security = Security(
            app,
            user_datastore,
            mail_util_cls=EmailValidator,
            password_util_cls=PasswordValidator,
            username_util_cls=UsernameValidator,
            login_form=SiteAccessLoginForm,
        )

        # Register blueprints to properly import all the DB models without circular imports
        from raven.blueprints.marti_api import marti_blueprint

        app.register_blueprint(marti_blueprint)

        from raven.blueprints.raven_api import raven_api

        app.register_blueprint(raven_api)

        from raven.blueprints.raven_socketio import raven_socketio_blueprint

        app.register_blueprint(raven_socketio_blueprint)

        from raven.blueprints.scheduled_jobs import scheduler_blueprint

        app.register_blueprint(scheduler_blueprint)

    return app


def create_default_groups(app):
    with app.app_context():
        if not app.config.get("RAVEN_ENABLE_LDAP"):
            anon_group = db.session.execute(
                db.session.query(Group).filter_by(name="__ANON__")
            ).first()

            if not anon_group:
                logger.info("Creating the __ANON__ group")
                anon_group = Group()
                anon_group.name = "__ANON__"
                anon_group.type = GroupTypeEnum.SYSTEM
                anon_group.bitpos = 2
                db.session.add(anon_group)
                db.session.commit()

        if app.config.get("RAVEN_FEDHUB_FEDERATE_ENABLE"):
            # Federation Hub attributes inbound federated CoT to the protected
            # "Server" system account and routes it through
            # RAVEN_FEDHUB_FEDERATE_GROUP ("Fed group" by default) -- see the
            # comments on those two config keys in defaultconfig.py. Both need
            # to exist, and Server needs an IN (write) membership in that
            # group, before federation can work at all; bootstrap them here
            # the same way the system groups above are, so a fresh install
            # doesn't have to repeat this by hand.
            import secrets

            from raven.models.GroupUser import GroupUser
            from raven.models.user import User

            fed_group_name = app.config.get("RAVEN_FEDHUB_FEDERATE_GROUP")
            fed_group = db.session.execute(
                db.session.query(Group).filter_by(name=fed_group_name)
            ).first()
            if not fed_group:
                logger.info(f"Creating the {fed_group_name} group")
                fed_group = Group()
                fed_group.name = fed_group_name
                fed_group.type = GroupTypeEnum.SYSTEM
                fed_group.bitpos = fed_group.get_next_bitpos()
                db.session.add(fed_group)
                db.session.commit()
            else:
                fed_group = fed_group[0]

            server_username = app.config.get("RAVEN_FEDHUB_FEDERATE_USERNAME")
            server_user = db.session.execute(
                db.session.query(User).filter_by(username=server_username)
            ).first()
            if not server_user:
                logger.info(f"Creating the protected '{server_username}' system account")
                server_user = app.security.datastore.create_user(
                    username=server_username,
                    password=hash_password(secrets.token_urlsafe(32)),
                    active=False,
                )
                db.session.commit()
            else:
                server_user = server_user[0]

            membership = db.session.execute(
                db.session.query(GroupUser).filter_by(
                    user_id=server_user.id, group_id=fed_group.id, direction=Group.IN
                )
            ).first()
            if not membership:
                logger.info(f"Adding '{server_username}' to the {fed_group_name} group")
                membership = GroupUser()
                membership.user_id = server_user.id
                membership.group_id = fed_group.id
                membership.direction = Group.IN
                db.session.add(membership)
                db.session.commit()


def main(app):
    with app.app_context():
        # Download the icon sets if they aren't already in the DB
        icons = db.session.query(Icon).count()
        if icons == 0:
            logger.info("Downloading icons...")
            try:
                r = requests.get(
                    "https://github.com/brian7704/OpenTAKServer-Installer/raw/master/iconsets.sqlite",
                    stream=True,
                )
                with open(
                    os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "icons.sqlite"), "wb"
                ) as f:
                    f.write(r.content)

                def dict_factory(cursor, row):
                    d = {}
                    for idx, col in enumerate(cursor.description):
                        d[col[0]] = row[idx]
                    return d

                con = sqlite3.connect(
                    os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "icons.sqlite")
                )
                con.row_factory = dict_factory
                cur = con.cursor()
                rows = cur.execute("SELECT * FROM icons")
                for row in rows:
                    db.session.execute(insert(Icon).values(**row))
                db.session.commit()
            except BaseException as e:
                logger.error("Failed to download icons: {}".format(e))
                logger.debug(traceback.format_exc())

        if app.config.get("DEBUG"):
            logger.debug("Starting in debug mode")
        else:
            logger.info("Starting in production mode")

        app.security.datastore.find_or_create_role(
            name="user", permissions={"user-read", "user-write"}
        )

        app.security.datastore.find_or_create_role(
            name="administrator", permissions={"administrator"}
        )

        # Make sure at least one admin user exists
        admin_user = db.session.execute(
            db.session.query(Role)
            .join(fsqla_v3.FsModels.roles_users)
            .where(Role.name == "administrator")
        ).scalar()
        if not admin_user:
            logger.info("Creating administrator account. The password is 'password'")
            app.security.datastore.create_user(
                username="administrator",
                password=hash_password("password"),
                roles=["administrator"],
            )
        db.session.commit()

    if app.config.get("RAVEN_ENABLE_MESHTASTIC"):
        mestastic_thread = MeshtasticController(app.app_context())
        app.mestastic_thread = mestastic_thread
    else:
        app.meshtastic_thread = None

    if app.config.get("RAVEN_ENABLE_MUMBLE_AUTHENTICATION"):
        try:
            logger.info("Starting Mumble authentication handler")
            mumble_daemon = MumbleIceDaemon(app, logger)
            mumble_daemon.daemon = True
            mumble_daemon.start()
        except BaseException as e:
            logger.error("Failed to enable Mumble authentication: {}".format(e))
            logger.error(traceback.format_exc())
    else:
        logger.info("Mumble authentication handler disabled")

    # The Federation Hub bridge runs as its own systemd service
    # (fedhub_bridge.service, raven.controllers.federation_hub_daemon), not
    # in this process -- see that module's docstring for why. Nothing to do
    # here.

    if app.config.get("RAVEN_ENABLE_PLUGINS"):
        try:
            app.plugin_manager = PluginManager(Plugin.group, app)
            app.plugin_manager.load_plugins()
            app.plugin_manager.activate(app)
        except BaseException as e:
            logger.error(f"Failed to load plugins: {e}")
            logger.debug(traceback.format_exc())

    app.start_time = datetime.now(timezone.utc)

    create_default_groups(app)

    try:
        socketio.run(
            app,
            host=app.config.get("RAVEN_LISTENER_ADDRESS"),
            port=app.config.get("RAVEN_LISTENER_PORT"),
            debug=app.config.get("DEBUG"),
            log_output=app.config.get("DEBUG"),
            use_reloader=False,
        )
    except KeyboardInterrupt:
        logger.warning("Caught CTRL+C, exiting...")
        if app.config.get("RAVEN_ENABLE_PLUGINS"):
            app.plugin_manager.stop_plugins()


def start():
    app = create_app(cli=False)

    @user_registered.connect_via(app)
    def user_registered_sighandler(app, user, confirmation_token, **kwargs):
        default_role = app.security.datastore.find_or_create_role(
            name="user", permissions={"user-read", "user-write"}
        )
        app.security.datastore.add_role_to_user(user, default_role)

        # Give self-registered users the same default __ANON__ membership
        # admin-created ones get (see _add_to_anon_group in user_api.py) so
        # they can see and be seen without an admin adding them to a group
        # first.
        anon_group = db.session.execute(
            db.session.query(Group).filter_by(name="__ANON__")
        ).first()
        if anon_group:
            anon_group = anon_group[0]
            from raven.models.GroupUser import GroupUser

            for direction in (Group.IN, Group.OUT):
                membership = GroupUser()
                membership.user_id = user.id
                membership.group_id = anon_group.id
                membership.direction = direction
                db.session.add(membership)
            try:
                db.session.commit()
            except sqlalchemy.exc.IntegrityError:
                db.session.rollback()

    main(app)
