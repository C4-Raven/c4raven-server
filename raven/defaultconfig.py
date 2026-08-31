import os
import random
import secrets
import string
from pathlib import Path

import pyotp


class DefaultConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex())
    DEBUG = os.getenv("DEBUG", "False").lower() in ["true", "1", "yes"]

    RAVEN_LANGUAGES = {
        "US": {"name": "English", "language_code": "en"},
        "DE": {"name": "Deutsch", "language_code": "de"},
        "FR": {"name": "Français", "language_code": "fr"},
        "PT": {"name": "Português", "language_code": "pt"},
        "ES": {"name": "Español", "language_code": "es"},
        "DK": {"name": "dansk", "language_code": "da"},
        "UA": {"name": "українська", "language_code": "uk"},
        "KR": {"name": "한국어", "language_code": "ko"},
        "PL": {"name": "Polski", "language_code": "pl"},
        "BR": {"name": "Português", "language_code": "pt_BR"},
        "IT": {"name": "Italiano", "language_code": "it"},
        "JA": {"name": "日本語", "language_code": "ja"},
        "NL": {"name": "Nederlands", "language_code": "nl"},
        "CN": {"name": "简化字", "language_code": "zh_Hans"},
        "SE": {"name": "Svenska", "language_code": "sv"},
        "TH": {"name": "ภาษาไทย", "language_code": "th"},
    }

    RAVEN_DATA_FOLDER = os.getenv("RAVEN_DATA_FOLDER", os.path.join(Path.home(), "ots"))
    RAVEN_LISTENER_ADDRESS = os.getenv("RAVEN_LISTENER_ADDRESS", "127.0.0.1")
    RAVEN_LISTENER_PORT = int(os.getenv("RAVEN_LISTENER_PORT", 8081))
    RAVEN_MARTI_HTTP_PORT = int(os.getenv("RAVEN_MARTI_HTTP_PORT", 8080))
    RAVEN_MARTI_HTTPS_PORT = int(os.getenv("RAVEN_MARTI_HTTPS_PORT", 8443))
    RAVEN_ENABLE_TCP_STREAMING_PORT = os.getenv("RAVEN_ENABLE_TCP_STREAMING_PORT", "True").lower() in [
        "true",
        "1",
        "yes",
    ]
    RAVEN_UDP_PORT = int(os.getenv("RAVEN_UDP_PORT", 8087))
    RAVEN_TCP_STREAMING_PORT = int(os.getenv("RAVEN_TCP_STREAMING_PORT", 8088))
    RAVEN_SSL_STREAMING_PORT = int(os.getenv("RAVEN_SSL_STREAMING_PORT", 8089))
    RAVEN_STREAMING_INTERFACE = os.getenv("RAVEN_STREAMING_INTERFACE", "0.0.0.0")
    RAVEN_BACKUP_COUNT = int(os.getenv("RAVEN_BACKUP_COUNT", 7))
    RAVEN_ENABLE_CHANNELS = os.getenv("RAVEN_ENABLE_CHANNELS", "True").lower() in ["true", "1", "yes"]

    # RabbitMQ Settings
    RAVEN_RABBITMQ_SERVER_ADDRESS = os.getenv("RAVEN_RABBITMQ_SERVER_ADDRESS", "127.0.0.1")
    RAVEN_RABBITMQ_USERNAME = os.getenv("RAVEN_RABBITMQ_USERNAME", "guest")
    RAVEN_RABBITMQ_PASSWORD = os.getenv("RAVEN_RABBITMQ_PASSWORD", "guest")
    # Messages queued in RabbitMQ will auto-delete after 1 day if not consumed https://www.rabbitmq.com/docs/ttl
    # Set to '0' to disable auto-deletion
    RAVEN_RABBITMQ_TTL = "86400000"
    # How many CoT messages that cot_parser processes should prefetch. https://www.rabbitmq.com/docs/consumer-prefetch
    RAVEN_RABBITMQ_PREFETCH = 2

    # TAK.gov account link settings
    RAVEN_TAK_GOV_LINKED = False
    RAVEN_TAK_GOV_ACCESS_TOKEN = ""
    RAVEN_TAK_GOV_REFRESH_TOKEN = ""

    RAVEN_MEDIAMTX_ENABLE = os.getenv("RAVEN_MEDIAMTX_ENABLE", "True").lower() in ["true", "1", "yes"]
    RAVEN_MEDIAMTX_API_ADDRESS = os.getenv("RAVEN_MEDIAMTX_API_ADDRESS", "http://localhost:9997")
    RAVEN_MEDIAMTX_TOKEN = os.getenv("RAVEN_MEDIAMTX_TOKEN", secrets.token_urlsafe(30 * 3 // 4))

    # Federation Hub admin API. Raven authenticates to it with a dedicated mTLS
    # client cert (fedhub-admin) rather than a user-facing login, so browsers
    # never need that cert installed -- Raven proxies the calls.
    RAVEN_FEDHUB_ENABLE = os.getenv("RAVEN_FEDHUB_ENABLE", "True").lower() in ["true", "1", "yes"]
    # Must be the hostname the Federation Hub server cert was issued for
    # (tak.c4raven.net) -- 127.0.0.1 fails TLS hostname verification.
    RAVEN_FEDHUB_API_ADDRESS = os.getenv("RAVEN_FEDHUB_API_ADDRESS", "https://tak.c4raven.net:9100/api")
    RAVEN_FEDHUB_CLIENT_CERT = os.getenv(
        "RAVEN_FEDHUB_CLIENT_CERT", "/opt/tak/federation-hub/certs/files/fedhub-admin.pem"
    )
    RAVEN_FEDHUB_CLIENT_KEY = os.getenv(
        "RAVEN_FEDHUB_CLIENT_KEY", "/opt/tak/federation-hub/certs/files/fedhub-admin-unencrypted.key"
    )
    # Federation Hub's UI (port 9100) now presents a public Let's Encrypt cert
    # rather than the private C4Raven-FedHub-CA (the broker on 9101/9102 still
    # uses the private CA -- unaffected), so trust the system's default CA
    # bundle here instead of pinning to that private CA's file.
    RAVEN_FEDHUB_CA_BUNDLE = os.getenv("RAVEN_FEDHUB_CA_BUNDLE") or True
    RAVEN_SSL_VERIFICATION_MODE = int(os.getenv("RAVEN_SSL_VERIFICATION_MODE", 2))
    RAVEN_SSL_CERT_HEADER = os.getenv("RAVEN_SSL_CERT_HEADER", "X-Ssl-Cert")
    RAVEN_NODE_ID = os.getenv(
        "RAVEN_NODE_ID", "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
    )

    # Certificate Authority Settings
    RAVEN_CA_NAME = os.getenv("RAVEN_CA_NAME", "Raven-CA")
    RAVEN_CA_FOLDER = os.getenv("RAVEN_CA_FOLDER", os.path.join(RAVEN_DATA_FOLDER, "ca"))
    RAVEN_CA_PASSWORD = os.getenv("RAVEN_CA_PASSWORD", "atakatak")
    RAVEN_CA_EXPIRATION_TIME = int(os.getenv("RAVEN_CA_EXPIRATION_TIME", 3650))
    RAVEN_CA_COUNTRY = os.getenv("RAVEN_CA_COUNTRY", "WW")
    RAVEN_CA_STATE = os.getenv("RAVEN_CA_STATE", "XX")
    RAVEN_CA_CITY = os.getenv("RAVEN_CA_CITY", "YY")
    RAVEN_CA_ORGANIZATION = os.getenv("RAVEN_CA_ORGANIZATION", "ZZ")
    RAVEN_CA_ORGANIZATIONAL_UNIT = os.getenv("RAVEN_CA_ORGANIZATIONAL_UNIT", "Raven")
    RAVEN_CA_SUBJECT = os.getenv(
        "RAVEN_CA_SUBJECT",
        f"/C={RAVEN_CA_COUNTRY}/ST={RAVEN_CA_STATE}/L={RAVEN_CA_CITY}/O={RAVEN_CA_ORGANIZATION}/OU={RAVEN_CA_ORGANIZATIONAL_UNIT}",
    )

    RAVEN_COT_PARSER_PROCESSES = int(os.getenv("RAVEN_COT_PARSER_PROCESSES", 1))

    RAVEN_ENABLE_LDAP = False
    # LDAP users in this group will be considered Raven administrators
    RAVEN_LDAP_ADMIN_GROUP = "raven_admin"

    # Attributes to control a user's team color, role, and callsign. The default values match takserver's attributes
    RAVEN_LDAP_COLOR_ATTRIBUTE = "colorAttribute"
    RAVEN_LDAP_ROLE_ATTRIBUTE = "roleAttribute"
    RAVEN_LDAP_CALLSIGN_ATTRIBUTE = "callsignAttribute"

    # LDAP user attributes with this prefix can be used to control ATAK settings for a specific user
    RAVEN_LDAP_PREFERENCE_ATTRIBUTE_PREFIX = "ots_"
    RAVEN_LDAP_GROUP_PREFIX = "ots_"

    # Flask-LDAP3-Login settings
    LDAP_HOST = "127.0.0.1"
    LDAP_BASE_DN = ""
    LDAP_USER_DN = ""
    LDAP_GROUP_DN = ""
    LDAP_BIND_USER_DN = "cn=admin,ou=users=dc=example,dc=com"
    LDAP_BIND_USER_PASSWORD = "password"

    # See https://docs.python.org/3/library/logging.handlers.html#logging.handlers.TimedRotatingFileHandler
    RAVEN_LOG_ROTATE_WHEN = os.getenv("RAVEN_LOG_ROTATE_WHEN", "midnight")
    RAVEN_LOG_ROTATE_INTERVAL = int(os.getenv("RAVEN_LOG_ROTATE_INTERVAL", 0))

    # ADS-B Settings
    RAVEN_ADSB_LAT = 40.744213
    RAVEN_ADSB_LON = -73.986939
    RAVEN_ADSB_RADIUS = 10
    RAVEN_ADSB_API_URL = "https://api.airplanes.live/v2/point/"
    RAVEN_ADSB_API_KEY = None

    RAVEN_ADSB_GROUP = "ADS-B"
    RAVEN_AIS_GROUP = "AIS"

    RAVEN_ENABLE_PLUGINS = True
    RAVEN_PLUGIN_REPO = "https://repo.opentakserver.io/brian/prod/"
    RAVEN_PLUGIN_PREFIXES = ["ots-", "ots_"]

    # AIS Settings
    RAVEN_AISHUB_USERNAME = None
    RAVEN_AISHUB_SOUTH_LAT = None
    RAVEN_AISHUB_WEST_LON = None
    RAVEN_AISHUB_NORTH_LAT = None
    RAVEN_AISHUB_EAST_LON = None
    RAVEN_AISHUB_MMSI_LIST = ""
    RAVEN_AISHUB_IMO_LIST = ""

    RAVEN_PROFILE_MAP_SOURCES = True

    RAVEN_ENABLE_MUMBLE_AUTHENTICATION = False

    RAVEN_IP_WHITELIST = ["127.0.0.1"]

    # Meshtastic settings
    RAVEN_ENABLE_MESHTASTIC = False
    RAVEN_MESHTASTIC_TOPIC = "raven"
    RAVEN_MESHTASTIC_PUBLISH_INTERVAL = 30
    RAVEN_MESHTASTIC_DOWNLINK_CHANNELS = []
    RAVEN_MESHTASTIC_NODEINFO_INTERVAL = 3
    RAVEN_MESHTASTIC_GROUP = "Meshtastic"

    # Email settings
    RAVEN_ENABLE_EMAIL = os.getenv("RAVEN_ENABLE_EMAIL", "False").lower() in ["true", "1", "yes"]
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "False").lower() in ["true", "1", "yes"]
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() in ["true", "1", "yes"]
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", None)
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", None)
    MAIL_DEBUG = False
    MAIL_DEFAULT_SENDER = None
    MAIL_MAX_EMAILS = None
    MAIL_SUPPRESS_SEND = False
    MAIL_ASCII_ATTACHMENTS = False
    RAVEN_EMAIL_DOMAIN_WHITELIST = []
    RAVEN_EMAIL_DOMAIN_BLACKLIST = []
    RAVEN_EMAIL_TLD_WHITELIST = []
    RAVEN_EMAIL_TLD_BLACKLIST = []

    RAVEN_DELETE_OLD_DATA_SECONDS = int(os.getenv("RAVEN_DELETE_OLD_DATA_SECONDS", 0))
    RAVEN_DELETE_OLD_DATA_MINUTES = int(os.getenv("RAVEN_DELETE_OLD_DATA_MINUTES", 0))
    RAVEN_DELETE_OLD_DATA_HOURS = int(os.getenv("RAVEN_DELETE_OLD_DATA_HOURS", 0))
    RAVEN_DELETE_OLD_DATA_DAYS = int(os.getenv("RAVEN_DELETE_OLD_DATA_DAYS", 0))
    RAVEN_DELETE_OLD_DATA_WEEKS = int(os.getenv("RAVEN_DELETE_OLD_DATA_WEEKS", 1))

    # flask-sqlalchemy
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "SQLALCHEMY_DATABASE_URI", f"postgresql+psycopg://ots:POSTGRESQL_PASSWORD@127.0.0.1/ots"
    )
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() in ["true", "1", "yes"]
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = False

    ALLOWED_EXTENSIONS = os.getenv(
        "ALLOWED_EXTENSIONS", "zip,xml,txt,pdf,png,jpg,jpeg,gif,kml,kmz,p12,tif,sqlite"
    ).split(",")

    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(RAVEN_DATA_FOLDER, "uploads"))
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    # Flask-Security-Too
    SECURITY_PASSWORD_SALT = os.getenv(
        "SECURITY_PASSWORD_SALT", str(secrets.SystemRandom().getrandbits(128))
    )
    REMEMBER_COOKIE_SAMESITE = "strict"
    SESSION_COOKIE_SAMESITE = "strict"
    SECURITY_USERNAME_ENABLE = True
    SECURITY_USERNAME_REQUIRED = True
    SECURITY_TRACKABLE = True
    SECURITY_CSRF_COOKIE_NAME = "XSRF-TOKEN"
    WTF_CSRF_TIME_LIMIT = None
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS = True
    WTF_CSRF_CHECK_DEFAULT = False
    SECURITY_RETURN_GENERIC_RESPONSES = True
    SECURITY_URL_PREFIX = "/api"
    SECURITY_CHANGEABLE = True
    SECURITY_CHANGE_URL = "/password/change"
    SECURITY_RESET_URL = "/password/reset"
    SECURITY_PASSWORD_LENGTH_MIN = 8
    SECURITY_PASSWORD_CONFIRM_REQUIRED = False
    SECURITY_REGISTERABLE = RAVEN_ENABLE_EMAIL
    SECURITY_CONFIRMABLE = RAVEN_ENABLE_EMAIL
    SECURITY_RECOVERABLE = RAVEN_ENABLE_EMAIL
    SECURITY_TWO_FACTOR = True
    SECURITY_TOTP_SECRETS = {1: os.getenv("SECURITY_TOTP_SECRET", pyotp.random_base32())}
    SECURITY_TOTP_ISSUER = os.getenv("SECURITY_TOTP_ISSUER", "Raven")
    SECURITY_TWO_FACTOR_ENABLED_METHODS = ["authenticator", "email"]
    SECURITY_TWO_FACTOR_RESCUE_MAIL = MAIL_USERNAME
    SECURITY_TWO_FACTOR_ALWAYS_VALIDATE = False
    SECURITY_CSRF_PROTECT_MECHANISMS = ["session", "basic"]
    SECURITY_LOGIN_WITHOUT_CONFIRMATION = True
    SECURITY_POST_CONFIRM_VIEW = "/login"
    SECURITY_REDIRECT_BEHAVIOR = "spa"
    SECURITY_RESET_VIEW = "/reset"
    SECURITY_USERNAME_MIN_LENGTH = 1
    SECURITY_MSG_USERNAME_DISALLOWED_CHARACTERS = (
        "Username can contain only letters, numbers, underscores, and periods",
        "error",
    )

    SCHEDULER_API_ENABLED = False
    JOBS = [
        {
            "id": "get_adsb_data",
            "func": "raven.blueprints.scheduled_jobs:get_adsb_data",
            "trigger": "interval",
            "seconds": 0,
            "minutes": 1,
            "next_run_time": None,
        },
        {
            "id": "delete_video_recordings",
            "func": "raven.blueprints.scheduled_jobs:delete_video_recordings",
            "trigger": "interval",
            "seconds": 0,
            "minutes": 1,
            "next_run_time": None,
        },
        {
            "id": "purge_data",
            "func": "raven.blueprints.scheduled_jobs:purge_data",
            "trigger": "cron",
            "day": "*",
            "hour": 0,
            "minute": 0,
            "next_run_time": None,
        },
        {
            "id": "ais",
            "func": "raven.blueprints.scheduled_jobs:get_aishub_data",
            "trigger": "interval",
            "seconds": 0,
            "minutes": 1,
            "next_run_time": None,
        },
        {
            "id": "delete_old_data",
            "func": "raven.blueprints.scheduled_jobs:delete_old_data",
            "trigger": "interval",
            "seconds": 0,
            "minutes": 1,
            "next_run_time": None,
        },
    ]
