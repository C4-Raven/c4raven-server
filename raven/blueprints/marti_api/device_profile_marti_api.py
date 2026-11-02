import datetime
import io
import os
import re
import traceback
import uuid
import zipfile
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, SubElement, tostring

from flask import Blueprint, Response
from flask import current_app as app
from flask import request
from werkzeug.wsgi import FileWrapper

import raven
from raven import remote_clear
from raven.blueprints.marti_api.certificate_enrollment_api import basic_auth
from raven.blueprints.marti_api.marti_api import verify_client_cert
from raven.blueprints.raven_api.onboard_api import export_onboard_truststore
from raven.device_profiles import resolve_settings, username_for_eud
from raven.extensions import db, ldap_manager, logger
from raven.group_isolation import filter_by_groups
from raven.models.DataPackage import DataPackage
from raven.models.Packages import Packages
from raven.models.Plugins import Plugins

device_profile_marti_api_blueprint = Blueprint("device_profile_marti_api_blueprint", __name__)


def get_ldap_attributes(prefs: Element):
    if app.config.get("RAVEN_ENABLE_LDAP"):
        cert = verify_client_cert()
        if not cert:
            return

        username = cert.get_subject().commonName
        user_info = ldap_manager.get_user_info_for_username(username)

        for field in user_info:
            if field.lower() == app.config.get("RAVEN_LDAP_COLOR_ATTRIBUTE").lower():
                team = SubElement(
                    prefs, "entry", {"key": "locationTeam", "class": "class java.lang.String"}
                )
                team.text = user_info[field][0]

            elif field.lower() == app.config.get("RAVEN_LDAP_ROLE_ATTRIBUTE").lower():
                role = SubElement(
                    prefs, "entry", {"key": "atakRoleType", "class": "class java.lang.String"}
                )
                role.text = user_info[field][0]

            elif field.lower() == app.config.get("RAVEN_LDAP_CALLSIGN_ATTRIBUTE").lower():
                callsign = SubElement(
                    prefs, "entry", {"key": "locationCallsign", "class": "class java.lang.String"}
                )
                callsign.text = user_info[field][0]

            elif field.lower().startswith(
                app.config.get("RAVEN_LDAP_PREFERENCE_ATTRIBUTE_PREFIX").lower()
            ):
                # Remove prefix, case insensitive
                remove_prefix = re.compile(
                    re.escape(app.config.get("RAVEN_LDAP_PREFERENCE_ATTRIBUTE_PREFIX")), re.IGNORECASE
                )
                attribute = remove_prefix.sub("", field)
                subelement = SubElement(
                    prefs, "entry", {"key": attribute, "class": "class java.lang.String"}
                )
                subelement.text = user_info[field][0]


def _set_entry(pref: Element, key: str, value_class: str, value: str):
    """Sets an entry in pref, replacing an existing entry with the same key (so a device profile
    setting overrides one of the built-in entries instead of duplicating it).

    A built-in entry keeps its own class: ATAK reads those keys with a fixed getter (getBoolean
    for deviceProfileEnableOnConnect, ...), and storing e.g. a String there makes it throw on the
    device. A value that doesn't fit the built-in class is dropped. Returns the entry or None."""
    for entry in pref.findall("entry"):
        if entry.get("key") == key:
            builtin_class = entry.get("class")
            if builtin_class != value_class:
                if builtin_class == "class java.lang.Boolean" and value.strip().lower() in (
                    "true",
                    "false",
                ):
                    value = value.strip().lower()
                elif builtin_class != "class java.lang.String":
                    logger.warning(
                        f"Device profile setting {key} has type {value_class}, but the server "
                        f"sends it as {builtin_class}; ignoring it"
                    )
                    return None
            entry.text = value
            return entry
    entry = SubElement(pref, "entry", {"key": key, "class": value_class})
    entry.text = value
    return entry


# Entries device profiles may not override: the remote clear plugin fails closed without the
# server's real key (an admin typo there would silently disable remote clear), and the update
# server CA location/password describe the truststore this same zip ships.
PROTECTED_KEYS = {
    remote_clear.SERVER_PUBKEY_PREF_KEY,
    "updateServerCaLocation",
    "updateServerCaPassword",
}


def create_profile_zip(
    enrollment=True,
    syncSecago=-1,
    clientUid: str | None = None,
    username: str | None = None,
):
    """
    Builds the device profile data package.

    :param enrollment: Enrollment profile (True) or connection profile (False)
    :param syncSecago: Connection only: seconds since the device last synced. Only settings from
        profiles updated (and data packages/plugins published) within that window are sent.
    :param clientUid: The device's uid, for device-targeted profiles
    :param username: The account the request is for, for user- and group-targeted profiles
    """
    # preference.pref
    prefs = Element("preferences")
    pref = SubElement(prefs, "preference", {"version": "1", "name": "com.atakmap.app_preferences"})

    get_ldap_attributes(pref)

    plugins = None
    data_packages = None
    # Auto-installed data packages are still limited to the groups that may see them
    profile_user = app.security.datastore.find_user(username=username) if username else None
    zip_buffer = io.BytesIO()
    zipf = zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False)

    # MANIFEST file
    manifest = Element("MissionPackageManifest", {"version": "2"})
    config = SubElement(manifest, "Configuration")
    SubElement(config, "Parameter", {"name": "uid", "value": str(uuid.uuid4())})
    SubElement(config, "Parameter", {"name": "name", "value": "Device Profile"})
    SubElement(config, "Parameter", {"name": "onReceiveDelete", "value": "true"})

    contents = SubElement(manifest, "Contents")
    SubElement(
        contents,
        "Content",
        {"ignore": "false", "zipEntry": "5c2bfcae3d98c9f4d262172df99ebac5/preference.pref"},
    )
    SubElement(
        contents,
        "Content",
        {"ignore": "false", "zipEntry": "5c2bfcae3d98c9f4d262172df99ebac5/truststore-root.p12"},
    )

    enable_update_server = SubElement(
        pref, "entry", {"key": "appMgmtEnableUpdateServer", "class": "class java.lang.Boolean"}
    )
    enable_update_server.text = "true"

    update_server_address = SubElement(
        pref, "entry", {"key": "atakUpdateServerUrl", "class": "class java.lang.String"}
    )
    update_server_address.text = f"https://{urlparse(request.url_root).hostname}:{app.config.get('RAVEN_MARTI_HTTPS_PORT')}/api/packages"

    startup_sync = SubElement(
        pref, "entry", {"key": "repoStartupSync", "class": "class java.lang.Boolean"}
    )
    startup_sync.text = "true"

    enable_profiles = SubElement(
        pref, "entry", {"key": "deviceProfileEnableOnConnect", "class": "class java.lang.Boolean"}
    )
    enable_profiles.text = "true"

    ca_location = SubElement(
        pref, "entry", {"key": "updateServerCaLocation", "class": "class java.lang.String"}
    )
    ca_location.text = "/storage/emulated/0/atak/cert/truststore-root.p12"

    ca_password = SubElement(
        pref, "entry", {"key": "updateServerCaPassword", "class": "class java.lang.String"}
    )
    ca_password.text = app.config.get("RAVEN_CA_PASSWORD")

    enable_channels_host = SubElement(
        pref,
        "entry",
        {
            "key": f"prefs_enable_channels_host-{urlparse(request.url_root).hostname}",
            "class": "class java.lang.String",
        },
    )
    enable_channels_host.text = "true"

    enable_channels = SubElement(
        pref, "entry", {"key": "prefs_enable_channels", "class": "class java.lang.String"}
    )
    enable_channels.text = "true" if app.config.get("RAVEN_ENABLE_CHANNELS") else "false"

    if enrollment:
        # Add the maps to the zip
        if app.config.get("RAVEN_PROFILE_MAP_SOURCES") and enrollment:
            maps_path = os.path.join(os.path.dirname(raven.__file__), "maps")
            for root, dirs, map_files in os.walk(maps_path):
                for map in map_files:
                    zipf.writestr(f"maps/{map}", open(os.path.join(maps_path, map), "r").read())
                    SubElement(contents, "Content", {"ignore": "false", "zipEntry": f"maps/{map}"})

        # Not inside the map sources block: with RAVEN_PROFILE_MAP_SOURCES off, enrollment used
        # to skip these (and 500 on the old settings loop)
        plugins = db.session.execute(
            db.session.query(Packages).filter_by(install_on_enrollment=True)
        ).all()
        data_packages = db.session.execute(
            filter_by_groups(
                db.session.query(DataPackage).filter_by(install_on_enrollment=True),
                DataPackage,
                profile_user,
            )
        ).all()
    else:
        # ravenclear: provision the server's public signing key to every
        # connected device. The device plugin fails CLOSED (ignores all remote
        # "clear content" commands) without this pref, so it must always be
        # present in the connection profile. This is a static/always-included
        # entry -- deliberately NOT a DB DeviceProfiles row -- keyed off the
        # server key material under RAVEN_CA_FOLDER. Value is single-line Base64
        # of the SPKI DER public key (the exact wire format the plugin expects).
        ravenclear_pubkey = SubElement(
            pref,
            "entry",
            {"key": remote_clear.SERVER_PUBKEY_PREF_KEY, "class": "class java.lang.String"},
        )
        ravenclear_pubkey.text = remote_clear.public_key_der_b64()

        data_package_query = filter_by_groups(
            db.session.query(DataPackage).filter_by(install_on_connection=True),
            DataPackage,
            profile_user,
        )
        plugins_query = db.session.query(Packages).filter_by(install_on_connection=True)

        if syncSecago > 0:
            publish_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
                seconds=syncSecago
            )
            data_package_query = data_package_query.filter(
                DataPackage.submission_time >= publish_time
            )
            plugins_query = plugins_query.filter(Packages.publish_time >= publish_time)
        # TODO: Support data packages and plugins per EUD

        data_packages = db.session.execute(data_package_query).all()
        plugins = db.session.execute(plugins_query).all()

    # Device profile settings (raven/device_profiles.py), merged for this user/device
    phase = "enrollment" if enrollment else "connection"
    settings = resolve_settings(phase, username, clientUid)
    if not enrollment and syncSecago > 0:
        cutoff = datetime.datetime.now(datetime.timezone.utc).replace(
            tzinfo=None
        ) - datetime.timedelta(seconds=syncSecago)
        updated = _profile_update_times({s["profile_id"] for s in settings})
        settings = [s for s in settings if (updated.get(s["profile_id"]) or cutoff) >= cutoff]
    for setting in settings:
        if setting["key"] in PROTECTED_KEYS:
            logger.warning(
                f"Device profile {setting['profile_name']!r} sets {setting['key']}, which is "
                "reserved; ignoring it"
            )
            continue
        _set_entry(pref, setting["key"], setting["value_class"], setting["value"])

    if plugins:
        for plugin in plugins:
            plugin = plugin[0]

            SubElement(
                contents,
                "Content",
                {
                    "ignore": "false",
                    "zipEntry": f"5c2bfcae3d98c9f4d262172df99ebac5/{plugin.file_name}",
                },
            )
            zipf.write(
                os.path.join(app.config.get("RAVEN_DATA_FOLDER"), "packages", plugin.file_name),
                f"5c2bfcae3d98c9f4d262172df99ebac5/{plugin.file_name}",
            )

    if data_packages:
        for data_package in data_packages:
            data_package = data_package[0]
            SubElement(
                contents,
                "Content",
                {
                    "ignore": "false",
                    "zipEntry": f"5c2bfcae3d98c9f4d262172df99ebac5/{data_package.filename}",
                },
            )
            zipf.write(
                os.path.join(app.config.get("UPLOAD_FOLDER"), f"{data_package.hash}.zip"),
                f"5c2bfcae3d98c9f4d262172df99ebac5/{data_package.filename}",
            )

    zipf.writestr("MANIFEST/manifest.xml", tostring(manifest))

    zipf.writestr("5c2bfcae3d98c9f4d262172df99ebac5/preference.pref", tostring(prefs))

    # Exported fresh under RAVEN_CA_PASSWORD (what updateServerCaPassword says) instead of reading
    # truststore-root.p12, which keeps whatever password it was created with
    zipf.writestr(
        "5c2bfcae3d98c9f4d262172df99ebac5/truststore-root.p12",
        export_onboard_truststore(
            app.config.get("RAVEN_CA_FOLDER"),
            app.config.get("RAVEN_CA_PASSWORD"),
            app.config.get("RAVEN_CA_NAME"),
        ),
    )

    return zip_buffer


def _profile_update_times(profile_ids) -> dict:
    from raven.models.DeviceProfileSet import DeviceProfileSet

    if not profile_ids:
        return {}
    rows = (
        db.session.query(DeviceProfileSet.id, DeviceProfileSet.updated_at)
        .filter(DeviceProfileSet.id.in_(profile_ids))
        .all()
    )
    return dict(rows)


def _client_cert_username() -> str | None:
    """The CN of the client cert nginx verified and forwarded (Raven issues certs with
    CN = username), or None."""
    try:
        cert = verify_client_cert()
    except BaseException as e:
        # A malformed header is just an unverified caller
        logger.warning(f"Unreadable client certificate header: {e}")
        return None
    if not cert:
        return None
    return cert.get_subject().commonName or None


# EUDs hit this endpoint on the enrollment port (8446) right after a successful
# /Marti/api/tls/signClient/v2. ATAK sends the same Basic credentials it enrolled with
# (CertificateEnrollmentClient.executeDeviceProfileRequest -> DeviceProfileClient.getProfile(..,
# username, password, ..) -> DeviceProfileOperation: hasCredentials() -> TakHttpClient.execute(get,
# creds) -> HttpUtil.AddBasicAuthentication), so require them here too: the profile carries the CA
# truststore and the enrollment data packages. A token that signClient just used up is still
# accepted (check_token_max=False) and this request doesn't count as another use.
@device_profile_marti_api_blueprint.route("/Marti/api/tls/profile/enrollment")
def enrollment_profile():
    username = basic_auth(
        request.headers.get("Authorization"), consume_token=False, check_token_max=False
    )
    if not username:
        return "", 401
    # Device-targeted settings only if the device isn't someone else's (the uid is self-declared)
    client_uid = request.args.get("clientUid") or request.args.get("clientUID") or None
    eud_username = username_for_eud(client_uid)
    if eud_username and eud_username.lower() != str(username).lower():
        client_uid = None
    try:
        profile_zip = create_profile_zip(username=username, clientUid=client_uid)
        profile_zip.seek(0)
        return Response(
            FileWrapper(profile_zip), mimetype="application/zip", direct_passthrough=True
        )
    except BaseException as e:
        logger.error(f"Failed to send enrollment package: {e}")
        logger.debug(traceback.format_exc())
        return "", 500


def connection_caller(client_uid: str | None):
    """Who a connection profile request is for: (allowed, username, eud_uid).

    ATAK fetches the connection profile from the streaming connection's host on 8443 over TLS
    with the device's client cert (nginx ssl_verify_client on, forwarded as X-Ssl-Cert), so
    the caller is the cert's CN. Basic credentials are accepted too, for other clients.

    The device-targeted settings only apply if the device (clientUid) is bound to that same
    account, or to none: otherwise anyone with a cert could ask for another device's settings
    by passing its uid.

    With RAVEN_CONNECTION_PROFILE_REQUIRE_AUTH off, unauthenticated callers get the old
    behaviour: whatever clientUid they claim, and that EUD's account.
    """
    eud_username = username_for_eud(client_uid)
    username = _client_cert_username()
    if not username and request.headers.get("Authorization"):
        username = basic_auth(request.headers.get("Authorization"), consume_token=False) or None

    if not username:
        if app.config.get("RAVEN_CONNECTION_PROFILE_REQUIRE_AUTH", True):
            return False, None, None
        return True, eud_username, client_uid

    if eud_username and eud_username.lower() != username.lower():
        logger.warning(
            f"Connection profile: {username} asked for device {client_uid}, which belongs to "
            f"{eud_username}; ignoring its device settings"
        )
        return True, username, None
    return True, username, client_uid


# EUDs hit this endpoint when the app connects to the server if deviceProfileEnableOnConnect
# ("Apply TAK Server profile updates") is on; the enrollment profile above turns it on.
@device_profile_marti_api_blueprint.route("/api/connection")
@device_profile_marti_api_blueprint.route("/Marti/api/device/profile/connection")
def connection_profile():
    try:
        syncSecago = -1
        if "syncSecago" in request.args:
            try:
                syncSecago = int(request.args["syncSecago"])
            except ValueError:
                pass
        client_uid = request.args.get("clientUid") or request.args.get("clientUID") or None

        allowed, username, client_uid = connection_caller(client_uid)
        if not allowed:
            return "", 401

        profile_zip = create_profile_zip(False, syncSecago, client_uid, username)
        profile_zip.seek(0)
        return Response(
            FileWrapper(profile_zip), mimetype="application/zip", direct_passthrough=True
        )
    except BaseException as e:
        logger.error(f"Failed to send enrollment package: {e}")
        logger.debug(traceback.format_exc())
        return "", 500
