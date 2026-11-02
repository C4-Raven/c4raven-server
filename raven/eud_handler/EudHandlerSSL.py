import traceback

from raven.cert_revocation import is_revoked, normalize_serial
from raven.eud_handler.EudHandler import EudHandler


class EudHandlerSSL(EudHandler):

    timeout = 1.0
    shutdown = False
    common_name = None
    user = None
    is_ssl = True

    def setup(self):
        super().setup()

        try:
            self.request.settimeout(10)
            self.request.do_handshake()
            self.request.settimeout(None)
            peer_cert = self.request.getpeercert() or {}
            self.cert_serial = normalize_serial(peer_cert.get("serialNumber"))
            # The handshake already checked ca.crl. This checks the CA's index directly as well,
            # in case the CRL couldn't be regenerated or reloaded after a revocation.
            if self.cert_serial and is_revoked(
                self.app.config.get("RAVEN_CA_FOLDER"), self.cert_serial
            ):
                self.logger.warning(
                    "Client cert serial {} from {} is revoked, disconnecting".format(
                        self.cert_serial, self.client_address[0]
                    )
                )
                self.close_connection()
                return
            for c in peer_cert.get("subject", ()):
                if c[0][0] == "commonName":
                    self.common_name = c[0][1]
                    self.logger.debug("Got common name {}".format(self.common_name))

                    with self.app.app_context():
                        self.user = self.app.security.datastore.find_user(username=self.common_name)
                        self.handle_auth("")
        except BaseException as e:
            self.logger.warning("Failed to do handshake: {}".format(e))
            self.logger.error(traceback.format_exc())
            self.close_connection()
