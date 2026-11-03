import ssl
import traceback

from raven.cert_revocation import is_revoked, normalize_serial
from raven.eud_handler.EudHandler import EudHandler


def handshake_failure_reason(e: BaseException) -> str:
    """One line on why a TLS handshake failed: the OpenSSL reason (HTTP_REQUEST,
    PEER_DID_NOT_RETURN_A_CERTIFICATE, UNEXPECTED_EOF_WHILE_READING...) or the socket error."""
    if isinstance(e, ssl.SSLCertVerificationError) and e.verify_message:
        return f"{e.reason}: {e.verify_message}"
    if isinstance(e, ssl.SSLError) and e.reason:
        return e.reason
    return f"{type(e).__name__}: {e}"


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
        except OSError as e:
            # ssl.SSLError, resets, EOFs and timeouts: mostly internet scanners probing the port
            # (plain HTTP, no client certificate, old TLS versions), or a revoked certificate.
            # Expected and not actionable, so one line rather than a traceback.
            self.logger.warning(
                "TLS handshake with {} failed: {}".format(
                    self.client_address[0], handshake_failure_reason(e)
                )
            )
            self.close_connection()
            return

        try:
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
            # Make this connection reachable by its cert serial (revocation kick) now that
            # it's known; the RabbitMQ channel may or may not be open yet
            self.request_cert_control_queue()
            for c in peer_cert.get("subject", ()):
                if c[0][0] == "commonName":
                    self.common_name = c[0][1]
                    self.logger.debug("Got common name {}".format(self.common_name))

                    with self.app.app_context():
                        self.user = self.app.security.datastore.find_user(username=self.common_name)
                        self.handle_auth("")
        except BaseException as e:
            self.logger.error(
                "Failed to set up the connection from {}: {}".format(self.client_address[0], e)
            )
            self.logger.error(traceback.format_exc())
            self.close_connection()
