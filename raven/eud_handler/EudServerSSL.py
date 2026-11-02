import datetime
import os
import socket
import socketserver
import ssl

from raven.eud_handler.EudServer import EudServer


class EudServerSSL(EudServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, eud_handler, logger, app_context):
        super().__init__(server_address, eud_handler, logger, app_context)

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # The listening socket stays plain TCP: get_request() wraps each accepted connection
        # with the current SSL context instead, so a new CRL (a certificate was revoked) is
        # picked up by the next handshake without a restart. Wrapping the listening socket
        # would pin every future connection to the context it was created with.
        self._ssl_context = None
        self._crl_key = None
        self._refresh_ssl_context()
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.logger.debug(f"listening on {self.server_address}")

    def _ca_path(self, *parts):
        return os.path.join(self.app_context.config.get("RAVEN_CA_FOLDER"), *parts)

    def _crl_stat_key(self):
        try:
            stat = os.stat(self._ca_path("ca.crl"))
            return stat.st_mtime_ns, stat.st_size, stat.st_ino
        except OSError:
            return None

    def _build_ssl_context(self):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.load_cert_chain(
            self._ca_path("certs", "raven", "raven.pem"),
            self._ca_path("certs", "raven", "raven.nopass.key"),
        )
        ssl_context.load_verify_locations(cafile=self._ca_path("ca.pem"))
        if os.path.exists(self._ca_path("ca.crl")):
            # Checked against the client (leaf) cert only. With this flag set, a handshake
            # fails if the CRL is missing or past its nextUpdate, which is why ensure_crl()
            # keeps it current.
            ssl_context.load_verify_locations(cafile=self._ca_path("ca.crl"))
            ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        else:
            self.logger.warning(
                "No ca.crl in the CA folder, the SSL streaming port can't check revoked certificates"
            )
        return ssl_context

    def _refresh_ssl_context(self):
        """Rebuild the SSL context if ca.crl changed since it was last loaded.

        Called from get_request() in the (single-threaded) accept loop: EudServer is a
        ForkingTCPServer, so connections run in child processes that each got their own copy
        of the context at fork time, and nothing else ever touches self._ssl_context. Swapping
        the reference here is therefore safe; an existing connection is never affected, it was
        already verified (and a revoked one is dropped through eud_control, see EudHandler)."""
        key = self._crl_stat_key()
        if self._ssl_context is not None and key == self._crl_key:
            return self._ssl_context

        if key is not None:
            # An expired CRL would fail every handshake; regenerate it rather than lock everyone out
            try:
                from raven.cert_revocation import crl_next_update, ensure_crl

                next_update = crl_next_update(self._ca_path())
                if next_update and next_update <= datetime.datetime.now(datetime.timezone.utc):
                    ensure_crl(
                        self._ca_path(),
                        self.app_context.config.get("RAVEN_CA_PASSWORD"),
                        self.logger,
                    )
                    key = self._crl_stat_key()
            except BaseException as e:
                self.logger.error(f"Failed to regenerate the expired CRL: {e}")

        try:
            self._ssl_context = self._build_ssl_context()
            if self._crl_key is not None:
                self.logger.info("ca.crl changed, reloaded the SSL context")
        except BaseException as e:
            if self._ssl_context is None:
                raise
            # A broken CRL mid-write or similar: keep verifying with the previous one
            self.logger.error(f"Failed to reload the SSL context, keeping the previous one: {e}")
        self._crl_key = key
        return self._ssl_context

    def get_request(self):
        connection, client_address = self.socket.accept()
        try:
            ssl_context = self._refresh_ssl_context()
            return (
                ssl_context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False),
                client_address,
            )
        except BaseException:
            connection.close()
            raise

    def server_activate(self):
        self.logger.debug("server activated")
        super().server_activate()

    def server_close(self):
        self.logger.debug("server closed")
        super().server_close()

    def process_request_thread(self, request, client_address):
        self.logger.debug("processing request thread")
        super().process_request_thread(request, client_address)

    def process_request(self, request, client_address):
        self.logger.debug("processing request")
        super().process_request(request, client_address)
