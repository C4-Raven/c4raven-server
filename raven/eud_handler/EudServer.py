import errno
import socketserver
import ssl
import sys

# Errors that only mean the client went away (or never completed TLS): reset, broken pipe,
# "transport endpoint is not connected" on a socket the peer already dropped, timeouts
CLIENT_GONE_ERRNOS = {errno.ENOTCONN, errno.EPIPE, errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT}


def is_client_disconnect(e: BaseException) -> bool:
    # A refused connection or a certificate that fails verification after the client's handshake
    # is done can only come from a connection the handler opened itself (RabbitMQ, LDAP, an HTTP
    # call...): a server-side problem that needs its traceback
    if isinstance(e, (ConnectionRefusedError, ssl.SSLCertVerificationError)):
        return False
    if isinstance(e, (ConnectionError, TimeoutError, ssl.SSLError)):
        return True
    return isinstance(e, OSError) and e.errno in CLIENT_GONE_ERRNOS


class EudServer(socketserver.ForkingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    logger = None
    port = 8088
    max_children = 9999999

    def __init__(self, server_address, eud_handler, logger, app_context):
        self.server_address = server_address
        self.logger = logger
        self.app_context = app_context
        super().__init__(server_address, eud_handler)

    def server_bind(self):
        super().server_bind()

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

    def handle_error(self, request, client_address):
        """Called (in the forked child) when the handler raised. socketserver's default prints a
        traceback to stderr, which flooded raven.log with clients dropping mid-connection.
        A disconnect is one line here; anything else is a bug and keeps its traceback."""
        e = sys.exc_info()[1]
        if e is not None and is_client_disconnect(e):
            self.logger.warning(
                "Connection from {}:{} dropped: {}: {}".format(
                    client_address[0], client_address[1], type(e).__name__, e
                )
            )
        else:
            self.logger.error(
                "Exception while handling the connection from {}:{}".format(*client_address[:2]),
                exc_info=True,
            )
