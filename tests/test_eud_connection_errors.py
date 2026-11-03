"""Clients dropping, and internet scanners probing the streaming ports, are expected: they are
logged as one line, not as tracebacks (socketserver's default handle_error printed one to stderr,
i.e. opentakserver.log, for every connection that reset or that close_connection() found already
gone). Real bugs keep their tracebacks."""

import datetime
import errno
import logging
import socket
import ssl
import threading

import pika
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from raven.eud_handler.EudHandler import EudHandler
from raven.eud_handler.EudHandlerSSL import EudHandlerSSL
from raven.eud_handler.EudServer import EudServer
from raven.extensions import logger


@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.DEBUG, logger=logger.name)
    return caplog


def raven_records(caplog, level):
    return [r for r in caplog.records if r.name == logger.name and r.levelno >= level]


def has_traceback(caplog):
    return any(r.exc_info or "Traceback" in r.getMessage() for r in caplog.records)


class GoneSocket:
    """A socket whose peer already went away: shutdown() fails with ENOTCONN."""

    closed = False

    def shutdown(self, how):
        raise OSError(errno.ENOTCONN, "Transport endpoint is not connected")

    def close(self):
        self.closed = True


def bare_handler(cls=EudHandler, request=None):
    handler = cls.__new__(cls)
    handler.request = request
    handler.client_address = ("203.0.113.7", 40000)
    return handler


# ---------------------------------------------------------------- close_connection


def test_close_connection_tolerates_a_peer_that_is_already_gone(logs):
    sock = GoneSocket()
    handler = bare_handler(request=sock)
    handler.close_connection()
    assert sock.closed and handler.shutdown
    assert not raven_records(logs, logging.WARNING)


def test_close_connection_skips_publishing_on_a_closed_channel():
    class ClosingChannel:
        is_open = False
        is_closing = True
        is_closed = False

        def basic_publish(self, **kwargs):
            raise pika.exceptions.ChannelWrongStateError("Channel is closing.")

    sock = GoneSocket()
    handler = bare_handler(request=sock)
    handler.rabbit_channel = ClosingChannel()
    handler.unbind_rabbitmq_queues = lambda: None
    handler.close_connection()
    assert sock.closed


# ---------------------------------------------------------------- RabbitMQ channel close


def test_own_channel_close_is_not_an_error(logs):
    handler = bare_handler()
    handler.on_channel_close(None, pika.exceptions.ChannelClosedByClient(200, "Normal shutdown"))
    assert handler.shutdown
    assert not raven_records(logs, logging.WARNING)
    assert "203.0.113.7" in logs.text  # says which connection, even before it identified itself


def test_broker_closing_the_channel_is_an_error(logs):
    handler = bare_handler()
    handler.callsign = "ALPHA"
    handler.on_channel_close(None, pika.exceptions.ChannelClosedByBroker(406, "PRECONDITION_FAILED"))
    errors = raven_records(logs, logging.ERROR)
    assert len(errors) == 1 and "ALPHA" in errors[0].getMessage()


# ---------------------------------------------------------------- server handle_error


def _handle_error_with(server, exc):
    try:
        raise exc
    except BaseException:
        server.handle_error(None, ("198.51.100.9", 51515))


def _server():
    server = EudServer.__new__(EudServer)
    server.logger = logger
    return server


@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.ENOTCONN, "Transport endpoint is not connected"),
        ConnectionResetError(errno.ECONNRESET, "Connection reset by peer"),
        BrokenPipeError(errno.EPIPE, "Broken pipe"),
        TimeoutError("timed out"),
        ssl.SSLEOFError(8, "EOF occurred in violation of protocol"),
    ],
)
def test_client_disconnect_is_one_line(logs, exc, capsys):
    _handle_error_with(_server(), exc)
    records = raven_records(logs, logging.WARNING)
    assert len(records) == 1 and records[0].levelno == logging.WARNING
    assert "198.51.100.9" in records[0].getMessage()
    assert not has_traceback(logs)
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "exc",
    [
        KeyError("uid"),
        ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
        ssl.SSLCertVerificationError(1, "certificate verify failed"),
    ],
)
def test_a_real_bug_keeps_its_traceback(logs, exc):
    _handle_error_with(_server(), exc)
    errors = raven_records(logs, logging.ERROR)
    assert len(errors) == 1 and errors[0].exc_info and errors[0].exc_info[0] is type(exc)
    assert "198.51.100.9" in errors[0].getMessage()


# ---------------------------------------------------------------- TLS handshake on 8089


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    folder = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "raven-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = folder / "cert.pem", folder / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)


def _ssl_setup(monkeypatch, tls_files, client):
    """Run EudHandlerSSL.setup() (minus the app/RabbitMQ part) against `client` on a socketpair."""
    monkeypatch.setattr(EudHandler, "setup", lambda self: None)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(*tls_files)
    context.load_verify_locations(cafile=tls_files[0])
    server_sock, client_sock = socket.socketpair()
    client_sock.settimeout(10)
    request = context.wrap_socket(server_sock, server_side=True, do_handshake_on_connect=False)
    peer = threading.Thread(target=client, args=(client_sock,))
    peer.start()
    handler = bare_handler(EudHandlerSSL, request)
    try:
        handler.setup()
    finally:
        peer.join(10)
        client_sock.close()
        request.close()
    return handler


def _plain_http(sock):
    sock.sendall(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
    try:
        sock.recv(1024)
    except OSError:
        pass


def _tls_without_cert(sock):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        tls = context.wrap_socket(sock)
        tls.recv(1024)  # TLS 1.3: the server's alert arrives after the client's handshake ends
    except OSError:
        pass


def _hang_up(sock):
    sock.shutdown(socket.SHUT_RDWR)


@pytest.mark.parametrize(
    "client, reason",
    [
        (_plain_http, "HTTP_REQUEST"),
        (_tls_without_cert, "PEER_DID_NOT_RETURN_A_CERTIFICATE"),
        (_hang_up, "EOF"),
    ],
)
def test_scanner_handshake_failures_are_one_line(logs, monkeypatch, tls_files, client, reason):
    handler = _ssl_setup(monkeypatch, tls_files, client)
    assert handler.shutdown
    warnings = raven_records(logs, logging.WARNING)
    assert len(warnings) == 1 and warnings[0].levelno == logging.WARNING, logs.text
    message = warnings[0].getMessage()
    assert "203.0.113.7" in message and reason in message, message
    assert not has_traceback(logs)


def test_unexpected_setup_errors_keep_their_traceback(logs, monkeypatch, tls_files):
    def client(sock):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(*tls_files)
        try:
            tls = context.wrap_socket(sock)
            tls.recv(1024)
        except OSError:
            pass

    # The handshake succeeds; the bare handler has no app, so the revocation check after it
    # fails with an AttributeError: a bug, not a client problem
    _ssl_setup(monkeypatch, tls_files, client)
    errors = raven_records(logs, logging.ERROR)
    assert any("AttributeError" in r.getMessage() for r in errors)
    assert not any("TLS handshake" in r.getMessage() for r in logs.records)
    assert has_traceback(logs)
