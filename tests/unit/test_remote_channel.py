"""The channel to the service: URL policy, TLS defaults, and error mapping."""

import ssl

import pytest
from websockets.exceptions import ConnectionClosed, InvalidURI, WebSocketException

from cryptnox_id_cli.remote import channel as ch
from cryptnox_id_cli.transport.errors import RemoteConnectError


# --------------------------------------------------------------------------- #
# URL policy                                                                  #
# --------------------------------------------------------------------------- #
def test_production_url_is_wss():
    assert ch.PRODUCTION_URL.startswith("wss://")
    assert ch.validate_url(ch.PRODUCTION_URL) == ch.PRODUCTION_URL


def test_plain_ws_to_a_remote_host_is_refused():
    with pytest.raises(RemoteConnectError, match="unencrypted"):
        ch.validate_url("ws://piv.cryptnox.com")


def test_plain_ws_to_loopback_is_refused_unless_opted_in():
    with pytest.raises(RemoteConnectError, match="unencrypted"):
        ch.validate_url("ws://localhost:8765")
    assert ch.validate_url("ws://localhost:8765", allow_insecure_loopback=True)
    assert ch.validate_url("ws://127.0.0.1:8765", allow_insecure_loopback=True)


def test_loopback_opt_in_does_not_extend_to_other_hosts():
    with pytest.raises(RemoteConnectError, match="unencrypted"):
        ch.validate_url("ws://localhost.evil.example", allow_insecure_loopback=True)


def test_non_websocket_schemes_are_refused():
    for url in ("https://piv.cryptnox.com", "piv.cryptnox.com", "file:///etc/passwd"):
        with pytest.raises(RemoteConnectError, match="not a WebSocket URL"):
            ch.validate_url(url)


# --------------------------------------------------------------------------- #
# TLS defaults                                                                #
# --------------------------------------------------------------------------- #
def test_default_tls_context_verifies_peer_and_hostname():
    context = ch.default_ssl_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


# --------------------------------------------------------------------------- #
# The WebSocket-backed channel                                                #
# --------------------------------------------------------------------------- #
class _FakeConnection:
    def __init__(self, *, recv_result=None, recv_raises=None, send_raises=None):
        self.sent: list[str] = []
        self.closed = False
        self._recv_result = recv_result
        self._recv_raises = recv_raises
        self._send_raises = send_raises
        self.last_timeout = None

    def send(self, message):
        if self._send_raises:
            raise self._send_raises
        self.sent.append(message)

    def recv(self, timeout=None):
        self.last_timeout = timeout
        if self._recv_raises:
            raise self._recv_raises
        return self._recv_result

    def close(self):
        self.closed = True


def test_channel_satisfies_the_protocol():
    assert isinstance(ch.WebSocketChannel(_FakeConnection()), ch.FrameChannel)


def test_send_passes_the_message_through():
    conn = _FakeConnection()
    ch.WebSocketChannel(conn).send('{"type":"hello"}')
    assert conn.sent == ['{"type":"hello"}']


def test_recv_passes_the_timeout_through_and_returns_text():
    conn = _FakeConnection(recv_result='{"type":"atr"}')
    assert ch.WebSocketChannel(conn).recv(timeout=7.5) == '{"type":"atr"}'
    assert conn.last_timeout == 7.5


def test_recv_decodes_binary_frames_as_utf8():
    conn = _FakeConnection(recv_result=b'{"type":"atr"}')
    assert ch.WebSocketChannel(conn).recv() == '{"type":"atr"}'


def test_recv_refuses_binary_that_is_not_utf8():
    conn = _FakeConnection(recv_result=b"\xff\xfe")
    with pytest.raises(RemoteConnectError, match="UTF-8"):
        ch.WebSocketChannel(conn).recv()


def test_recv_timeout_names_the_wait():
    conn = _FakeConnection(recv_raises=TimeoutError())
    with pytest.raises(RemoteConnectError, match="nothing for 30 seconds"):
        ch.WebSocketChannel(conn).recv(timeout=30)


def test_recv_on_a_closed_connection_says_so():
    conn = _FakeConnection(recv_raises=ConnectionClosed(None, None))
    with pytest.raises(RemoteConnectError, match="closed the connection"):
        ch.WebSocketChannel(conn).recv()


def test_recv_wraps_other_websocket_failures():
    conn = _FakeConnection(recv_raises=WebSocketException("boom"))
    with pytest.raises(RemoteConnectError, match="connection to the service failed"):
        ch.WebSocketChannel(conn).recv()


def test_recv_wraps_os_errors():
    conn = _FakeConnection(recv_raises=ConnectionResetError("reset by peer"))
    with pytest.raises(RemoteConnectError, match="reset by peer"):
        ch.WebSocketChannel(conn).recv()


def test_send_wraps_failures():
    conn = _FakeConnection(send_raises=WebSocketException("gone"))
    with pytest.raises(RemoteConnectError):
        ch.WebSocketChannel(conn).send("x")


def test_close_swallows_errors_so_the_real_failure_survives():
    class _Explodes(_FakeConnection):
        def close(self):
            raise RuntimeError("already dead")

    ch.WebSocketChannel(_Explodes()).close()  # must not raise


# --------------------------------------------------------------------------- #
# Opening the channel                                                         #
# --------------------------------------------------------------------------- #
def test_open_channel_uses_a_verifying_tls_context_for_wss(monkeypatch):
    seen = {}

    def fake_connect(url, **kwargs):
        seen["url"] = url
        seen.update(kwargs)
        return _FakeConnection()

    monkeypatch.setattr("websockets.sync.client.connect", fake_connect)
    with ch.open_channel("wss://piv.cryptnox.com") as channel:
        assert isinstance(channel, ch.WebSocketChannel)
    assert seen["url"] == "wss://piv.cryptnox.com"
    assert isinstance(seen["ssl"], ssl.SSLContext)
    assert seen["ssl"].check_hostname is True
    assert seen["open_timeout"] == ch.CONNECT_TIMEOUT
    assert seen["max_size"] == ch.MAX_MESSAGE_BYTES


def test_open_channel_leaves_tls_off_for_plain_ws(monkeypatch):
    seen = {}

    def fake_connect(url, **kwargs):
        seen.update(kwargs)
        return _FakeConnection()

    monkeypatch.setattr("websockets.sync.client.connect", fake_connect)
    with ch.open_channel("ws://localhost:1"):
        pass
    assert seen["ssl"] is None


def test_open_channel_closes_on_exit_even_after_an_error(monkeypatch):
    conn = _FakeConnection()
    monkeypatch.setattr("websockets.sync.client.connect", lambda url, **kw: conn)

    def use_and_fail() -> None:
        with ch.open_channel("wss://x"):
            raise RuntimeError("inside")

    with pytest.raises(RuntimeError, match="inside"):
        use_and_fail()
    assert conn.closed is True


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (ssl.SSLCertVerificationError(1, "self-signed certificate"), "could not be verified"),
        (ssl.SSLError("handshake failure"), "TLS handshake"),
        (InvalidURI("wss://x", "bad"), "not a usable service URL"),
        (TimeoutError(), "did not answer within"),
        (WebSocketException("426"), "could not open a connection"),
        (ConnectionRefusedError("refused"), "could not reach the service"),
    ],
)
def test_open_channel_maps_every_failure_to_a_connect_error(monkeypatch, raised, expected):
    def fake_connect(url, **kwargs):
        raise raised

    monkeypatch.setattr("websockets.sync.client.connect", fake_connect)
    with pytest.raises(RemoteConnectError, match=expected), ch.open_channel("wss://x"):
        pass
