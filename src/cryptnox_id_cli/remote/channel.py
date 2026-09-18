"""The message channel to the remote PIV service.

The relay is written against :class:`FrameChannel`, a two-method view of a
message stream, so the operation loop can be exercised against a scripted
channel with no socket and no card.

The production implementation is a synchronous WebSocket over TLS. Timeouts are
explicit everywhere: an operation that generates a key on the card can leave the
client waiting tens of seconds for the next frame, and a stall must end in a
clear message rather than a hung command.
"""

from __future__ import annotations

import contextlib
import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

from ..transport.errors import RemoteConnectError

#: The service. Shipped as a constant rather than an option so an operation
#: cannot be pointed somewhere else by accident.
PRODUCTION_URL = "wss://piv.cryptnox.com"

#: Environment variable that redirects the client, for development against a
#: local stand-in. Callers decide which operations tolerate a redirect.
URL_ENV = "CRYPTNOX_REMOTE_URL"

#: Seconds to wait for the connection and the TLS handshake.
CONNECT_TIMEOUT = 20.0

#: Seconds to wait for the next frame. Generous: RSA key generation on the card
#: is measured in tens of seconds, and the service stays silent while it runs.
RECV_TIMEOUT = 120.0

#: Seconds to wait for the closing handshake before dropping the connection.
CLOSE_TIMEOUT = 5.0

#: Largest message accepted at the WebSocket layer. The codec caps again, in
#: its own terms; this stops an oversize message from being buffered at all.
MAX_MESSAGE_BYTES = 1 << 20


@runtime_checkable
class FrameChannel(Protocol):
    """A bidirectional stream of text messages."""

    def send(self, message: str) -> None: ...

    def recv(self, timeout: float | None = None) -> str: ...

    def close(self) -> None: ...


def validate_url(url: str, *, allow_insecure_loopback: bool = False) -> str:
    """Check a service URL before anything is sent to it.

    Only ``wss://`` is accepted. Plain ``ws://`` is allowed solely against
    loopback, and only when the caller opts in, so a development stand-in can
    run without a certificate.
    """
    parsed = urlparse(url)
    if parsed.scheme == "wss":
        return url
    if parsed.scheme == "ws":
        host = (parsed.hostname or "").lower()
        if allow_insecure_loopback and host in ("localhost", "127.0.0.1", "::1"):
            return url
        raise RemoteConnectError(
            f"refusing an unencrypted connection to {url!r}; the service must be reached "
            "over wss://"
        )
    raise RemoteConnectError(f"not a WebSocket URL: {url!r}")


def default_ssl_context() -> ssl.SSLContext:
    """A TLS context with verification and hostname checking on.

    Certificate pinning is deliberately not applied. The endpoint presents a
    short-lived certificate on a wildcard shared with other Cryptnox services
    and fronted by a CDN, so a pin held in a released CLI would fail on routine
    rotation, and a pin that fails open would prove nothing.
    """
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class WebSocketChannel:
    """A :class:`FrameChannel` over a synchronous WebSocket connection."""

    def __init__(self, connection: object) -> None:
        self._conn = connection

    def send(self, message: str) -> None:
        from websockets.exceptions import WebSocketException

        try:
            self._conn.send(message)  # type: ignore[attr-defined]
        except WebSocketException as exc:
            raise RemoteConnectError(f"the connection to the service failed: {exc}") from exc
        except OSError as exc:
            raise RemoteConnectError(f"the connection to the service failed: {exc}") from exc

    def recv(self, timeout: float | None = None) -> str:
        from websockets.exceptions import ConnectionClosed, WebSocketException

        try:
            message = self._conn.recv(timeout=timeout)  # type: ignore[attr-defined]
        except TimeoutError as exc:
            raise RemoteConnectError(
                f"the service sent nothing for {timeout:g} seconds"
                if timeout is not None
                else "the service sent nothing"
            ) from exc
        except ConnectionClosed as exc:
            raise RemoteConnectError(
                f"the service closed the connection before the operation finished: {exc}"
            ) from exc
        except WebSocketException as exc:
            raise RemoteConnectError(f"the connection to the service failed: {exc}") from exc
        except OSError as exc:
            raise RemoteConnectError(f"the connection to the service failed: {exc}") from exc

        if isinstance(message, bytes | bytearray):
            try:
                return bytes(message).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RemoteConnectError("the service sent a message that is not UTF-8") from exc
        return message

    def close(self) -> None:
        # Closing must not mask whatever error brought us here.
        with contextlib.suppress(Exception):
            self._conn.close()  # type: ignore[attr-defined]


@contextmanager
def open_channel(
    url: str,
    *,
    ssl_context: ssl.SSLContext | None = None,
    connect_timeout: float = CONNECT_TIMEOUT,
) -> Iterator[FrameChannel]:
    """Open a channel to the service and close it on the way out."""
    from websockets.exceptions import InvalidURI, WebSocketException
    from websockets.sync.client import connect

    parsed = urlparse(url)
    context = ssl_context
    if parsed.scheme == "wss" and context is None:
        context = default_ssl_context()

    try:
        connection = connect(
            url,
            ssl=context,
            open_timeout=connect_timeout,
            close_timeout=CLOSE_TIMEOUT,
            max_size=MAX_MESSAGE_BYTES,
        )
    except ssl.SSLCertVerificationError as exc:
        raise RemoteConnectError(f"the service's certificate could not be verified: {exc}") from exc
    except ssl.SSLError as exc:
        raise RemoteConnectError(f"the TLS handshake with the service failed: {exc}") from exc
    except InvalidURI as exc:
        raise RemoteConnectError(f"not a usable service URL: {url!r}") from exc
    except TimeoutError as exc:
        raise RemoteConnectError(
            f"the service did not answer within {connect_timeout:g} seconds"
        ) from exc
    except WebSocketException as exc:
        raise RemoteConnectError(f"could not open a connection to the service: {exc}") from exc
    except OSError as exc:
        raise RemoteConnectError(f"could not reach the service: {exc}") from exc

    channel = WebSocketChannel(connection)
    try:
        yield channel
    finally:
        channel.close()
