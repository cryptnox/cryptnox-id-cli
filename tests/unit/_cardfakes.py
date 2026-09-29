"""Shared card doubles and wiring helpers.

Two transmit conventions exist in this suite and both are deliberate:

* ``RawConnection`` style, ``transmit(list[int]) -> (list[int], sw1, sw2)``. This is what
  ``CardSession`` drives, and what most doubles here implement.
* transmit-callable style, ``transmit(APDU | bytes) -> Response``. The SCP doubles use it
  because ``open_channel`` takes a bare callable rather than a connection.

:class:`ResponseAdapter` bridges the second into the first, which is what lets a secure
channel double sit behind ``connect()`` and be driven by a real ``CardSession`` - redactor,
APDU log and 6Cxx/61xx chaining all running for real.

Import this as ``_cardfakes`` from any module in this directory. There is no
``__init__.py`` here, so pytest's prepend import mode puts the directory on ``sys.path``
under both ``python -m pytest`` and the bare ``pytest`` entry point CI uses. The leading
underscore keeps it out of collection.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from click.testing import CliRunner

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root

_Reply = tuple[list[int], int, int]


class QueueConn:
    """A RawConnection returning queued ``(data, sw1, sw2)`` replies in order."""

    def __init__(self, responses: Iterable[tuple[Sequence[int] | bytes, int, int]]) -> None:
        self._responses = list(responses)
        self.sent: list[bytes] = []

    def transmit(self, apdu: list[int]) -> _Reply:
        self.sent.append(bytes(apdu))
        data, sw1, sw2 = self._responses.pop(0)
        return list(data), sw1, sw2

    def get_atr(self) -> bytes:
        return b""

    def disconnect(self) -> None:
        pass


class RecordingConn:
    """A RawConnection that records every frame and answers with one fixed reply.

    Useful for asserting on command shaping (chaining, P1/P2, Lc) rather than on state.
    """

    def __init__(self, reply: _Reply = ([], 0x90, 0x00), *, atr: bytes = b"\x3b\x00") -> None:
        self.frames: list[bytes] = []
        self._reply = reply
        self._atr = atr

    def transmit(self, apdu: list[int]) -> _Reply:
        self.frames.append(bytes(apdu))
        data, sw1, sw2 = self._reply
        return list(data), sw1, sw2

    def get_atr(self) -> bytes:
        return self._atr

    def disconnect(self) -> None:
        pass


class ResponseAdapter:
    """Expose a transmit-callable card as a RawConnection.

    ``answers`` is consulted first, keyed on the full command hex exactly like conftest's
    ``MockConnection``. That covers framing the wrapped double does not model - a SELECT,
    say - without teaching it new commands. Anything unmatched goes to the card, whose
    reply may be a ``Response`` or an already-raw tuple.

    ``log`` holds every command as uppercase hex, which is usually the assertion you want:
    it catches command-shaping regressions that a state-modelling fake would hide.
    """

    def __init__(
        self,
        card: object,
        *,
        atr: bytes = b"\x3b\x00",
        answers: dict[str, _Reply] | None = None,
    ) -> None:
        self._card = card
        self._atr = atr
        self._answers = {k.upper(): v for k, v in (answers or {}).items()}
        self.log: list[str] = []

    def transmit(self, apdu: list[int]) -> _Reply:
        raw = bytes(apdu)
        key = raw.hex().upper()
        self.log.append(key)
        scripted = self._answers.get(key)
        if scripted is not None:
            data, sw1, sw2 = scripted
            return list(data), sw1, sw2
        reply = self._card.transmit(raw)  # type: ignore[attr-defined]
        if isinstance(reply, tuple):
            data, sw1, sw2 = reply
            return list(data), sw1, sw2
        return list(reply.data), reply.sw1, reply.sw2

    def get_atr(self) -> bytes:
        return self._atr

    def disconnect(self) -> None:
        pass


def wire_session(monkeypatch, conn, *, reader_name: str | None = None) -> None:
    """Route every ``app.open_session()`` at ``conn``.

    This is the seam 63 call sites share. ``make_session`` still runs, so the redactor,
    the ``--apdu-log`` file and the session's chaining are exercised rather than bypassed.
    Commands that import ``connect``/``pick_reader`` directly (``doctor``, ``readers``)
    are not covered by this - use :func:`wire_pcsc` for those.
    """
    monkeypatch.setattr(
        AppContext,
        "open_session",
        lambda self: self.make_session(conn, reader_name=reader_name),
    )


def wire_pcsc(monkeypatch, module, conn, *, reader_name: str, infos=None) -> None:
    """Substitute the PC/SC names a command module imported into its own namespace."""
    if infos is not None:
        monkeypatch.setattr(module, "reader_states", lambda: infos, raising=True)
    monkeypatch.setattr(module, "pick_reader", lambda preference: reader_name, raising=True)
    monkeypatch.setattr(module, "connect", lambda name: conn, raising=True)


def run(args: Sequence[str], **kwargs):
    """Invoke the CLI through CliRunner."""
    return CliRunner().invoke(root, list(args), **kwargs)


def run_both_modes(args: Sequence[str], **kwargs):
    """Return ``(json_result, human_result)`` for the same command.

    About a fifth of the missed statements in the command modules sit inside the
    ``human(c)`` closures, which only run when ``--json`` is absent, so the second
    invocation is usually the cheapest coverage in any wave.
    """
    return run(["--json", *args], **kwargs), run(list(args), **kwargs)
