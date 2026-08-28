"""pyscard wrapper: passive reader status, Cryptnox/ACS-first selection, and a CardSession
that handles 6Cxx/61xx chaining and writes a redacted APDU transcript."""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TextIO

from cryptnox_id_cli.secrets.redaction import Redactor
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.elevation import looks_like_no_access
from cryptnox_id_cli.transport.errors import (
    CardAccessDeniedError,
    NoCardError,
    NoReadersError,
    ReaderNotFoundError,
    TransportError,
)

#: Substrings that identify the project's own readers: the Cryptnox-branded units
#: ("CryptnoxCR" contact, "Cryptnox NFC" contactless) and the ACS readers they are
#: based on. Selection prefers these so we never auto-target another project's card.
PREFERRED_HINTS = ("Cryptnox", "ACS", "ACR39")


@dataclass(frozen=True)
class ReaderInfo:
    index: int
    name: str
    present: bool
    atr: bytes

    @property
    def atr_hex(self) -> str:
        return self.atr.hex().upper()

    @property
    def is_preferred(self) -> bool:
        return any(h.lower() in self.name.lower() for h in PREFERRED_HINTS)


class RawConnection(Protocol):
    """Minimal card-connection interface (satisfied by pyscard and the test mock)."""

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]: ...
    def get_atr(self) -> bytes: ...
    def disconnect(self) -> None: ...


# --------------------------------------------------------------------------- #
# Reader enumeration (passive — no card session, no APDU)                      #
# --------------------------------------------------------------------------- #
def reader_states() -> list[ReaderInfo]:
    """List readers with card-present + ATR, passively via SCardGetStatusChange.

    This does NOT open a card session or transmit anything — safe for readers that
    hold other projects' cards.
    """
    try:
        from smartcard.scard import (
            SCARD_S_SUCCESS,
            SCARD_SCOPE_USER,
            SCARD_STATE_PRESENT,
            SCARD_STATE_UNAWARE,
            SCardEstablishContext,
            SCardGetStatusChange,
            SCardListReaders,
            SCardReleaseContext,
        )
    except ImportError as exc:  # pragma: no cover - pyscard always present at runtime
        raise TransportError(f"pyscard unavailable: {exc}") from exc

    hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
    if hresult != SCARD_S_SUCCESS:
        raise TransportError(
            "Cannot reach the PC/SC service. On Windows ensure 'Smart Card' (SCardSvr) "
            "is running; on Linux start pcscd."
        )
    try:
        hresult, names = SCardListReaders(hcontext, [])
        if hresult != SCARD_S_SUCCESS or not names:
            return []
        states = [(name, SCARD_STATE_UNAWARE) for name in names]
        hresult, new_states = SCardGetStatusChange(hcontext, 0, states)
        infos: list[ReaderInfo] = []
        for index, entry in enumerate(new_states):
            name, event_state, atr = entry
            present = bool(event_state & SCARD_STATE_PRESENT)
            infos.append(ReaderInfo(index, name, present, bytes(atr)))
        return infos
    finally:
        SCardReleaseContext(hcontext)


def list_reader_names() -> list[str]:
    try:
        from smartcard.System import readers as _readers
    except ImportError as exc:  # pragma: no cover
        raise TransportError(f"pyscard unavailable: {exc}") from exc
    try:
        return [str(r) for r in _readers()]
    except Exception as exc:  # pragma: no cover - defensive
        raise TransportError(f"Cannot list readers: {exc}") from exc


def _listing(infos: list[ReaderInfo]) -> str:
    return ", ".join(f"[{r.index}] {r.name}" for r in infos)


def select_reader(infos: list[ReaderInfo], preference: str | None) -> str:
    """Resolve a reader name from a reader list + an optional ``--reader`` preference.

    Pure (no PC/SC calls) so it is unit-testable. ``--reader`` accepts an index or a
    case-insensitive name substring; an ambiguous substring is an error, never a
    silent first-match. With no preference it prefers the single Cryptnox/ACS reader
    that has a card, and REFUSES TO GUESS when several do (e.g. a contact + a
    contactless reader both loaded) — the caller must disambiguate with ``--reader``.
    """
    if not infos:
        raise NoReadersError("No PC/SC readers found.")
    if preference is not None:
        pref = preference.strip()
        if pref.isdigit():
            match = next((r for r in infos if r.index == int(pref)), None)
            if match is not None:
                return match.name
            raise ReaderNotFoundError(f"No reader at index {pref} (found {len(infos)}).")
        matches = [r for r in infos if pref.lower() in r.name.lower()]
        if len(matches) == 1:
            return matches[0].name
        if not matches:
            raise ReaderNotFoundError(
                f"No reader matching {preference!r}. Available: {_listing(infos)}"
            )
        raise ReaderNotFoundError(f"Reader {preference!r} is ambiguous: {_listing(matches)}")
    # No preference: prefer a Cryptnox/ACS reader that actually has a card.
    preferred = [r for r in infos if r.is_preferred]
    with_card = [r for r in preferred if r.present]
    if len(with_card) == 1:
        return with_card[0].name
    if len(with_card) > 1:
        raise ReaderNotFoundError(
            "Multiple Cryptnox/ACS readers have a card; pass --reader <index|name> to "
            "choose (e.g. PICC for contactless, ICC for contact). "
            f"Candidates: {_listing(with_card)}"
        )
    if len(preferred) == 1:
        return preferred[0].name  # present but cardless -> let the session report NoCard
    if preferred:
        raise ReaderNotFoundError(
            "Multiple Cryptnox/ACS readers found (none with a card); pass --reader. "
            f"{_listing(preferred)}"
        )
    if len(infos) == 1:
        return infos[0].name
    raise ReaderNotFoundError(
        "Multiple readers found and no Cryptnox/ACS reader detected. "
        f"Pass --reader <name|index>. Available: {_listing(infos)}"
    )


def pick_reader(preference: str | None) -> str:
    """Resolve a reader name from ``--reader`` (index or substring), else Cryptnox/ACS-with-card."""
    return select_reader(reader_states(), preference)


#: Reader-name tokens that mark a contactless (PICC/NFC) interface. Vendor names are
#: free-form, so this is evidence, not proof - `is_contactless_interface` also looks at
#: the ATR before claiming contactless.
_CONTACTLESS_NAME_TOKENS = frozenset({"picc", "contactless", "nfc", "cl"})
#: Model numbers fold the marker into the token ("OMNIKEY 5422CL") - digits then "cl".
_MODEL_CL_RE = re.compile(r"\d+cl")


def is_contactless_interface(reader_name: str | None, atr: bytes | None) -> bool:
    """Best-effort: is this session on a contactless (ISO 14443 / PICC) interface?

    Two independent signals, either suffices:

    * the reader name advertises a PICC/CL/NFC interface (e.g. ``ACS ACR1552 1S CL
      Reader PICC 0``, ``OMNIKEY 5422CL``) - matched on whole name tokens, so ``SCL011``
      alone does not count while its ``Contactless`` suffix does, or
    * the ATR follows the PC/SC v2 Part 3 contactless construction ``3B 8x 80 01 …``,
      which readers synthesise for ISO 14443 cards (a wired card answers with its own
      ATR instead - e.g. the D600's ``3B FA 13 …``).

    False means "no evidence of contactless", not "proven contact" - callers should
    phrase contact-side advice accordingly.
    """
    if reader_name:
        tokens = re.split(r"[^a-z0-9]+", reader_name.lower())
        if any(t in _CONTACTLESS_NAME_TOKENS or _MODEL_CL_RE.fullmatch(t) for t in tokens):
            return True
    return (
        atr is not None
        and len(atr) >= 4
        and atr[0] == 0x3B
        and (atr[1] & 0xF0) == 0x80
        and atr[2] == 0x80
        and atr[3] == 0x01
    )


class PCSCConnection:
    """Adapts a pyscard connection to :class:`RawConnection`, mapping exceptions."""

    def __init__(self, conn: object) -> None:
        self._conn = conn

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        from smartcard.Exceptions import CardConnectionException

        try:
            data, sw1, sw2 = self._conn.transmit(apdu)  # type: ignore[attr-defined]
            return list(data), sw1, sw2
        except CardConnectionException as exc:
            if looks_like_no_access(exc):
                raise CardAccessDeniedError(
                    str(exc), hresult=getattr(exc, "hresult", None)
                ) from exc
            raise TransportError(f"APDU transmit failed: {exc}") from exc

    def get_atr(self) -> bytes:
        return bytes(self._conn.getATR())  # type: ignore[attr-defined]

    def disconnect(self) -> None:
        with contextlib.suppress(Exception):  # pragma: no cover - best effort
            self._conn.disconnect()  # type: ignore[attr-defined]


def connect(reader_name: str) -> PCSCConnection:
    """Open a card connection on ``reader_name`` (tries default then T1/T0)."""
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.System import readers as _readers

    target = next((r for r in _readers() if str(r) == reader_name), None)
    if target is None:
        raise ReaderNotFoundError(f"Reader not found: {reader_name}")
    conn = target.createConnection()
    try:
        conn.connect()
        return PCSCConnection(conn)
    except NoCardException as exc:
        raise NoCardError(f"No card present in reader {reader_name!r}.") from exc
    except CardConnectionException as exc:
        if looks_like_no_access(exc):
            raise CardAccessDeniedError(str(exc), hresult=getattr(exc, "hresult", None)) from exc
        for proto in (CardConnection.T1_protocol, CardConnection.T0_protocol):
            try:
                conn.connect(proto)
                return PCSCConnection(conn)
            except Exception:  # noqa: S112 - try next protocol
                continue
        raise TransportError(f"Cannot connect to card in {reader_name!r}: {exc}") from exc


class CardSession:
    """High-level APDU exchange with chaining and a redacted transcript."""

    def __init__(
        self,
        conn: RawConnection,
        *,
        redactor: Redactor | None = None,
        apdu_log: TextIO | None = None,
        trace: Callable[[str], None] | None = None,
        reader_name: str | None = None,
    ) -> None:
        self._conn = conn
        self._redactor = redactor or Redactor()
        self._log = apdu_log
        self._trace = trace
        #: Name of the PC/SC reader this session runs on, when known. Diagnostic only
        #: (interface heuristics); never used to route APDUs.
        self.reader_name = reader_name

    @property
    def redactor(self) -> Redactor:
        return self._redactor

    @property
    def atr(self) -> bytes:
        return self._conn.get_atr()

    def _emit(self, line: str) -> None:
        if self._log is not None:
            self._log.write(line + "\n")
            self._log.flush()
        if self._trace is not None:
            self._trace(line)

    def transmit(self, apdu: APDU | bytes | bytearray, *, context: str | None = None) -> Response:
        raw = apdu.to_bytes() if isinstance(apdu, APDU) else bytes(apdu)
        ins = raw[1] if len(raw) > 1 else 0
        self._emit("> " + self._redactor.redact_command(raw))

        data, sw1, sw2 = self._conn.transmit(list(raw))

        # 6Cxx: wrong Le — resend with the corrected Le in the trailing byte.
        if sw1 == 0x6C and len(raw) >= 5:
            data, sw1, sw2 = self._conn.transmit(list(raw[:-1]) + [sw2])

        # 61xx: more data — pull it with GET RESPONSE.
        acc = list(data)
        while sw1 == 0x61:
            more, sw1, sw2 = self._conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            acc += list(more)

        resp = Response(bytes(acc), sw1, sw2)
        self._emit("< " + self._redactor.redact_response(resp.data, resp.sw1, resp.sw2, ins=ins))
        return resp

    def transmit_chained(
        self, apdu: APDU, *, block_size: int = 200, context: str | None = None
    ) -> Response:
        """Send a command whose data exceeds a short APDU via ISO command chaining
        (CLA bit 0x10 on every block but the last, which keeps the original CLA/Le)."""
        blocks = [apdu.data[i : i + block_size] for i in range(0, len(apdu.data), block_size)] or [
            b""
        ]
        resp: Response | None = None
        for index, block in enumerate(blocks):
            final = index == len(blocks) - 1
            frame = APDU(
                apdu.cla if final else (apdu.cla | 0x10),
                apdu.ins,
                apdu.p1,
                apdu.p2,
                data=block,
                le=apdu.le if final else None,
            )
            label = f"{context} [{index + 1}/{len(blocks)}]" if context else None
            resp = self.transmit(frame, context=label)
            if not final and not resp.ok:
                return resp
        if resp is None:  # unreachable: chained transmit always sends at least one frame
            raise RuntimeError("no APDU frames were sent")
        return resp

    def disconnect(self) -> None:
        self._conn.disconnect()

    def __enter__(self) -> CardSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.disconnect()
