"""The single redaction chokepoint for APDU logs and any secret-bearing output.

Two layers of defence:

1. **Command-aware redaction** — the data field of inherently sensitive commands
   (VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GENERAL AUTHENTICATE, and
   CTAP ``clientPIN``) is masked regardless of whether the value was registered.
2. **Registered-secret masking** — any byte string explicitly registered (a PIN,
   key, session key…) is masked wherever it appears in a hex transcript.
"""

from __future__ import annotations

# INS values whose command data field is always secret, regardless of whether the
# value was registered. Covers PIV PIN/PUK + auth commands, GlobalPlatform key
# loading, and the DESFire ChangeKey opcode (seen as the INS of its 90-wrapped frame)
# so even raw `apdu send` of a key never lands in a log in the clear.
SENSITIVE_INS: dict[int, str] = {
    0x20: "VERIFY",
    0x24: "CHANGE REFERENCE DATA",
    0x2C: "RESET RETRY COUNTER",
    0x87: "GENERAL AUTHENTICATE",
    0xC4: "DESFire ChangeKey",
    0xD8: "PUT KEY",
    0xE2: "STORE DATA",
}

_MARK = "<REDACTED:{n}B>"
_MARK_PREFIX = "<REDACTED:"
_HEX_DIGITS = frozenset("0123456789ABCDEF")


def _replace_aligned(text: str, needle: str, marker: str) -> str:
    """Replace ``needle`` only where it starts on a byte boundary (even hex offset).

    A plain ``str.replace`` also matches at odd nibble offsets (registered bytes
    ``12 34`` inside ``A1 23 4F``), garbling the surrounding nibbles. Walking the
    hex two characters at a time keeps replacement byte-aligned; alignment restarts
    after any non-hex character, and already-inserted redaction markers are skipped
    whole so their letters/digits are never rewritten.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch not in _HEX_DIGITS:
            if text.startswith(_MARK_PREFIX, i):
                end = text.find(">", i)
                if end != -1:
                    out.append(text[i : end + 1])
                    i = end + 1
                    continue
            out.append(ch)
            i += 1
            continue
        if text.startswith(needle, i):
            out.append(marker)
            i += len(needle)
            continue
        out.append(text[i : i + 2])
        i += 2
    return "".join(out)


def _parse_command(apdu: bytes) -> tuple[int, int, int, int, bytes, bytes, bool] | None:
    """Best-effort split into (cla, ins, p1, p2, data, trailer, data_located).

    ``data_located`` is False when the length field disagrees with the bytes present,
    so the data field could not be isolated and everything after the header sits in
    ``trailer``. Callers must not read that as "carries no data": an Lc larger than
    the remaining bytes is exactly how a truncated VERIFY looks.
    """
    if len(apdu) < 4:
        return None
    cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
    body = apdu[4:]
    if not body:
        return (cla, ins, p1, p2, b"", b"", True)
    if len(body) == 1:  # Le only (case 2)
        return (cla, ins, p1, p2, b"", body, True)
    if body[0] == 0x00 and len(body) >= 3:  # extended length
        lc = (body[1] << 8) | body[2]
        if lc and len(body) >= 3 + lc:
            return (cla, ins, p1, p2, body[3 : 3 + lc], body[3 + lc :], True)
        # lc == 0 is the extended Le form and genuinely carries no data; any other
        # value is an Lc that overruns what is here.
        return (cla, ins, p1, p2, b"", body, lc == 0)
    lc = body[0]  # short length
    if lc and len(body) >= 1 + lc:
        return (cla, ins, p1, p2, body[1 : 1 + lc], body[1 + lc :], True)
    return (cla, ins, p1, p2, b"", body, False)


def _is_sensitive(cla: int, ins: int, data: bytes) -> bool:
    if ins in SENSITIVE_INS:
        return True
    # CTAP message (CLA 0x80, INS 0x10) carrying clientPIN (cmd byte 0x06).
    return (cla & 0xF0) == 0x80 and ins == 0x10 and data[:1] == b"\x06"


def _may_carry_secret(cla: int, ins: int) -> bool:
    """Sensitivity decided from the header alone, for a body that would not split.

    Used only when the length field is inconsistent, so the data bytes cannot be
    inspected. CTAP is treated as sensitive as a family here: ``clientPIN`` is
    identifiable only from the first data byte, which is precisely what an
    unparseable length hides.
    """
    return ins in SENSITIVE_INS or ((cla & 0xF0) == 0x80 and ins == 0x10)


class Redactor:
    """Masks secrets in hex transcripts. Stateless except for the secret registry."""

    def __init__(self) -> None:
        self._secrets: list[bytes] = []

    def register(self, secret: bytes | bytearray | None) -> None:
        """Register a secret so it is masked anywhere it later appears."""
        if not secret:
            return
        b = bytes(secret)
        if len(b) >= 1 and b not in self._secrets:
            self._secrets.append(b)

    def mask(self, hexstr: str) -> str:
        """Mask any registered secret that appears byte-aligned in a hex string."""
        out = hexstr.upper()
        # Longest first so overlapping secrets mask cleanly.
        for s in sorted(self._secrets, key=len, reverse=True):
            h = s.hex().upper()
            if len(h) >= 2 and h in out:
                out = _replace_aligned(out, h, _MARK.format(n=len(s)))
        return out

    def redact_command(self, apdu: bytes | bytearray) -> str:
        """Return a log-safe hex rendering of a command APDU."""
        apdu = bytes(apdu)
        parsed = _parse_command(apdu)
        if parsed is None:
            return self.mask(apdu.hex().upper())
        cla, ins, p1, p2, data, trailer, data_located = parsed
        if data and _is_sensitive(cla, ins, data):
            header = apdu[:4].hex().upper()
            lc = f"{len(data):02X}" if len(data) <= 0xFF else f"00{len(data):04X}"
            tail = trailer.hex().upper()
            return f"{header}{lc}{_MARK.format(n=len(data))}{tail}"
        if not data_located and trailer and _may_carry_secret(cla, ins):
            # Fail closed. The length field did not agree with the bytes present, so
            # the data field was never isolated and the registered-secret path below
            # would mask nothing unless the value happened to be registered. Emit the
            # header and the length of what was withheld, without inventing an Lc.
            return f"{apdu[:4].hex().upper()}{_MARK.format(n=len(trailer))}"
        return self.mask(apdu.hex().upper())

    def redact_response_data(self, data: bytes | bytearray, *, ins: int) -> str:
        """Return a log-safe hex rendering of a response body alone (no SW appended)."""
        body = bytes(data)
        if body and ins == 0x87:  # GENERAL AUTHENTICATE responses can carry key material
            return _MARK.format(n=len(body))
        return self.mask(body.hex().upper())

    def redact_response(self, data: bytes | bytearray, sw1: int, sw2: int, *, ins: int) -> str:
        """Return a log-safe hex rendering of a response. Masks secret-bearing INS."""
        return f"{self.redact_response_data(data, ins=ins)}{sw1:02X}{sw2:02X}"
