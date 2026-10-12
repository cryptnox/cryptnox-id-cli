"""Frame codec for the remote PIV service.

The service exchanges JSON objects over a WebSocket. Frames are sent one
compact object per text message. On receive, a message is split on newlines and
every non-empty line is parsed as its own frame, so both framings are accepted.

Everything arriving from the service is untrusted input: sizes are capped, types
are checked, and unknown fields are ignored rather than trusted. Unknown frame
types are reported rather than skipped, because a frame this client does not
understand may be one it was meant to answer.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..transport.errors import RemoteProtocolError

#: Operations the service exposes.
OPS: tuple[str, ...] = ("authenticate", "inspect", "attest", "reset", "dev-reset")

#: Largest WebSocket message accepted, in bytes. A CAP load block is ~255 bytes
#: and the largest result carries a certificate, so this is generous.
MAX_MESSAGE_BYTES = 1 << 20

#: Largest number of frames accepted in a single message.
MAX_FRAMES_PER_MESSAGE = 16

#: Largest command APDU accepted from the service, in bytes.
MAX_APDU_BYTES = 65544

#: Longest untrusted string rendered from a service frame.
MAX_TEXT_CHARS = 2000

_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OTHER = re.compile(r"\x1b[@-Z\\-_]")


@dataclass(frozen=True)
class PowChallenge:
    """A proof-of-work challenge the client must answer before the operation runs."""

    challenge: bytes
    bits: int


@dataclass(frozen=True)
class ApduCommand:
    """A command the service wants transmitted to the card, verbatim."""

    apdu: bytes

    @property
    def header_hex(self) -> str:
        return self.apdu[:4].hex().upper()


@dataclass(frozen=True)
class AtrRequest:
    """A request for the card's answer-to-reset."""


@dataclass(frozen=True)
class LogMessage:
    """An informational line from the service. Untrusted text."""

    message: str


@dataclass(frozen=True)
class OpResult:
    """The final frame: the operation's outcome."""

    payload: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.payload.get("ok", False))


ServerFrame = PowChallenge | ApduCommand | AtrRequest | LogMessage | OpResult


def sanitize_server_text(text: object, *, limit: int = MAX_TEXT_CHARS) -> str:
    """Make a string from the service safe to display.

    Strips ANSI escape sequences and control characters, and caps the length.
    Callers rendering through rich must still escape markup.
    """
    if not isinstance(text, str):
        text = str(text)
    cleaned = _ANSI_CSI.sub("", text)
    cleaned = _ANSI_OTHER.sub("", cleaned)
    cleaned = "".join(ch for ch in cleaned if ch == " " or ch.isprintable())
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "… (truncated)"
    return cleaned


def encode_frame(frame: Mapping[str, object]) -> str:
    """Render one frame as a compact JSON text message."""
    return json.dumps(frame, separators=(",", ":"))


def decode_frames(message: str | bytes) -> list[dict[str, object]]:
    """Parse a WebSocket message into frames.

    Accepts either a single JSON object or several separated by newlines.
    """
    if isinstance(message, bytes | bytearray):
        try:
            message = bytes(message).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RemoteProtocolError("the service sent a message that is not UTF-8") from exc
    if len(message.encode("utf-8", "replace")) > MAX_MESSAGE_BYTES:
        raise RemoteProtocolError(
            f"the service sent a message larger than {MAX_MESSAGE_BYTES} bytes"
        )

    frames: list[dict[str, object]] = []
    for line in message.split("\n"):
        if not line.strip():
            continue
        if len(frames) >= MAX_FRAMES_PER_MESSAGE:
            raise RemoteProtocolError(
                f"the service sent more than {MAX_FRAMES_PER_MESSAGE} frames in one message"
            )
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise RemoteProtocolError(f"the service sent malformed JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise RemoteProtocolError("the service sent a frame that is not a JSON object")
        frames.append(obj)
    if not frames:
        raise RemoteProtocolError("the service sent an empty message")
    return frames


def _require_str(obj: Mapping[str, object], key: str, kind: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise RemoteProtocolError(f"the service sent a {kind} frame without a usable {key!r}")
    return value


def _require_hex(obj: Mapping[str, object], key: str, kind: str, *, limit: int) -> bytes:
    text = _require_str(obj, key, kind).strip()
    if len(text) % 2 != 0:
        raise RemoteProtocolError(f"the service sent a {kind} frame with odd-length hex {key!r}")
    if len(text) // 2 > limit:
        raise RemoteProtocolError(
            f"the service sent a {kind} frame whose {key!r} exceeds {limit} bytes"
        )
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise RemoteProtocolError(
            f"the service sent a {kind} frame with invalid hex in {key!r}"
        ) from exc


def parse_server_frame(obj: Mapping[str, object]) -> ServerFrame:
    """Turn a decoded frame into its typed form."""
    kind = obj.get("type")
    if not isinstance(kind, str):
        raise RemoteProtocolError("the service sent a frame without a type")

    if kind == "pow_challenge":
        challenge = _require_hex(obj, "challenge", kind, limit=64)
        bits = obj.get("bits")
        if not isinstance(bits, int) or isinstance(bits, bool) or bits < 0:
            raise RemoteProtocolError(
                "the service sent a proof-of-work challenge without a usable bit count"
            )
        return PowChallenge(challenge=challenge, bits=bits)

    if kind == "apdu":
        apdu = _require_hex(obj, "hex", kind, limit=MAX_APDU_BYTES)
        if len(apdu) < 4:
            raise RemoteProtocolError("the service sent a command shorter than an APDU header")
        return ApduCommand(apdu=apdu)

    if kind == "atr":
        return AtrRequest()

    if kind == "log":
        return LogMessage(message=sanitize_server_text(obj.get("msg", "")))

    if kind == "result":
        payload = {k: v for k, v in obj.items() if k != "type"}
        return OpResult(payload=payload)

    raise RemoteProtocolError(f"the service sent an unsupported frame type: {kind!r}")


def hello_frame(op: str, params: Mapping[str, object] | None = None) -> dict[str, object]:
    """Build the opening frame that names the operation."""
    if op not in OPS:
        raise ValueError(f"unknown remote operation: {op!r}")
    return {"type": "hello", "op": op, "params": dict(params or {})}


def pow_frame(nonce: int) -> dict[str, object]:
    return {"type": "pow", "nonce": nonce}


def apdu_response_frame(data: bytes, sw1: int, sw2: int) -> dict[str, object]:
    return {
        "type": "apdu_resp",
        "data": bytes(data).hex().upper(),
        "sw1": sw1 & 0xFF,
        "sw2": sw2 & 0xFF,
    }


def apdu_error_frame(message: str) -> dict[str, object]:
    return {"type": "apdu_resp", "error": message}


def atr_response_frame(atr: bytes) -> dict[str, object]:
    return {"type": "atr_resp", "atr": bytes(atr).hex().upper()}
