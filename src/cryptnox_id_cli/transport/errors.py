"""Exception hierarchy and friendly ISO 7816 status-word decoding.

Every status word is mapped to a plain-language message plus the raw code, so the
CLI never shows a bare ``SW=6982``.
"""

from __future__ import annotations

from dataclasses import dataclass


class CryptnoxError(Exception):
    """Base class for all errors surfaced by the CLI's error funnel."""

    exit_code = 1
    #: short machine token, e.g. "card_access_denied"
    code = "error"

    def to_dict(self) -> dict[str, object]:
        return {"error": self.code, "message": str(self)}


class TransportError(CryptnoxError):
    code = "transport_error"


class NoReadersError(TransportError):
    code = "no_readers"
    exit_code = 3


class ReaderNotFoundError(TransportError):
    code = "reader_not_found"
    exit_code = 3


class NoCardError(TransportError):
    code = "no_card"
    exit_code = 3


class CardAccessDeniedError(TransportError):
    """PC/SC refused the transmit (e.g. Windows blocking the FIDO CTAP AID)."""

    code = "card_access_denied"
    exit_code = 4

    def __init__(self, message: str, *, hresult: int | None = None) -> None:
        super().__init__(message)
        self.hresult = hresult


class AppletNotFoundError(CryptnoxError):
    code = "applet_not_found"
    exit_code = 5


class Scp03Error(CryptnoxError):
    """SCP03 secure-channel failure (wrong keys, bad cryptogram, MAC error)."""

    code = "scp03_error"
    exit_code = 7


class Scp02Error(CryptnoxError):
    """SCP02 secure-channel failure (wrong keys, bad cryptogram, MAC error)."""

    code = "scp02_error"
    exit_code = 7


@dataclass(frozen=True)
class SWInfo:
    sw: int
    name: str
    message: str
    ok: bool = False
    more_data: int | None = None  # 61xx -> bytes still available
    wrong_le: int | None = None  # 6Cxx -> correct Le
    retries: int | None = None  # 63Cx -> remaining tries

    def sw_hex(self) -> str:
        return f"{self.sw:04X}"


# Exact status words → (name, friendly message).
_SW_TABLE: dict[int, tuple[str, str]] = {
    0x9000: ("OK", "Success."),
    0x6982: (
        "SECURITY_STATUS_NOT_SATISFIED",
        "Security status not satisfied. You probably need to verify the PIN or "
        "authenticate with the admin key before running this command.",
    ),
    0x6983: (
        "AUTH_METHOD_BLOCKED",
        "Authentication method blocked. The PIN or PUK is likely blocked.",
    ),
    0x6985: (
        "CONDITIONS_NOT_SATISFIED",
        "Conditions of use not satisfied. The applet may be in the wrong lifecycle state "
        "for this command.",
    ),
    0x6A80: (
        "WRONG_DATA",
        "Incorrect data. Check the command parameters or object format.",
    ),
    0x6A81: ("FUNC_NOT_SUPPORTED", "Function not supported by this applet."),
    0x6A82: (
        "FILE_NOT_FOUND",
        "File, object or applet not found. The selected item may not exist on this card.",
    ),
    0x6A84: ("NOT_ENOUGH_MEMORY", "Not enough memory on the card for this operation."),
    0x6A86: ("WRONG_P1P2", "Incorrect P1/P2 parameters."),
    0x6A88: (
        "REFERENCE_DATA_NOT_FOUND",
        "Referenced data not found (e.g. the PIN/key reference is not configured).",
    ),
    0x6700: ("WRONG_LENGTH", "Wrong length (Lc/Le)."),
    0x6D00: ("INS_NOT_SUPPORTED", "Instruction (INS) not supported by this applet."),
    0x6E00: (
        "CLA_NOT_SUPPORTED",
        "Class (CLA) not supported; this function is not reachable over this interface "
        "(e.g. a contactless-only function on a contact reader).",
    ),
    0x6881: ("LOGICAL_CHANNEL_UNSUPPORTED", "Logical channel not supported."),
    0x6882: ("SM_UNSUPPORTED", "Secure messaging not supported."),
    0x6999: ("APPLET_SELECT_FAILED", "Applet selection failed or refused."),
    0x6F00: ("NO_PRECISE_DIAGNOSIS", "Unknown card error (no precise diagnosis)."),
}


def describe_sw(sw1: int, sw2: int) -> SWInfo:
    """Decode a status word into a friendly :class:`SWInfo`."""
    sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)
    if sw == 0x9000:
        return SWInfo(sw, "OK", "Success.", ok=True)
    if sw1 == 0x61:
        return SWInfo(
            sw, "MORE_DATA", f"{sw2} more byte(s) available (GET RESPONSE).", more_data=sw2
        )
    if sw1 == 0x6C:
        return SWInfo(sw, "WRONG_LE", f"Wrong Le; resend with Le=0x{sw2:02X}.", wrong_le=sw2)
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        tries = sw2 & 0x0F
        return SWInfo(
            sw,
            "VERIFY_FAILED",
            f"Verification failed; {tries} attempt(s) remaining.",
            retries=tries,
        )
    if sw == 0x6300:
        return SWInfo(sw, "VERIFY_FAILED", "Verification failed.")
    if sw in _SW_TABLE and _SW_TABLE[sw][1]:
        name, msg = _SW_TABLE[sw]
        return SWInfo(sw, name, msg)
    # Family fallbacks.
    if sw1 == 0x63:
        return SWInfo(sw, "WARNING", "Operation completed with warning / counter changed.")
    if sw1 in (0x62, 0x63):
        return SWInfo(sw, "WARNING", f"Warning (SW={sw:04X}).")
    if sw1 in (0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F):
        return SWInfo(sw, "ERROR", f"Card returned error SW={sw:04X}.")
    return SWInfo(sw, "UNKNOWN", f"Unrecognised status word SW={sw:04X}.")


class StatusWordError(CryptnoxError):
    """A command returned a non-success status word."""

    code = "status_word"
    exit_code = 6

    def __init__(self, sw1: int, sw2: int, *, context: str | None = None) -> None:
        self.info = describe_sw(sw1, sw2)
        self.context = context
        prefix = f"{context}: " if context else ""
        super().__init__(f"{prefix}{self.info.message} (SW={self.info.sw_hex()})")

    def to_dict(self) -> dict[str, object]:
        return {
            "error": self.code,
            "message": str(self),
            "sw": self.info.sw_hex(),
            "sw_name": self.info.name,
            "context": self.context,
        }
