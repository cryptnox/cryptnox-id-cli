"""CTAP2 status-code decoding (CTAP 2.1; matches the Android client's table)."""

from __future__ import annotations

from cryptnox_id_cli.transport.errors import CryptnoxError

_CTAP_ERRORS: dict[int, tuple[str, str]] = {
    0x01: ("CTAP1_ERR_INVALID_COMMAND", "The command is not valid or not supported."),
    0x02: ("CTAP1_ERR_INVALID_PARAMETER", "Invalid parameter."),
    0x03: ("CTAP1_ERR_INVALID_LENGTH", "Invalid message length."),
    0x04: ("CTAP1_ERR_INVALID_SEQ", "Invalid message sequencing."),
    0x05: ("CTAP1_ERR_TIMEOUT", "Message timed out."),
    0x06: ("CTAP1_ERR_CHANNEL_BUSY", "Channel busy."),
    0x11: ("CTAP2_ERR_CBOR_UNEXPECTED_TYPE", "Invalid/unexpected CBOR type."),
    0x12: ("CTAP2_ERR_INVALID_CBOR", "Error when parsing CBOR."),
    0x14: ("CTAP2_ERR_MISSING_PARAMETER", "Missing non-optional parameter."),
    0x15: ("CTAP2_ERR_LIMIT_EXCEEDED", "Limit for number of items exceeded."),
    0x17: ("CTAP2_ERR_LARGE_BLOB_STORAGE_FULL", "Large blob storage is full."),
    0x19: ("CTAP2_ERR_CREDENTIAL_EXCLUDED", "A credential in the exclude list already exists."),
    0x21: ("CTAP2_ERR_PROCESSING", "Processing (lengthy operation underway)."),
    0x22: ("CTAP2_ERR_INVALID_CREDENTIAL", "Credential not valid for the authenticator."),
    0x23: ("CTAP2_ERR_USER_ACTION_PENDING", "Authentication is waiting for user interaction."),
    0x24: ("CTAP2_ERR_OPERATION_PENDING", "Another processing operation is pending."),
    0x25: ("CTAP2_ERR_NO_OPERATIONS", "No outstanding operations."),
    0x26: (
        "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
        "Authenticator does not support the requested algorithm.",
    ),
    0x27: ("CTAP2_ERR_OPERATION_DENIED", "The operation was denied (user presence / policy)."),
    0x28: ("CTAP2_ERR_KEY_STORE_FULL", "Internal key storage is full."),
    0x2B: ("CTAP2_ERR_UNSUPPORTED_OPTION", "Unsupported option."),
    0x2C: ("CTAP2_ERR_INVALID_OPTION", "Not a valid option for the current operation."),
    0x2D: ("CTAP2_ERR_KEEPALIVE_CANCEL", "The operation was cancelled."),
    0x2E: ("CTAP2_ERR_NO_CREDENTIALS", "No valid credentials provided / found."),
    0x2F: ("CTAP2_ERR_USER_ACTION_TIMEOUT", "Timeout waiting for user interaction."),
    0x30: ("CTAP2_ERR_NOT_ALLOWED", "Command not allowed on this CID/transport."),
    0x31: ("CTAP2_ERR_PIN_INVALID", "The PIN is invalid (wrong PIN entered)."),
    0x32: (
        "CTAP2_ERR_PIN_BLOCKED",
        "The PIN is blocked. Reset is required to use the authenticator again.",
    ),
    0x33: (
        "CTAP2_ERR_PIN_AUTH_INVALID",
        "PIN authentication (pinUvAuthParam) verification failed.",
    ),
    0x34: (
        "CTAP2_ERR_PIN_AUTH_BLOCKED",
        "PIN authentication is blocked for this power cycle - remove and re-present the card.",
    ),
    0x35: ("CTAP2_ERR_PIN_NOT_SET", "No PIN is set on this authenticator."),
    0x36: ("CTAP2_ERR_PUAT_REQUIRED", "A PIN/UV auth token is required for this operation."),
    0x37: (
        "CTAP2_ERR_PIN_POLICY_VIOLATION",
        "The new PIN violates the PIN policy (e.g. too short).",
    ),
    0x39: ("CTAP2_ERR_REQUEST_TOO_LARGE", "The request is larger than the authenticator supports."),
    0x3A: ("CTAP2_ERR_ACTION_TIMEOUT", "The action timed out."),
    0x3B: ("CTAP2_ERR_UP_REQUIRED", "User presence is required."),
    0x3C: ("CTAP2_ERR_UV_BLOCKED", "Built-in user verification is blocked."),
    0x3E: ("CTAP2_ERR_UV_INVALID", "User verification failed."),
    0x7F: ("CTAP1_ERR_OTHER", "Other unspecified error."),
}


def describe_ctap(status: int) -> tuple[str, str]:
    return _CTAP_ERRORS.get(
        status, (f"CTAP_ERR_0x{status:02X}", f"Unknown CTAP error 0x{status:02X}.")
    )


class CtapStatusError(CryptnoxError):
    """A CTAP command returned a non-success status byte."""

    code = "ctap_error"
    exit_code = 10

    def __init__(self, status: int, *, context: str | None = None) -> None:
        self.status = status
        name, message = describe_ctap(status)
        prefix = f"{context}: " if context else ""
        super().__init__(f"{prefix}{message} ({name}, 0x{status:02X})")

    def to_dict(self) -> dict[str, object]:
        name, _ = describe_ctap(self.status)
        return {
            "error": self.code,
            "message": str(self),
            "ctap_status": f"0x{self.status:02X}",
            "ctap_name": name,
        }
