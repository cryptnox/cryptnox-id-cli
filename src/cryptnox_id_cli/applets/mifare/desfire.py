"""MIFARE DESFire EV2 native command transport + read-only parsers.

Native commands are sent ISO-7816-wrapped: ``90 <cmd> 00 00 [Lc <data>] 00``.
Responses end in ``91 <status>``; ``0x91AF`` means "additional frame", fetched
with ``90 AF 00 00 00`` until the status is final.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.pcsc import CardSession

# Native command codes.
CMD_GET_VERSION = 0x60
CMD_ADDITIONAL_FRAME = 0xAF
CMD_GET_FREE_MEMORY = 0x6E
CMD_GET_APPLICATION_IDS = 0x6A
CMD_GET_DF_NAMES = 0x6D
CMD_SELECT_APPLICATION = 0x5A
CMD_GET_FILE_IDS = 0x6F
CMD_GET_FILE_SETTINGS = 0xF5
CMD_CHANGE_FILE_SETTINGS = 0x5F
CMD_GET_KEY_SETTINGS = 0x45
CMD_CREATE_APPLICATION = 0xCA
CMD_DELETE_APPLICATION = 0xDA
CMD_FORMAT_PICC = 0xFC
CMD_CREATE_STD_DATA_FILE = 0xCD
CMD_WRITE_DATA = 0x3D
CMD_READ_DATA = 0xBD
CMD_CREATE_VALUE_FILE = 0xCC
CMD_GET_VALUE = 0x6C
CMD_CREDIT = 0x0C
CMD_DEBIT = 0xDC
CMD_COMMIT_TXN = 0xC7
CMD_ABORT_TXN = 0xA7
CMD_CREATE_LINEAR_RECORD_FILE = 0xC1
CMD_CREATE_CYCLIC_RECORD_FILE = 0xC0
CMD_WRITE_RECORD = 0x3B
CMD_READ_RECORDS = 0xBB
CMD_CLEAR_RECORD_FILE = 0xEB
CMD_CHANGE_KEY = 0xC4

STATUS_OK = 0x00
STATUS_ADDITIONAL_FRAME = 0xAF
STATUS_LENGTH_ERROR = 0x7E  # card rejected the command/payload length

_STATUS = {
    0x00: "OPERATION_OK",
    0x0C: "NO_CHANGES",
    0x0E: "OUT_OF_EEPROM_ERROR",
    0x1C: "ILLEGAL_COMMAND_CODE",
    0x1E: "INTEGRITY_ERROR",
    0x40: "NO_SUCH_KEY",
    0x7E: "LENGTH_ERROR",
    0x9D: "PERMISSION_DENIED",
    0x9E: "PARAMETER_ERROR",
    0xA0: "APPLICATION_NOT_FOUND",
    0xA1: "APPL_INTEGRITY_ERROR",
    0xAE: "AUTHENTICATION_ERROR",
    0xAF: "ADDITIONAL_FRAME",
    0xBE: "BOUNDARY_ERROR",
    0xC1: "CARD_INTEGRITY_ERROR",
    0xCA: "COMMAND_ABORTED",
    0xCD: "CARD_DISABLED_ERROR",
    0xCE: "COUNT_ERROR",
    0xDE: "DUPLICATE_ERROR",
    0xEE: "EEPROM_ERROR",
    0xF0: "FILE_NOT_FOUND",
    0xF1: "FILE_INTEGRITY_ERROR",
}


def status_name(status: int) -> str:
    return _STATUS.get(status, f"0x{status:02X}")


class DesfireError(CryptnoxError):
    code = "desfire_error"
    exit_code = 9

    def __init__(self, status: int, context: str | None = None) -> None:
        self.status = status
        prefix = f"{context}: " if context else ""
        super().__init__(f"{prefix}DESFire status {status_name(status)} (0x{status:02X}).")


class DesfireNotSelectedError(CryptnoxError):
    """The card did not answer as a DESFire (MIFARE not the selected default applet)."""

    code = "desfire_not_selected"
    exit_code = 5


class DesfireFrameTooLargeError(CryptnoxError):
    """A native command would exceed the single short-frame limit (Lc > 255)."""

    code = "desfire_frame_too_large"
    exit_code = 2


@dataclass
class DesfireVersion:
    hw_vendor: int
    hw_type: int
    hw_subtype: int
    hw_major: int
    hw_minor: int
    hw_storage: int
    hw_protocol: int
    sw_vendor: int
    sw_type: int
    sw_subtype: int
    sw_major: int
    sw_minor: int
    sw_storage: int
    sw_protocol: int
    uid: bytes
    batch: bytes
    cw_production: int
    year_production: int

    @staticmethod
    def _storage(code: int) -> int:
        # n>>1 is the exponent; the low bit flags "between this and the next size".
        return 1 << (code >> 1)

    @property
    def storage_bytes(self) -> int:
        return self._storage(self.hw_storage)

    def to_dict(self) -> dict[str, object]:
        return {
            "vendor": "NXP" if self.hw_vendor == 0x04 else f"0x{self.hw_vendor:02X}",
            "hardware_version": f"{self.hw_major}.{self.hw_minor}",
            "software_version": f"{self.sw_major}.{self.sw_minor}",
            "storage_bytes": self.storage_bytes,
            "protocol": f"0x{self.hw_protocol:02X}",
            "uid": self.uid.hex().upper(),
            "batch": self.batch.hex().upper(),
            "production": f"week {self.cw_production:02X}/year {self.year_production:02X}",
        }


def parse_version(data: bytes) -> DesfireVersion:
    if len(data) < 28:
        raise ValueError(f"GetVersion response too short ({len(data)} bytes)")
    return DesfireVersion(
        hw_vendor=data[0],
        hw_type=data[1],
        hw_subtype=data[2],
        hw_major=data[3],
        hw_minor=data[4],
        hw_storage=data[5],
        hw_protocol=data[6],
        sw_vendor=data[7],
        sw_type=data[8],
        sw_subtype=data[9],
        sw_major=data[10],
        sw_minor=data[11],
        sw_storage=data[12],
        sw_protocol=data[13],
        uid=data[14:21],
        batch=data[21:26],
        cw_production=data[26],
        year_production=data[27],
    )


def parse_application_ids(data: bytes) -> list[bytes]:
    return [data[i : i + 3] for i in range(0, len(data) - 2, 3)]


class DesfireTransport:
    """Sends DESFire native commands and reassembles 0x91AF multi-frame responses."""

    def __init__(self, session: CardSession) -> None:
        self.session = session

    @staticmethod
    def _frame(cmd: int, data: bytes = b"") -> bytes:
        if len(data) > 0xFF:
            raise DesfireFrameTooLargeError(
                f"DESFire native frame data is {len(data)} bytes; this transport sends a single "
                "short frame (Lc <= 255, including any command header and MAC). Chunked / "
                "multi-frame (0x91AF) writes are not implemented yet."
            )
        if data:
            return bytes([0x90, cmd, 0x00, 0x00, len(data)]) + bytes(data) + b"\x00"
        return bytes([0x90, cmd, 0x00, 0x00, 0x00])

    def raw_command(
        self, cmd: int, data: bytes = b"", *, context: str | None = None
    ) -> tuple[int, bytes]:
        """Send one native frame; return ``(status, data)`` without following AF."""
        ctx = context or f"DESFire {cmd:02X}"
        resp = self.session.transmit(self._frame(cmd, data), context=ctx)
        if resp.sw1 != 0x91:
            raise DesfireNotSelectedError(
                f"{ctx}: card answered SW={resp.sw_hex()} (not a DESFire response). "
                "Ensure MIFARE is the selected (default) applet - re-tap the card with no "
                "JavaCard applet selected, on a DESFire-capable contactless reader."
            )
        return resp.sw2, resp.data

    def command(self, cmd: int, data: bytes = b"", *, context: str | None = None) -> bytes:
        """Send a native command and return the accumulated response data (no status)."""
        ctx = context or f"DESFire {cmd:02X}"
        status, first = self.raw_command(cmd, data, context=ctx)
        acc = bytearray(first)
        while status == STATUS_ADDITIONAL_FRAME:
            status, more = self.raw_command(CMD_ADDITIONAL_FRAME, context=f"{ctx} (AF)")
            acc += more
        if status != STATUS_OK:
            raise DesfireError(status, context)
        return bytes(acc)

    # -- read-only operations ---------------------------------------------- #
    def get_version(self) -> DesfireVersion:
        return parse_version(self.command(CMD_GET_VERSION, context="GetVersion"))

    def get_free_memory(self) -> int:
        data = self.command(CMD_GET_FREE_MEMORY, context="GetFreeMemory")
        return int.from_bytes(data[:3], "little")

    def application_ids(self) -> list[bytes]:
        return parse_application_ids(
            self.command(CMD_GET_APPLICATION_IDS, context="GetApplicationIDs")
        )

    def select_application(self, aid: bytes) -> None:
        if len(aid) != 3:
            raise ValueError("DESFire AID must be 3 bytes")
        self.command(CMD_SELECT_APPLICATION, bytes(aid), context="SelectApplication")

    def file_ids(self) -> list[int]:
        return list(self.command(CMD_GET_FILE_IDS, context="GetFileIDs"))

    def get_key_settings(self) -> tuple[int, int, int]:
        """GetKeySettings for the selected application: (settings, key_type_bits, max_keys).

        ``key_type_bits`` is the top two bits of the second byte: 0x00 = DES/2K3DES,
        0x40 = 3K3DES, 0x80 = AES. Readable without authentication when the settings
        permit (the factory default does)."""
        data = self.command(CMD_GET_KEY_SETTINGS, context="GetKeySettings")
        if len(data) < 2:
            raise DesfireError(STATUS_OK, "GetKeySettings (short response)")
        return data[0], data[1] & 0xC0, data[1] & 0x0F

    # -- write operations (plain comm; MACed variants live in ev2.py) ------- #
    def create_application(
        self, aid: bytes, *, key_settings: int = 0x0F, num_keys: int = 3, aes: bool = True
    ) -> None:
        """CreateApplication. KeySettings2 high bits select AES (0x80)."""
        if len(aid) != 3:
            raise ValueError("DESFire AID must be 3 bytes")
        if not (1 <= num_keys <= 14):
            raise ValueError("number of keys must be 1..14")
        ks2 = (0x80 if aes else 0x00) | num_keys
        self.command(
            CMD_CREATE_APPLICATION,
            bytes(aid) + bytes([key_settings, ks2]),
            context="CreateApplication",
        )

    def delete_application(self, aid: bytes) -> None:
        if len(aid) != 3:
            raise ValueError("DESFire AID must be 3 bytes")
        self.command(CMD_DELETE_APPLICATION, bytes(aid), context="DeleteApplication")

    def create_std_data_file(
        self, file_no: int, size: int, *, comm: int = 0x01, access: int = 0xE000, sdm: bool = False
    ) -> None:
        """CreateStdDataFile. ``access`` packs Read|Write|ReadWrite|Change nibbles
        (MSB first); 0xE = free, 0xF = never. Default: free read, key-0 write.

        ``sdm=True`` sets the FileOption SDM bit (0x40) so the file can later carry a
        Secure Dynamic Messaging config (EV3; SDM must be enabled at creation). The SDM
        details themselves are applied with ChangeFileSettings - see ev2.change_file_settings."""
        file_option = (comm & 0x03) | (0x40 if sdm else 0x00)
        data = (
            bytes([file_no, file_option])
            + access.to_bytes(2, "little")
            + size.to_bytes(3, "little")
        )
        self.command(CMD_CREATE_STD_DATA_FILE, data, context="CreateStdDataFile")

    def create_value_file(
        self,
        file_no: int,
        lower: int,
        upper: int,
        value: int,
        *,
        comm: int = 0x01,
        access: int = 0x0000,
        limited_credit: int = 0x00,
    ) -> None:
        """CreateValueFile (plain, like CreateStdDataFile). Default access = key-0 for
        all ops; comm 0x01 = MAC so get/credit/debit go through the EV2 MAC channel."""
        data = (
            bytes([file_no, comm])
            + access.to_bytes(2, "little")
            + lower.to_bytes(4, "little", signed=True)
            + upper.to_bytes(4, "little", signed=True)
            + value.to_bytes(4, "little", signed=True)
            + bytes([limited_credit])
        )
        self.command(CMD_CREATE_VALUE_FILE, data, context="CreateValueFile")

    def create_record_file(
        self,
        file_no: int,
        record_size: int,
        max_records: int,
        *,
        cyclic: bool = False,
        comm: int = 0x01,
        access: int = 0x0000,
    ) -> None:
        """CreateLinear/CyclicRecordFile (plain). comm 0x01 = MAC for write/read."""
        cmd = CMD_CREATE_CYCLIC_RECORD_FILE if cyclic else CMD_CREATE_LINEAR_RECORD_FILE
        data = (
            bytes([file_no, comm])
            + access.to_bytes(2, "little")
            + record_size.to_bytes(3, "little")
            + max_records.to_bytes(3, "little")
        )
        ctx = "CreateCyclicRecordFile" if cyclic else "CreateLinearRecordFile"
        self.command(cmd, data, context=ctx)

    @staticmethod
    def value_arg(file_no: int, amount: int) -> bytes:
        """Credit/Debit argument: file number + signed 4-byte little-endian amount."""
        return bytes([file_no]) + amount.to_bytes(4, "little", signed=True)

    @staticmethod
    def data_header(file_no: int, offset: int, length: int) -> bytes:
        return bytes([file_no]) + offset.to_bytes(3, "little") + length.to_bytes(3, "little")

    def read_data_plain(self, file_no: int, offset: int = 0, length: int = 0) -> bytes:
        """ReadData in plain communication (free-read files; length 0 = whole file)."""
        return self.command(
            CMD_READ_DATA, self.data_header(file_no, offset, length), context="ReadData"
        )


def parse_value(data: bytes) -> int:
    """A GetValue response payload: a signed 4-byte little-endian integer."""
    if len(data) < 4:
        raise ValueError(f"GetValue response too short ({len(data)} bytes)")
    return int.from_bytes(data[:4], "little", signed=True)
