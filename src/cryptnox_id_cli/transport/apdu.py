"""APDU command encoding and response wrapping (ISO 7816-4, short + extended)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class APDU:
    """A command APDU. ``le`` is the expected response length; use 256 for the
    short-form ``0x00`` ("up to 256 bytes")."""

    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes = b""
    le: int | None = None

    def to_bytes(self) -> bytes:
        header = bytes((self.cla & 0xFF, self.ins & 0xFF, self.p1 & 0xFF, self.p2 & 0xFF))
        data = bytes(self.data)
        le = self.le
        extended = len(data) > 0xFF or (le is not None and le > 256)

        if not data and le is None:  # case 1
            return header
        if not data:  # case 2 (Le only; le is not None - case 1 returned above)
            if le is None:
                raise ValueError("case 2 APDU requires Le")
            if not extended:
                return header + bytes((le & 0xFF if le != 256 else 0x00,))
            return header + b"\x00" + (le & 0xFFFF if le != 65536 else 0).to_bytes(2, "big")

        if not extended:  # case 3 / 4 short
            out = header + bytes((len(data),)) + data
            if le is not None:
                out += bytes((le & 0xFF if le != 256 else 0x00,))
            return out

        out = header + b"\x00" + len(data).to_bytes(2, "big") + data  # case 3 / 4 extended
        if le is not None:
            out += (le & 0xFFFF if le != 65536 else 0).to_bytes(2, "big")
        return out

    def to_list(self) -> list[int]:
        return list(self.to_bytes())

    def header_hex(self) -> str:
        return bytes((self.cla, self.ins, self.p1, self.p2)).hex().upper()


@dataclass(frozen=True)
class Response:
    """A response APDU: payload plus the two status bytes."""

    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> int:
        return ((self.sw1 & 0xFF) << 8) | (self.sw2 & 0xFF)

    @property
    def ok(self) -> bool:
        return self.sw == 0x9000

    def sw_hex(self) -> str:
        return f"{self.sw1:02X}{self.sw2:02X}"

    def data_hex(self) -> str:
        return self.data.hex().upper()
