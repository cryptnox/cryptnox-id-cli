"""Hex helpers. Centralised so formatting stays consistent everywhere."""

from __future__ import annotations

from collections.abc import Iterable


def to_hex(data: Iterable[int] | bytes | bytearray, *, sep: str = "") -> str:
    """Render bytes as uppercase hex, optionally separated (e.g. ``sep=" "``)."""
    b = bytes(data)
    if sep:
        return sep.join(f"{x:02X}" for x in b)
    return b.hex().upper()


def from_hex(text: str) -> bytes:
    """Parse a hex string, tolerating spaces, colons and ``0x`` prefixes."""
    cleaned = (
        text.strip()
        .replace("0x", "")
        .replace("0X", "")
        .replace(" ", "")
        .replace(":", "")
        .replace("-", "")
    )
    if len(cleaned) % 2 != 0:
        raise ValueError(f"hex string has an odd number of digits: {text!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex string: {text!r}") from exc


def to_list(data: bytes | bytearray | Iterable[int]) -> list[int]:
    """pyscard wants ``list[int]`` for APDUs."""
    return list(bytes(data))
