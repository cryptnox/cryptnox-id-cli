# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Hex helpers. Centralised so formatting stays consistent everywhere."""

from __future__ import annotations

from collections.abc import Iterable

from cryptnox_id_cli.transport.errors import InputError


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
    # The value is left out of the message: it is often a key.
    if len(cleaned) % 2 != 0:
        raise InputError("hex value has an odd number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise InputError("value is not valid hex") from exc


def to_list(data: bytes | bytearray | Iterable[int]) -> list[int]:
    """pyscard wants ``list[int]`` for APDUs."""
    return list(bytes(data))
