"""Generators for basic PIV data objects (CHUID, CCC, Discovery).

These produce minimal, well-formed objects suitable for a dev/test card so the
operator never hand-crafts TLV. FASC-N / Card Identifier use placeholder values;
they are NOT federally meaningful credentials.
"""

from __future__ import annotations

import os

from cryptnox_id_cli.applets.piv.constants import PIV_AID
from cryptnox_id_cli.util import tlv

# CHUID element tags (SP 800-73-4 Part 1 Table 9).
_FASC_N = 0x30
_GUID = 0x34
_EXPIRATION = 0x35
_ISSUER_SIGNATURE = 0x3E
_ERROR_DETECTION = 0xFE


def generate_chuid(guid: bytes | None = None, expiration: str = "20400101") -> bytes:
    """Build a minimal CHUID object value (the content wrapped by tag 0x53).

    ``guid`` defaults to a random 16-byte value; ``expiration`` is YYYYMMDD ASCII.
    The issuer signature (0x3E) is left empty (unsigned dev CHUID).
    """
    guid = guid or os.urandom(16)
    if len(guid) != 16:
        raise ValueError("GUID must be 16 bytes")
    return (
        tlv.build(_FASC_N, bytes(25))  # placeholder FASC-N
        + tlv.build(_GUID, guid)
        + tlv.build(_EXPIRATION, expiration.encode("ascii"))
        + tlv.build(_ISSUER_SIGNATURE, b"")
        + tlv.build(_ERROR_DETECTION, b"")
    )


def generate_ccc(card_id: bytes | None = None) -> bytes:
    """Build a minimal Card Capability Container value (content wrapped by 0x53)."""
    # F0 Card Identifier (21 bytes): GSC-RID A000000116 + mfr/card-type + 14-byte id.
    card_id = card_id or (bytes.fromhex("A000000116") + b"\xff\x02" + os.urandom(14))
    if len(card_id) != 21:
        raise ValueError("CCC card identifier must be 21 bytes")
    return (
        tlv.build(0xF0, card_id)
        + tlv.build(0xF1, b"\x21")  # capability container version
        + tlv.build(0xF2, b"\x21")  # capability grammar version
        + tlv.build(0xF3, b"")  # applications CardURL
        + tlv.build(0xF4, b"\x00")  # PKCS#15
        + tlv.build(0xF5, b"\x10")  # registered data model number
        + tlv.build(0xF6, b"")  # access control rule table
        + tlv.build(0xF7, b"")  # card APDUs
        + tlv.build(0xFA, b"")  # redirection tag
        + tlv.build(0xFB, b"")  # capability tuples
        + tlv.build(0xFC, b"")  # status tuples
        + tlv.build(0xFD, b"")  # next CCC
        + tlv.build(0xFE, b"")  # error detection
    )


# PIN Usage Policy (SP 800-73-4 Part 1, Discovery Object tag 0x5F2F): first byte
# 0x40 = the PIV Application PIN (key ref 0x80) is present; second byte 0x10 = it is
# the primary PIN. We deliberately do NOT offer the Global PIN (first byte 0x20 /
# second byte 0x20, key ref 0x00) -- see docs/adr/0001-piv-application-pin-not-global-pin.md.
_PIN_USAGE_APPLICATION_PRIMARY = b"\x40\x10"


def generate_discovery() -> bytes:
    """Build the Discovery Object (the 0x7E TLV itself, not 0x53-wrapped).

    The PIN Usage Policy is fixed to "Application PIN, primary" (0x40 0x10). The Global
    PIN is intentionally not supported (ADR-0001), so this is not configurable.
    """
    return tlv.build_constructed(
        0x7E, tlv.build(0x4F, PIV_AID) + tlv.build(0x5F2F, _PIN_USAGE_APPLICATION_PRIMARY)
    )
