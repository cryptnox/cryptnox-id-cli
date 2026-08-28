"""PIV data-object registry plus GET DATA construction / unwrapping."""

from __future__ import annotations

import contextlib
import gzip
from dataclasses import dataclass

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.util import tlv
from cryptnox_id_cli.util.hexutil import from_hex

TAG_DATA = 0x53  # most PIV objects are wrapped in tag 0x53
TAG_DISCOVERY = 0x7E
TAG_CERT = 0x70  # certificate (possibly gzip-compressed)
TAG_CERTINFO = 0x71  # 1 byte; bit0 set => certificate is gzip-compressed


@dataclass(frozen=True)
class PivObject:
    name: str
    oid: bytes
    description: str
    mandatory: bool = False
    pin_protected: bool = False
    slot: int | None = None

    @property
    def oid_hex(self) -> str:
        return self.oid.hex().upper()


PIV_OBJECTS: list[PivObject] = [
    PivObject("ccc", from_hex("5FC107"), "Card Capability Container", mandatory=True),
    PivObject("chuid", from_hex("5FC102"), "Card Holder Unique Identifier", mandatory=True),
    PivObject("discovery", bytes([TAG_DISCOVERY]), "Discovery Object", mandatory=False),
    PivObject(
        "auth-cert", from_hex("5FC105"), "Certificate for PIV Auth (9A)", slot=c.KEYREF_PIV_AUTH
    ),
    PivObject(
        "sign-cert",
        from_hex("5FC10A"),
        "Certificate for Digital Sig (9C)",
        slot=c.KEYREF_DIGITAL_SIGNATURE,
    ),
    PivObject(
        "keymgmt-cert",
        from_hex("5FC10B"),
        "Certificate for Key Mgmt (9D)",
        slot=c.KEYREF_KEY_MANAGEMENT,
    ),
    PivObject(
        "card-auth-cert",
        from_hex("5FC101"),
        "Certificate for Card Auth (9E)",
        slot=c.KEYREF_CARD_AUTH,
    ),
    # Key-attestation leaf, stored in the retired-slot-95 certificate container (5FC120).
    # This repurposes a retired-key cert container (least likely to hold a real retired key)
    # to carry the factory/issuance-time PIV key-attestation leaf — see docs/attestation-format.md.
    PivObject(
        "attestation-cert",
        from_hex("5FC120"),
        "PIV key attestation leaf (retired slot 95 container)",
        slot=0x95,
    ),
    PivObject("security-object", from_hex("5FC106"), "Security Object"),
    PivObject("key-history", from_hex("5FC10C"), "Key History Object"),
    PivObject("printed", from_hex("5FC109"), "Printed Information", pin_protected=True),
    PivObject("fingerprints", from_hex("5FC103"), "Cardholder Fingerprints", pin_protected=True),
    PivObject("facial", from_hex("5FC108"), "Cardholder Facial Image", pin_protected=True),
    PivObject("bitg", from_hex("7F61"), "Biometric Information Templates Group"),
]

OBJECTS_BY_NAME: dict[str, PivObject] = {o.name: o for o in PIV_OBJECTS}


def object_by_name(name: str) -> PivObject | None:
    return OBJECTS_BY_NAME.get(name.lower())


def get_data_apdu(oid: bytes) -> APDU:
    """Build a GET DATA APDU for the given object identifier."""
    tag_list = bytes([0x5C, len(oid)]) + oid
    return APDU(0x00, c.INS_GET_DATA, 0x3F, 0xFF, data=tag_list, le=256)


def unwrap(oid: bytes, data: bytes) -> bytes:
    """Strip the outer tag-0x53 wrapper for standard objects; pass discovery through."""
    if oid == bytes([TAG_DISCOVERY]):
        return data
    try:
        tlvs = tlv.parse(data)
    except ValueError:
        return data
    node = tlv.find(tlvs, TAG_DATA)
    return node.value if node is not None else data


def extract_certificate(object_value: bytes) -> bytes | None:
    """Pull the DER certificate out of a PIV certificate container (tag 0x70),
    decompressing it if the CertInfo (tag 0x71) flags gzip. ``object_value`` is the
    already-unwrapped object content."""
    try:
        nodes = tlv.parse(object_value)
    except ValueError:
        return None
    # Look only at the container's own top-level TLVs. tlv.find descends depth-first,
    # and tag 0x70 is constructed, so a find() for 0x71 could match a node *inside*
    # the certificate's parsed DER and read the wrong gzip flag.
    cert = next((n for n in nodes if n.tag == TAG_CERT), None)
    if cert is None:
        return None
    der = cert.value
    info = next((n for n in nodes if n.tag == TAG_CERTINFO), None)
    if info is not None and info.value and (info.value[0] & 0x01):
        with contextlib.suppress(Exception):
            der = gzip.decompress(der)
    return der


def wrap_certificate(der: bytes, *, compressed: bool = False) -> bytes:
    """Build a PIV certificate container value: 70 <cert> 71 01 <info> FE 00."""
    info = 0x01 if compressed else 0x00
    return tlv.build(TAG_CERT, der) + tlv.build(TAG_CERTINFO, bytes([info])) + tlv.build(0xFE, b"")
