"""Keyless facts about the GlobalPlatform security domain that administers the PIV
applet: which SCP it speaks and which key versions it holds.

Both reads are plain GET DATA on the selected domain. No INITIALIZE UPDATE is sent,
so nothing here counts against the card's failed-authentication limit.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptnox_id_cli.applets.piv.admin import SCP02, SCP03, scp_label
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.pcsc import CardSession
from cryptnox_id_cli.util import tlv

PIV_SSD_AID = bytes.fromhex("A00000015153504101")
ISD_AID = bytes.fromhex("A000000151000000")

TAG_KEY_INFO_TEMPLATE = 0xE0
TAG_KEY_INFO = 0xC0

# GlobalPlatform key type coding (GPCS 2.3, table 11-16).
KEY_TYPE_AES = 0x88
_DES_TYPES = frozenset({0x80, 0x81, 0x82, 0x83, 0x84})
_KEY_TYPES = {
    0x80: "DES",
    0x81: "3DES",
    0x82: "3DES-CBC",
    0x83: "DES-ECB",
    0x84: "DES-CBC",
    0x85: "TLS-PSK",
    0x88: "AES",
    0x90: "HMAC-SHA1",
    0x91: "HMAC-SHA1-160",
    0xA0: "RSA-e",
    0xA1: "RSA-N",
    0xB0: "ECC-public",
    0xB1: "ECC-private",
}


@dataclass(frozen=True)
class KeyEntry:
    key_id: int
    key_version: int
    key_type: int
    length: int

    @property
    def type_name(self) -> str:
        return _KEY_TYPES.get(self.key_type, f"{self.key_type:#04x}")

    def to_dict(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "key_version": self.key_version,
            "type": self.type_name,
            "type_raw": f"{self.key_type:02X}",
            "length": self.length,
        }


@dataclass(frozen=True)
class SecurityDomainInfo:
    aid: bytes
    keys: tuple[KeyEntry, ...]
    key_table_sw: int

    @property
    def aid_hex(self) -> str:
        return self.aid.hex().upper()

    @property
    def scp_version(self) -> int | None:
        """SCP03 for an AES keyset, SCP02 for a DES one; ``None`` when unreadable or mixed."""
        types = {k.key_type for k in self.keys}
        if types and all(t == KEY_TYPE_AES for t in types):
            return SCP03
        if types and types <= _DES_TYPES:
            return SCP02
        return None

    @property
    def key_versions(self) -> list[int]:
        return sorted({k.key_version for k in self.keys})

    def keys_for(self, version: int) -> list[KeyEntry]:
        return [k for k in self.keys if k.key_version == version]

    def to_dict(self) -> dict[str, object]:
        return {
            "aid": self.aid_hex,
            "scp_version": scp_label(self.scp_version) if self.scp_version else None,
            "key_table_sw": f"{self.key_table_sw:04X}",
            "key_versions": [
                {"version": v, "keys": [k.to_dict() for k in self.keys_for(v)]}
                for v in self.key_versions
            ],
        }


def parse_key_information(data: bytes) -> list[KeyEntry]:
    """Entries of a Key Information Template (``E0`` of ``C0`` records)."""
    nodes = tlv.parse(data, recurse=False)
    template = next((n for n in nodes if n.tag == TAG_KEY_INFO_TEMPLATE), None)
    body = template.value if template is not None else bytes(data)
    entries: list[KeyEntry] = []
    for node in tlv.parse(body, recurse=False):
        v = node.value
        if node.tag != TAG_KEY_INFO or len(v) < 4:
            continue
        if v[2] == 0xFF:  # extended format: id, version, FF, type, length(2)
            if len(v) >= 6:
                entries.append(KeyEntry(v[0], v[1], v[3], int.from_bytes(v[4:6], "big")))
            continue
        entries.append(KeyEntry(v[0], v[1], v[2], v[3]))
    return entries


def select_security_domain(session: CardSession, aid: bytes) -> Response:
    label = f"SELECT SD {aid.hex().upper()}"
    resp = session.transmit(APDU(0x00, 0xA4, 0x04, 0x00, data=aid, le=256), context=label)
    if resp.sw == 0x6700:  # same case-4 quirk as the applet SELECTs: retry without Le
        resp = session.transmit(APDU(0x00, 0xA4, 0x04, 0x00, data=aid), context=f"{label} (no Le)")
    return resp


def read_key_information(session: CardSession) -> Response:
    return session.transmit(
        APDU(0x80, 0xCA, 0x00, TAG_KEY_INFO_TEMPLATE, le=256), context="GET DATA (key info)"
    )


def describe_security_domain(
    session: CardSession, aids: tuple[bytes, ...] = (PIV_SSD_AID, ISD_AID)
) -> SecurityDomainInfo | None:
    """The first selectable domain in ``aids`` with its key table, or ``None``.

    Leaves that domain selected; re-select the PIV applet before using it.
    """
    for aid in aids:
        if not select_security_domain(session, aid).ok:
            continue
        resp = read_key_information(session)
        keys = tuple(parse_key_information(resp.data)) if resp.ok else ()
        return SecurityDomainInfo(aid=aid, keys=keys, key_table_sw=resp.sw)
    return None
