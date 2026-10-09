"""The GlobalPlatform security domain that administers the PIV applet: keyless facts
(which SCP it speaks, which key versions it holds) and the key-management commands
(PUT KEY, DELETE KEY) that a holder of its keys sends it.

The facts are plain GET DATA on the selected domain. No INITIALIZE UPDATE is sent for
them, so nothing there counts against the card's failed-authentication limit.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptnox_id_cli.applets.piv.admin import SCP02, SCP03, scp_label
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.pcsc import CardSession
from cryptnox_id_cli.transport.scp03 import Scp03Keys
from cryptnox_id_cli.util import tlv

PIV_SSD_AID = bytes.fromhex("A00000015153504101")
ISD_AID = bytes.fromhex("A000000151000000")

#: Key version the card ships with on the public GlobalPlatform test key; the one a
#: customer replaces. Version 2 is Cryptnox's own keyset and is left alone.
CUSTOMER_KEY_VERSION = 1
CRYPTNOX_KEY_VERSION = 2

TAG_KEY_INFO_TEMPLATE = 0xE0
TAG_KEY_INFO = 0xC0

# GlobalPlatform key type coding (GPCS 2.3, table 11-16).
KEY_TYPE_DES = 0x80
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


def kcv_des(key: bytes) -> bytes:
    """GP key check value for a 2-key 3DES key: 3DES-ECB of eight zero bytes, first 3 bytes."""
    enc = Cipher(TripleDES(key + key[:8]), modes.ECB()).encryptor()  # noqa: S304 - KCV
    return (enc.update(bytes(8)) + enc.finalize())[:3]


def kcv_aes(key: bytes) -> bytes:
    """GP key check value for an AES key: AES-ECB of sixteen 0x01 bytes, first 3 bytes."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - KCV
    return (enc.update(b"\x01" * 16) + enc.finalize())[:3]


def kcv(scp_version: int, key: bytes) -> bytes:
    return kcv_aes(key) if scp_version == SCP03 else kcv_des(key)


def encrypt_key_des(session_dek: bytes, key: bytes) -> bytes:
    """SCP02 key data: 3DES-ECB under the session DEK."""
    enc = Cipher(TripleDES(session_dek + session_dek[:8]), modes.ECB()).encryptor()  # noqa: S304
    return enc.update(key) + enc.finalize()


def encrypt_key_aes(dek: bytes, key: bytes) -> bytes:
    """SCP03 key data: AES-CBC with a zero ICV under the static DEK."""
    enc = Cipher(algorithms.AES(dek), modes.CBC(bytes(16))).encryptor()
    return enc.update(key) + enc.finalize()


def put_key_apdu(
    scp_version: int,
    dek: bytes,
    new_keys: Scp03Keys,
    *,
    replace_version: int,
    new_version: int,
) -> tuple[APDU, list[bytes]]:
    """PUT KEY writing ENC, MAC and DEK (key IDs 1-3) as ``new_version``.

    ``replace_version`` is the version being replaced; 0 adds a new one. ``dek`` is the
    key the new values travel under: the session DEK on SCP02, the static DEK on SCP03.
    Returns the APDU and the three key check values the card echoes on success.
    """
    blocks = b""
    kcvs: list[bytes] = []
    for key in (new_keys.enc, new_keys.mac, new_keys.dek):
        check = kcv(scp_version, key)
        if scp_version == SCP03:
            block = bytes([KEY_TYPE_AES, 0x11, 0x10]) + encrypt_key_aes(dek, key)
        else:
            block = bytes([KEY_TYPE_DES, 0x10]) + encrypt_key_des(dek, key)
        blocks += block + bytes([0x03]) + check
        kcvs.append(check)
    # P2: bit 8 set = several keys follow, low bits = first key ID.
    return APDU(0x80, 0xD8, replace_version, 0x81, data=bytes([new_version]) + blocks), kcvs


def delete_key_version_apdu(version: int) -> APDU:
    """DELETE every key of one key version (tag D2)."""
    return APDU(0x80, 0xE4, 0x00, 0x00, data=bytes([0xD2, 0x01, version]))


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
