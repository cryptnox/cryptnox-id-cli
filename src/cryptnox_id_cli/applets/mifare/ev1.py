"""DESFire EV1 secure messaging for a DES / 2K3DES key: AuthenticateISO (0x1A), the
3DES CMAC chain, FormatPICC and moving the PICC master key to AES.

Factory cards ship with a 2K3DES PICC master key, which AuthenticateEV2First cannot
use. These commands follow the EV1 ("AS_NEW") scheme: CBC with an IV that chains
through the handshake, then an 8-byte 3DES CMAC whose running value is the IV.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from cryptnox_id_cli.applets.mifare.desfire import (
    CMD_ADDITIONAL_FRAME,
    CMD_CHANGE_KEY,
    CMD_FORMAT_PICC,
    CMD_GET_KEY_SETTINGS,
    STATUS_ADDITIONAL_FRAME,
    STATUS_OK,
    DesfireError,
    DesfireTransport,
)
from cryptnox_id_cli.applets.mifare.ev2 import desfire_crc32, rot_left
from cryptnox_id_cli.transport.errors import CryptnoxError

CMD_AUTHENTICATE_ISO = 0x1A
BLOCK = 8
_RB = 0x1B
#: Key-number bit that makes ChangeKey on the PICC master key store an AES key.
PICC_KEY_AES = 0x80


def _cbc(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    cipher = Cipher(TripleDES(key + key[:8]), modes.CBC(iv))  # noqa: S304 - DESFire EV1
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


def session_key(key: bytes, rnd_a: bytes, rnd_b: bytes) -> bytes:
    """The 16-byte session key. A key with identical halves is single DES on the card,
    and so is its session key."""
    if key[:8] == key[8:]:
        half = rnd_a[:4] + rnd_b[:4]
        return half + half
    return rnd_a[:4] + rnd_b[:4] + rnd_a[4:8] + rnd_b[4:8]


def _shift(block: bytes) -> bytes:
    value = (int.from_bytes(block, "big") << 1) & ((1 << (8 * BLOCK)) - 1)
    return value.to_bytes(BLOCK, "big")


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    l_block = _cbc(key, bytes(BLOCK), bytes(BLOCK), encrypt=True)
    k1 = bytearray(_shift(l_block))
    if l_block[0] & 0x80:
        k1[-1] ^= _RB
    k2 = bytearray(_shift(bytes(k1)))
    if k1[0] & 0x80:
        k2[-1] ^= _RB
    return bytes(k1), bytes(k2)


def cmac(key: bytes, iv: bytes, data: bytes) -> bytes:
    """3DES CMAC (SP 800-38B) whose chaining starts from ``iv``."""
    k1, k2 = _subkeys(key)
    if data and len(data) % BLOCK == 0:
        last = bytes(a ^ b for a, b in zip(data[-BLOCK:], k1, strict=True))
        padded = data[:-BLOCK] + last
    else:
        tail = data[len(data) - len(data) % BLOCK :] + b"\x80"
        tail += bytes(BLOCK - len(tail))
        last = bytes(a ^ b for a, b in zip(tail, k2, strict=True))
        padded = data[: len(data) - len(data) % BLOCK] + last
    return _cbc(key, iv, padded, encrypt=True)[-BLOCK:]


@dataclass
class Ev1Session:
    key: bytes
    iv: bytes = field(default=bytes(BLOCK))

    def mac_command(self, command: bytes) -> None:
        """Advance the IV over a plain command, as the card does."""
        self.iv = cmac(self.key, self.iv, command)

    def verify_response(self, payload: bytes, status: int, mac: bytes, context: str) -> None:
        expected = cmac(self.key, self.iv, payload + bytes([status]))
        if mac != expected:
            raise CryptnoxError(f"{context}: the card's response MAC does not verify.")
        self.iv = expected

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = _cbc(self.key, self.iv, plaintext, encrypt=True)
        self.iv = ciphertext[-BLOCK:]
        return ciphertext


def authenticate_iso(
    transport: DesfireTransport, key_no: int, key: bytes, *, rnd_a: bytes | None = None
) -> Ev1Session:
    """AuthenticateISO with a 16-byte DES / 2K3DES key."""
    status, enc_b = transport.raw_command(
        CMD_AUTHENTICATE_ISO, bytes([key_no]), context="AuthenticateISO"
    )
    if status != STATUS_ADDITIONAL_FRAME or len(enc_b) != BLOCK:
        raise DesfireError(status, "AuthenticateISO")
    rnd_b = _cbc(key, bytes(BLOCK), enc_b, encrypt=False)
    rnd_a = rnd_a if rnd_a is not None else os.urandom(BLOCK)
    token = _cbc(key, enc_b, rnd_a + rot_left(rnd_b), encrypt=True)
    status, enc_a = transport.raw_command(
        CMD_ADDITIONAL_FRAME, token, context="AuthenticateISO (AF)"
    )
    if status != STATUS_OK or len(enc_a) != BLOCK:
        raise DesfireError(status, "AuthenticateISO (AF)")
    if _cbc(key, token[-BLOCK:], enc_a, encrypt=False) != rot_left(rnd_a):
        raise CryptnoxError(
            "AuthenticateISO: the card's answer does not match; not the card's key."
        )
    return _confirmed_session(transport, key, rnd_a, rnd_b)


def _confirmed_session(
    transport: DesfireTransport, key: bytes, rnd_a: bytes, rnd_b: bytes
) -> Ev1Session:
    """The session key the card actually uses, settled by the MAC on GetKeySettings
    before any command that changes the card."""
    # Whether the card treats a key as single DES depends on bits the host may not see
    # the same way (parity, key version), so both forms are tried against the card's MAC.
    preferred = session_key(key, rnd_a, rnd_b)
    other = rnd_a[:4] + rnd_b[:4] + rnd_a[4:8] + rnd_b[4:8]
    if other == preferred:
        half = rnd_a[:4] + rnd_b[:4]
        other = half + half
    command = bytes([CMD_GET_KEY_SETTINGS])
    status, data = transport.raw_command(CMD_GET_KEY_SETTINGS, context="GetKeySettings")
    if status != STATUS_OK:
        raise DesfireError(status, "GetKeySettings")
    if len(data) <= BLOCK:
        return Ev1Session(preferred, cmac(preferred, bytes(BLOCK), command))
    payload, mac = data[:-BLOCK], data[-BLOCK:]
    for candidate in (preferred, other):
        iv = cmac(candidate, bytes(BLOCK), command)
        expected = cmac(candidate, iv, payload + bytes([status]))
        if mac == expected:
            return Ev1Session(candidate, expected)
    raise CryptnoxError(
        "AuthenticateISO: the card's MAC matches neither DES nor 2K3DES session key; "
        "nothing was changed."
    )


def format_picc_iso(transport: DesfireTransport, session: Ev1Session) -> None:
    """FormatPICC under an EV1 session (plain command, MAC'd response)."""
    session.mac_command(bytes([CMD_FORMAT_PICC]))
    status, data = transport.raw_command(CMD_FORMAT_PICC, context="FormatPICC")
    if status != STATUS_OK:
        raise DesfireError(status, "FormatPICC")
    if data:
        session.verify_response(data[:-BLOCK], status, data[-BLOCK:], "FormatPICC")


def change_picc_key_to_aes(
    transport: DesfireTransport, session: Ev1Session, new_key: bytes, version: int = 0
) -> None:
    """ChangeKey on the PICC master key (the key the session holds) to an AES-128 key.
    The session ends with it."""
    header = bytes([CMD_CHANGE_KEY, PICC_KEY_AES])
    body = new_key + bytes([version & 0xFF])
    plain = body + desfire_crc32(header + body)
    plain += bytes(-len(plain) % BLOCK)
    status, _ = transport.raw_command(
        CMD_CHANGE_KEY,
        bytes([PICC_KEY_AES]) + session.encrypt(plain),
        context="ChangeKey (PICC master key to AES)",
    )
    if status != STATUS_OK:
        raise DesfireError(status, "ChangeKey (PICC master key to AES)")
