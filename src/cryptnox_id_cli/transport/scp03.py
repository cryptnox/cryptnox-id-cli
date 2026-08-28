"""SCP03 secure channel (GlobalPlatform Amendment D), used for PIV admin commands.

Implements the SP 800-108 counter-mode KDF (AES-CMAC PRF), session-key derivation,
card/host cryptograms, C-MAC chaining and C-ENC command wrapping. Response security
(R-MAC/R-ENC) is not requested by default (security level 0x03 = C-MAC + C-DECRYPTION).

Correctness is proven end-to-end by the card: if our derived keys are wrong, the card
cryptogram check fails locally and EXTERNAL AUTHENTICATE is refused by the card.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import Scp03Error

_BLOCK = 16

# KDF derivation constants (GP Amd D, Table 4-1).
_DERIV_CARD_CRYPTOGRAM = 0x00
_DERIV_HOST_CRYPTOGRAM = 0x01
_DERIV_S_ENC = 0x04
_DERIV_S_MAC = 0x06
_DERIV_S_RMAC = 0x07

# Security-level bits (EXTERNAL AUTHENTICATE P1).
SL_C_MAC = 0x01
SL_C_DECRYPTION = 0x02
SL_R_MAC = 0x10
SL_R_ENCRYPTION = 0x20
SL_CMAC_CENC = SL_C_MAC | SL_C_DECRYPTION  # 0x03


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - single-block ICV
    return enc.update(block) + enc.finalize()


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _kdf(key: bytes, constant: int, context: bytes, length_bits: int) -> bytes:
    """SP 800-108 counter-mode KDF with an AES-CMAC PRF (SCP03 flavour)."""
    out = b""
    counter = 1
    while len(out) * 8 < length_bits:
        block = (
            b"\x00" * 11
            + bytes([constant])
            + b"\x00"
            + length_bits.to_bytes(2, "big")
            + bytes([counter])
            + context
        )
        out += _aes_cmac(key, block)
        counter += 1
    return out[: length_bits // 8]


def _pad80(data: bytes) -> bytes:
    """ISO 7816-4 / SCP03 padding: 0x80 then 0x00s to the next block boundary."""
    padded = data + b"\x80"
    if len(padded) % _BLOCK:
        padded += b"\x00" * (_BLOCK - len(padded) % _BLOCK)
    return padded


@dataclass
class Scp03Keys:
    enc: bytes
    mac: bytes
    dek: bytes

    @classmethod
    def same(cls, key: bytes) -> Scp03Keys:
        return cls(key, key, key)

    @property
    def key_bits(self) -> int:
        return len(self.enc) * 8


class Scp03Session:
    """An open SCP03 session: holds session keys and wraps/unwraps command APDUs."""

    def __init__(self, s_enc: bytes, s_mac: bytes, s_rmac: bytes, security_level: int) -> None:
        self.s_enc = s_enc
        self.s_mac = s_mac
        self.s_rmac = s_rmac
        self.security_level = security_level
        self.mac_chaining = b"\x00" * _BLOCK
        self.encrypt_counter = 1

    def _encrypt(self, data: bytes) -> bytes:
        if not data:
            return data
        icv = _aes_ecb(self.s_enc, self.encrypt_counter.to_bytes(_BLOCK, "big"))
        return _aes_cbc_encrypt(self.s_enc, icv, _pad80(data))

    def wrap(self, apdu: APDU) -> bytes:
        """Return the wrapped command bytes (CLA|0x04, optional C-ENC, C-MAC appended).

        Supports short and extended Lc (the pre-perso BULK is ~316 bytes -> extended).
        The C-MAC is computed over the command exactly as transmitted (incl. the Lc
        field), then its first 8 bytes are appended.
        """
        data = apdu.data
        if self.security_level & SL_C_DECRYPTION:
            data = self._encrypt(data)
        lc = len(data) + 8  # +8 for the C-MAC
        cla = apdu.cla | 0x04
        if lc <= 0xFF:
            header = bytes([cla, apdu.ins, apdu.p1, apdu.p2, lc])
            le_bytes = (
                b"" if apdu.le is None else bytes([0x00 if apdu.le >= 256 else apdu.le & 0xFF])
            )
        else:  # extended length
            header = bytes([cla, apdu.ins, apdu.p1, apdu.p2, 0x00, (lc >> 8) & 0xFF, lc & 0xFF])
            le_bytes = b"" if apdu.le is None else (apdu.le & 0xFFFF).to_bytes(2, "big")
        full_mac = _aes_cmac(self.s_mac, self.mac_chaining + header + data)
        self.mac_chaining = full_mac
        self.encrypt_counter += 1
        return header + data + full_mac[:8] + le_bytes

    def unwrap(self, resp: Response) -> Response:
        """With level 0x03 the response is plaintext; pass it through."""
        if self.security_level & (SL_R_MAC | SL_R_ENCRYPTION):
            raise Scp03Error("R-MAC/R-ENC responses are not implemented")
        return resp


def derive_session_keys(
    keys: Scp03Keys, host_challenge: bytes, card_challenge: bytes
) -> tuple[bytes, bytes, bytes]:
    context = host_challenge + card_challenge
    bits = keys.key_bits
    s_enc = _kdf(keys.enc, _DERIV_S_ENC, context, bits)
    s_mac = _kdf(keys.mac, _DERIV_S_MAC, context, bits)
    s_rmac = _kdf(keys.mac, _DERIV_S_RMAC, context, bits)
    return s_enc, s_mac, s_rmac


def _cryptogram(s_mac: bytes, constant: int, host_challenge: bytes, card_challenge: bytes) -> bytes:
    return _kdf(s_mac, constant, host_challenge + card_challenge, 64)


def open_channel(
    transmit,
    keys: Scp03Keys,
    *,
    key_version: int = 0,
    security_level: int = SL_CMAC_CENC,
    host_challenge: bytes | None = None,
    init_response: Response | None = None,
) -> Scp03Session:
    """Run INITIALIZE UPDATE + EXTERNAL AUTHENTICATE. ``transmit(APDU|bytes)->Response``.

    If ``init_response`` is given (the caller already issued INITIALIZE UPDATE to
    auto-detect the SCP version), it is reused with the matching ``host_challenge``
    instead of issuing a second one.

    Raises Scp03Error on a wrong key (card cryptogram mismatch) or a card rejection.
    """
    if init_response is None:
        host_challenge = host_challenge or os.urandom(8)
        resp = transmit(APDU(0x80, 0x50, key_version, 0x00, data=host_challenge, le=256))
    else:
        if host_challenge is None:
            raise Scp03Error("host_challenge is required when init_response is supplied.")
        resp = init_response
    if not resp.ok:
        raise Scp03Error(f"INITIALIZE UPDATE rejected (SW={resp.sw_hex()}).")
    body = resp.data
    if len(body) < 29:
        raise Scp03Error(f"INITIALIZE UPDATE response too short ({len(body)} bytes).")
    card_challenge = body[13:21]
    card_cryptogram = body[21:29]

    s_enc, s_mac, s_rmac = derive_session_keys(keys, host_challenge, card_challenge)

    expected = _cryptogram(s_mac, _DERIV_CARD_CRYPTOGRAM, host_challenge, card_challenge)
    if expected != card_cryptogram:
        raise Scp03Error("Card cryptogram mismatch - the SCP03 keys are wrong for this card.")

    session = Scp03Session(s_enc, s_mac, s_rmac, security_level)
    host_cryptogram = _cryptogram(s_mac, _DERIV_HOST_CRYPTOGRAM, host_challenge, card_challenge)

    # EXTERNAL AUTHENTICATE: CLA 0x84, Lc=0x10 (8-byte host cryptogram + 8-byte C-MAC).
    header = bytes([0x84, 0x82, security_level, 0x00, 0x10])
    full_mac = _aes_cmac(session.s_mac, session.mac_chaining + header + host_cryptogram)
    session.mac_chaining = full_mac
    ext_auth = header + host_cryptogram + full_mac[:8]

    resp = transmit(ext_auth)
    if not resp.ok:
        raise Scp03Error(
            f"EXTERNAL AUTHENTICATE rejected (SW={resp.sw_hex()}); "
            "keys or security level may be wrong."
        )
    return session
