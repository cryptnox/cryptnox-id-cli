"""SCP02 secure channel (GlobalPlatform Card Spec 2.x), used for PIV admin commands.

Some Cryptnox cards present an SCP02 admin channel rather than SCP03 -- notably the
JCOP4 D321 / A27F 110KB family, whose PIV admin SSD is an SCP02 Security Domain. On
those, ``INITIALIZE UPDATE`` returns a 28-byte body with ``keyInfo[1] == 0x02`` and the
SCP03 layer cannot speak to the card. This module mirrors :mod:`scp03`'s shape
(:class:`Scp02Keys`, :class:`Scp02Session`, :func:`open_channel`) so that
:class:`~cryptnox_id_cli.applets.piv.admin.PivAdmin` is agnostic to the SCP version.

The crypto follows GlobalPlatformPro (the proven ``gp`` reference) for implementation
option **i = 0x55** (``icvEnc = true``, ``macModifiedAPDU = true``):

* **Session keys** (3DES, 2-key) derived by 3DES-CBC with a zero IV over a 16-byte block
  ``<const(2)> | seqCounter(2) | 00*12``: ``S-ENC`` (``0182``), ``S-MAC`` (``0101``),
  ``S-DEK`` (``0181``).
* **Cryptograms** use the full 3DES-CBC MAC (every block 3DES) with ``S-ENC`` and a zero
  IV: card = ``MAC(hostChallenge | cardChallenge)``, host = ``MAC(cardChallenge |
  hostChallenge)`` -- where ``cardChallenge`` is the 8 bytes ``seqCounter(2) |
  random(6)``.
* **C-MAC** is the ISO 9797-1 retail MAC (single-DES chain, final block 3DES) computed
  over the *plaintext* modified APDU (CLA|0x04, INS, P1, P2, origLc+8, data). The ICV
  starts at zero and, for every command after the first, is the previous C-MAC encrypted
  with single-DES under ``S-MAC``.
* **C-ENC** (when the security level includes C-DECRYPTION) is 3DES-CBC under ``S-ENC``
  with a zero IV over 80-padded data, applied *after* the C-MAC (encrypt-and-MAC). The
  transmitted ``Lc`` is the encrypted length + 8, while the C-MAC used origLc + 8.

Correctness is proven end-to-end by the card: wrong keys fail the card-cryptogram check
locally and EXTERNAL AUTHENTICATE is refused -- no silent corruption.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import Scp02Error

_BLOCK = 8
_ZERO_IV = b"\x00" * _BLOCK

# Session-key derivation constants (GP Card Spec 2.2, E.4.1).
_DERIV_S_ENC = b"\x01\x82"
_DERIV_S_MAC = b"\x01\x01"
_DERIV_S_DEK = b"\x01\x81"

# Security-level bits (EXTERNAL AUTHENTICATE P1) -- same encoding as SCP03.
SL_C_MAC = 0x01
SL_C_DECRYPTION = 0x02
SL_CMAC_CENC = SL_C_MAC | SL_C_DECRYPTION  # 0x03

# Largest plaintext we wrap into a single short APDU. Encrypted+padded data plus the
# 8-byte C-MAC must leave the Lc <= 0xFF; larger bodies go via ISO command chaining
# (PivAdmin.send_chained, block_size=200), so this ceiling is never hit in practice.
_MAX_SHORT_PLAINTEXT = 239


def _k3(key: bytes) -> bytes:
    """Expand a 16-byte 2-key 3DES key to the 24-byte K1|K2|K1 form GP uses."""
    return key + key[:8] if len(key) == 16 else key


def _k1(key: bytes) -> bytes:
    """The first 8 key bytes as a 24-byte single-DES key (K1|K1|K1)."""
    return key[:8] * 3


def _des_ecb(key: bytes, block: bytes) -> bytes:
    """Single-DES ECB (the first 8 key bytes), used for ICV encryption."""
    enc = Cipher(TripleDES(_k1(key)), modes.ECB()).encryptor()  # noqa: S304 - single-block ICV
    return enc.update(block) + enc.finalize()


def _des_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Single-DES CBC (the first 8 key bytes)."""
    enc = Cipher(TripleDES(_k1(key)), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _des3_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """3DES CBC (2-key static/session keys expanded to the 24-byte K1|K2|K1 form)."""
    enc = Cipher(TripleDES(_k3(key)), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _pad80(data: bytes) -> bytes:
    """ISO 7816-4 padding: 0x80 then 0x00s to the next 8-byte boundary (always adds)."""
    padded = data + b"\x80"
    if len(padded) % _BLOCK:
        padded += b"\x00" * (_BLOCK - len(padded) % _BLOCK)
    return padded


def _mac_3des(s_enc: bytes, data: bytes) -> bytes:
    """Full 3DES-CBC MAC over 80-padded data, zero IV -- used for the cryptograms."""
    out = _des3_cbc(s_enc, _ZERO_IV, _pad80(data))
    return out[-_BLOCK:]


def _retail_mac(s_mac: bytes, data: bytes, icv: bytes) -> bytes:
    """ISO 9797-1 MAC algorithm 3 (retail MAC): single-DES chain, final block 3DES."""
    padded = _pad80(data)
    iv = icv
    if len(padded) > _BLOCK:
        chain = _des_cbc(s_mac, iv, padded[:-_BLOCK])
        iv = chain[-_BLOCK:]
    return _des3_cbc(s_mac, iv, padded[-_BLOCK:])[-_BLOCK:]


def _derive_key(static_key: bytes, constant: bytes, seq: bytes) -> bytes:
    """Derive one 16-byte session key: 3DES-CBC(zero IV) over const | seq | 00*12."""
    return _des3_cbc(static_key, _ZERO_IV, constant + seq + b"\x00" * 12)


@dataclass
class Scp02Keys:
    enc: bytes
    mac: bytes
    dek: bytes

    @classmethod
    def same(cls, key: bytes) -> Scp02Keys:
        return cls(key, key, key)


class Scp02Session:
    """An open SCP02 session: holds session keys and wraps/unwraps command APDUs."""

    def __init__(self, s_enc: bytes, s_mac: bytes, s_dek: bytes, security_level: int) -> None:
        self.s_enc = s_enc
        self.s_mac = s_mac
        self.s_dek = s_dek
        self.security_level = security_level
        #: last computed C-MAC; ``None`` until the first MAC (EXTERNAL AUTHENTICATE).
        self.icv: bytes | None = None

    def _cmac(self, mac_input: bytes) -> bytes:
        """Retail MAC over ``mac_input`` with ICV chaining; advances the session ICV."""
        # First MAC uses the zero ICV; later commands chain on single-DES(previous C-MAC).
        icv = _ZERO_IV if self.icv is None else _des_ecb(self.s_mac, self.icv)
        mac = _retail_mac(self.s_mac, mac_input, icv)
        self.icv = mac
        return mac

    def wrap(self, apdu: APDU) -> bytes:
        """Return the wrapped command bytes (CLA|0x04, optional C-ENC, C-MAC appended).

        Short Lc only -- callers chain larger bodies (see ``_MAX_SHORT_PLAINTEXT``). The
        C-MAC is computed over the *plaintext* modified APDU (origLc+8); the data is then
        encrypted and the wire Lc becomes the encrypted length + 8.
        """
        data = apdu.data
        if len(data) > _MAX_SHORT_PLAINTEXT:
            raise Scp02Error(
                f"SCP02 wraps short APDUs only ({len(data)} > {_MAX_SHORT_PLAINTEXT} "
                "plaintext bytes); send large bodies via command chaining."
            )
        cla = apdu.cla | 0x04
        header = bytes([cla, apdu.ins, apdu.p1, apdu.p2])

        # C-MAC over the plaintext modified APDU: header | (origLc + 8) | data.
        mac = self._cmac(header + bytes([len(data) + 8]) + data)

        body = data
        if self.security_level & SL_C_DECRYPTION and data:
            body = _des3_cbc(self.s_enc, _ZERO_IV, _pad80(data))

        out = header + bytes([len(body) + 8]) + body + mac
        if apdu.le is not None:
            out += bytes([0x00 if apdu.le >= 256 else apdu.le & 0xFF])
        return out

    def unwrap(self, resp: Response) -> Response:
        """At security level 0x03 the response is plaintext; pass it through."""
        return resp


def derive_session_keys(keys: Scp02Keys, seq: bytes) -> tuple[bytes, bytes, bytes]:
    s_enc = _derive_key(keys.enc, _DERIV_S_ENC, seq)
    s_mac = _derive_key(keys.mac, _DERIV_S_MAC, seq)
    s_dek = _derive_key(keys.dek, _DERIV_S_DEK, seq)
    return s_enc, s_mac, s_dek


def open_channel(
    transmit,
    keys: Scp02Keys,
    *,
    key_version: int = 0,
    security_level: int = SL_CMAC_CENC,
    host_challenge: bytes | None = None,
    init_response: Response | None = None,
) -> Scp02Session:
    """Run INITIALIZE UPDATE + EXTERNAL AUTHENTICATE for SCP02.

    ``transmit(APDU|bytes) -> Response``. If ``init_response`` is given (the caller has
    already issued INITIALIZE UPDATE to auto-detect the SCP version), it is reused with
    the matching ``host_challenge`` instead of issuing a second one.

    Raises :class:`Scp02Error` on a wrong key (card-cryptogram mismatch) or a card
    rejection.
    """
    if init_response is None:
        host_challenge = host_challenge or os.urandom(8)
        resp = transmit(APDU(0x80, 0x50, key_version, 0x00, data=host_challenge, le=256))
    else:
        if host_challenge is None:
            raise Scp02Error("host_challenge is required when init_response is supplied.")
        resp = init_response

    if not resp.ok:
        raise Scp02Error(f"INITIALIZE UPDATE rejected (SW={resp.sw_hex()}).")
    body = resp.data
    if len(body) < 28:
        raise Scp02Error(f"INITIALIZE UPDATE response too short ({len(body)} bytes) for SCP02.")

    # keyDivData(10) | keyInfo(2: ver, 0x02) | seqCounter(2) | cardChallenge(6) | cardCrypto(8).
    seq = body[12:14]
    card_challenge = body[12:20]  # full 8-byte challenge = seqCounter | random(6)
    card_cryptogram = body[20:28]

    s_enc, s_mac, s_dek = derive_session_keys(keys, seq)

    expected = _mac_3des(s_enc, host_challenge + card_challenge)
    if expected != card_cryptogram:
        raise Scp02Error("Card cryptogram mismatch - the SCP02 keys are wrong for this card.")

    session = Scp02Session(s_enc, s_mac, s_dek, security_level)
    host_cryptogram = _mac_3des(s_enc, card_challenge + host_challenge)

    # EXTERNAL AUTHENTICATE: CLA 0x84, P1 = security level, Lc = 0x10 (host cryptogram + C-MAC).
    # The host cryptogram is MACed in clear (never encrypted), with the zero ICV.
    header = bytes([0x84, 0x82, security_level, 0x00])
    mac = session._cmac(header + bytes([len(host_cryptogram) + 8]) + host_cryptogram)
    ext_auth = header + bytes([len(host_cryptogram) + 8]) + host_cryptogram + mac

    resp = transmit(ext_auth)
    if not resp.ok:
        raise Scp02Error(
            f"EXTERNAL AUTHENTICATE rejected (SW={resp.sw_hex()}); "
            "keys or security level may be wrong."
        )
    return session
