"""CTAP2 PIN/UV Auth Protocol (one and two) - the crypto under FIDO PIN + token ops.

Both protocols agree a shared secret over ECDH (P-256), then provide ``encrypt`` /
``decrypt`` / ``authenticate``:

- **Protocol one:** sharedSecret = SHA-256(Z); AES-256-CBC with a zero IV; HMAC-SHA-256
  truncated to 16 bytes.
- **Protocol two:** sharedSecret = HKDF(Z) -> 32-byte HMAC key || 32-byte AES key;
  AES-256-CBC with a random IV prepended to the ciphertext; full HMAC-SHA-256.

``Z`` is the 32-byte X coordinate of the ECDH point.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptnox_id_cli.applets.fido import constants as c

_P256 = ec.SECP256R1()


def _sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def _hmac256(key: bytes, msg: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def _aes_cbc(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


def cose_to_public_key(cose: dict) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(cose[c.COSE_X], "big")
    y = int.from_bytes(cose[c.COSE_Y], "big")
    return ec.EllipticCurvePublicNumbers(x, y, _P256).public_key()


def public_key_to_cose(pub: ec.EllipticCurvePublicKey) -> dict:
    nums = pub.public_numbers()
    return {
        c.COSE_KTY: c.COSE_KTY_EC2,
        c.COSE_ALG: c.COSE_ALG_ECDH_ES_HKDF256,
        c.COSE_CRV: c.COSE_CRV_P256,
        c.COSE_X: nums.x.to_bytes(32, "big"),
        c.COSE_Y: nums.y.to_bytes(32, "big"),
    }


class PinUvAuthProtocol:
    version: int

    def __init__(self, shared_secret: bytes) -> None:
        self.shared_secret = shared_secret

    @staticmethod
    def kdf(z: bytes) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError

    def encrypt(self, plaintext: bytes) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError

    def authenticate(self, message: bytes) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError


class ProtocolOne(PinUvAuthProtocol):
    version = 1

    @staticmethod
    def kdf(z: bytes) -> bytes:
        return _sha256(z)

    def encrypt(self, plaintext: bytes) -> bytes:
        return _aes_cbc(self.shared_secret, b"\x00" * 16, plaintext, encrypt=True)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return _aes_cbc(self.shared_secret, b"\x00" * 16, ciphertext, encrypt=False)

    def authenticate(self, message: bytes) -> bytes:
        return _hmac256(self.shared_secret, message)[:16]


class ProtocolTwo(PinUvAuthProtocol):
    version = 2

    @staticmethod
    def kdf(z: bytes) -> bytes:
        salt = b"\x00" * 32
        hmac_key = HKDF(hashes.SHA256(), 32, salt, b"CTAP2 HMAC key").derive(z)
        aes_key = HKDF(hashes.SHA256(), 32, salt, b"CTAP2 AES key").derive(z)
        return hmac_key + aes_key

    @property
    def _hmac_key(self) -> bytes:
        return self.shared_secret[:32]

    @property
    def _aes_key(self) -> bytes:
        return self.shared_secret[32:]

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        return iv + _aes_cbc(self._aes_key, iv, plaintext, encrypt=True)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return _aes_cbc(self._aes_key, ciphertext[:16], ciphertext[16:], encrypt=False)

    def authenticate(self, message: bytes) -> bytes:
        return _hmac256(self._hmac_key, message)


_PROTOCOLS: dict[int, type[PinUvAuthProtocol]] = {1: ProtocolOne, 2: ProtocolTwo}


def encapsulate(peer_cose: dict, version: int) -> tuple[dict, PinUvAuthProtocol]:
    """ECDH against the authenticator's public key; returns the platform COSE key to
    send and the initialized protocol (holding the shared secret)."""
    cls = _PROTOCOLS.get(version)
    if cls is None:
        raise ValueError(f"unsupported PIN/UV auth protocol {version}")
    ephemeral = ec.generate_private_key(_P256)
    z = ephemeral.exchange(ec.ECDH(), cose_to_public_key(peer_cose))
    return public_key_to_cose(ephemeral.public_key()), cls(cls.kdf(z))


# -- PIN value helpers ------------------------------------------------------- #
_PIN_PAD_LEN = 64


def pad_pin(pin: str) -> bytes:
    """UTF-8 PIN padded with 0x00 to 64 bytes (CTAP minimum). 4..63 bytes."""
    raw = pin.encode("utf-8")
    if len(raw) < 4:
        raise ValueError("FIDO PIN must be at least 4 characters.")
    if len(raw) > _PIN_PAD_LEN - 1:
        raise ValueError("FIDO PIN must be at most 63 bytes.")
    return raw + b"\x00" * (_PIN_PAD_LEN - len(raw))


def pin_hash_left16(pin: str) -> bytes:
    """LEFT(SHA-256(PIN), 16) - the pinHash the authenticator checks."""
    return _sha256(pin.encode("utf-8"))[:16]


def pin_uv_authenticate(version: int, key: bytes, message: bytes) -> bytes:
    """The pinUvAuthParam MAC over ``message`` keyed by a pinUvAuthToken: protocol 1
    truncates the HMAC to 16 bytes, protocol 2 uses the full 32."""
    mac = _hmac256(key, message)
    return mac[:16] if version == 1 else mac
