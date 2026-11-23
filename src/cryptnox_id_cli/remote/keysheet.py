"""Key sheets: the keys the consumer lock hands to the card's owner.

The receiver publishes an ephemeral P-256 public key; the sender agrees a
one-time AES-256-GCM key with it through ECDH and HKDF-SHA256 and sends ``its
ephemeral public key || nonce || ciphertext``. A TLS terminator that passes the
traffic through sees ciphertext only. Neither one-time key is signed, so one
that rewrites the traffic could substitute both and read the keys. The service
delivers the key sheet this way, and the client sends values the owner supplies
the same way in the other direction.

On disk a sheet is ``CNXKS1 || salt || nonce || AES-256-GCM``, under a key that
scrypt derives from a passphrase.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from collections.abc import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..applets.piv.ssd import kcv_aes
from ..transport.errors import CryptnoxError

KEY_SHEET_CONTEXT = b"cryptnox/consumer-lock/key-sheet/v1"
PROVIDED_CONTEXT = b"cryptnox/consumer-lock/provided/v1"
FILE_MAGIC = b"CNXKS1"

_PUB_LEN = 65
_NONCE_LEN = 12
_SALT_LEN = 16
_TAG_LEN = 16
_SCRYPT_N = 2**15


PrivateKey = ec.EllipticCurvePrivateKey


class KeySheetError(CryptnoxError):
    """A key sheet could not be decrypted, read or written."""

    code = "key_sheet"
    exit_code = 17


class KeySheetRunError(KeySheetError):
    """A consumer lock whose delivered keys are lost or failed a check.

    Carries the run's whole report, so ``--json`` still writes one document.
    """

    def __init__(self, message: str, *, report: Mapping[str, object]) -> None:
        super().__init__(message)
        self.report = dict(report)

    def to_dict(self) -> dict[str, object]:
        return {"error": self.code, "message": str(self), **self.report}


def generate_kex() -> ec.EllipticCurvePrivateKey:
    """A fresh ephemeral key pair; use it for one operation only."""
    return ec.generate_private_key(ec.SECP256R1())


def public_bytes(private: ec.EllipticCurvePrivateKey) -> bytes:
    """The uncompressed 65-byte point of ``private``'s public key."""
    return private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def public_from_bytes(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) != _PUB_LEN or raw[0] != 0x04:
        raise KeySheetError("the public key is not a 65-byte uncompressed P-256 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        raise KeySheetError("the public key is not a point on P-256") from None


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64decode(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise KeySheetError(f"the {what} is not valid base64") from None


def _derive(shared: bytes, context: bytes, sender_pub: bytes, receiver_pub: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context + sender_pub + receiver_pub,
    )
    return hkdf.derive(shared)


def encrypt_to(receiver_pub: bytes, payload: Mapping[str, object], *, context: bytes) -> bytes:
    """Encrypt ``payload`` as JSON so only the holder of ``receiver_pub`` can read it."""
    receiver = public_from_bytes(receiver_pub)
    sender = generate_kex()
    sender_pub = public_bytes(sender)
    key = _derive(sender.exchange(ec.ECDH(), receiver), context, sender_pub, receiver_pub)
    nonce = secrets.token_bytes(_NONCE_LEN)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return sender_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, context + sender_pub)


def decrypt(
    private: ec.EllipticCurvePrivateKey, blob: bytes, *, context: bytes
) -> dict[str, object]:
    """Open a blob sent to ``private``'s public key under ``context``."""
    if len(blob) < _PUB_LEN + _NONCE_LEN + _TAG_LEN:
        raise KeySheetError("the key sheet is too short to be one")
    sender_pub = blob[:_PUB_LEN]
    nonce = blob[_PUB_LEN : _PUB_LEN + _NONCE_LEN]
    ciphertext = blob[_PUB_LEN + _NONCE_LEN :]
    shared = private.exchange(ec.ECDH(), public_from_bytes(sender_pub))
    key = _derive(shared, context, sender_pub, public_bytes(private))
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, context + sender_pub)
    except InvalidTag:
        raise KeySheetError(
            "the key sheet does not decrypt: it was not made for this operation, or it "
            "was altered on the way"
        ) from None
    return _json_object(plaintext)


def _json_object(plaintext: bytes) -> dict[str, object]:
    try:
        obj = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise KeySheetError("the key sheet decrypted but holds no JSON") from None
    if not isinstance(obj, dict):
        raise KeySheetError("the key sheet decrypted but holds no JSON object")
    return obj


def _file_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=8, p=1).derive(passphrase.encode("utf-8"))


def seal_file(sheet: dict[str, object], passphrase: str) -> bytes:
    """The bytes of a passphrase-protected key sheet file."""
    if not passphrase:
        raise KeySheetError("a key sheet file needs a passphrase")
    salt = secrets.token_bytes(_SALT_LEN)
    nonce = secrets.token_bytes(_NONCE_LEN)
    plaintext = json.dumps(sheet, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(_file_key(passphrase, salt)).encrypt(nonce, plaintext, FILE_MAGIC)
    return FILE_MAGIC + salt + nonce + ciphertext


def open_file(raw: bytes, passphrase: str) -> dict[str, object]:
    """Read back what :func:`seal_file` wrote."""
    if not raw.startswith(FILE_MAGIC):
        raise KeySheetError("this is not a Cryptnox key sheet file")
    body = raw[len(FILE_MAGIC) :]
    if len(body) < _SALT_LEN + _NONCE_LEN + _TAG_LEN:
        raise KeySheetError("the key sheet file is truncated")
    salt, nonce = body[:_SALT_LEN], body[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
    try:
        plaintext = AESGCM(_file_key(passphrase, salt)).decrypt(
            nonce, body[_SALT_LEN + _NONCE_LEN :], FILE_MAGIC
        )
    except InvalidTag:
        raise KeySheetError(
            "the key sheet file does not decrypt: wrong passphrase, or the file is damaged"
        ) from None
    return _json_object(plaintext)


def sheet_keys(sheet: dict[str, object]) -> list[tuple[str, str]]:
    """The keys a sheet carries, as (name, hex value), in a fixed order."""
    keys: list[tuple[str, str]] = []
    kvn1 = sheet.get("ssd_kvn1")
    if isinstance(kvn1, str) and kvn1:
        keys.append(("ssd_kvn1", kvn1))
    mgmt = sheet.get("mgmt_key_9b")
    if isinstance(mgmt, dict):
        for mechanism in sorted(mgmt):
            value = mgmt[mechanism]
            if isinstance(value, str) and value:
                keys.append((f"mgmt_key_9b_{mechanism.lower()}", value))
    return keys


def check_kcvs(sheet: dict[str, object]) -> bool | None:
    """Whether every key in an SCP03 sheet matches the check value it came with.

    ``None`` when there is nothing to compare: no keys, no check values, or an
    SCP02 sheet, whose DES check values this client does not compute.
    """
    expected = sheet.get("kcv")
    keys = sheet_keys(sheet)
    if not keys or not isinstance(expected, dict) or sheet.get("scp") != "SCP03":
        return None
    for name, value in keys:
        want = expected.get(name)
        if not isinstance(want, str):
            return False
        try:
            if kcv_aes(bytes.fromhex(value)).hex().upper() != want.upper():
                return False
        except ValueError:
            return False
    return True
