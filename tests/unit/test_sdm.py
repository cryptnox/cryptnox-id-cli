"""DESFire EV3 SDM / SUN host-side verification crypto (per NXP AN12196).

These check our helpers against an independent re-derivation of the documented scheme;
the live card remains the final arbiter (see the SDM round-trip in the field notes).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from cryptnox_id_cli.applets.mifare import ev2

META_KEY = bytes(range(16))
FILE_KEY = bytes(range(16, 32))
UID = bytes.fromhex("04AABBCCDDEE11")
CTR = 0x010203  # little-endian 03 02 01


def _cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def test_sdm_decrypt_picc_roundtrip():
    # EncryptedPICCData block: PICCDataTag, 7-byte UID, 3-byte LE counter, zero-pad to 16.
    plain = bytes([0xC7]) + UID + CTR.to_bytes(3, "little") + bytes(5)
    enc = _aes_cbc_encrypt(META_KEY, bytes(16), plain)
    uid, ctr = ev2.sdm_decrypt_picc(META_KEY, enc)
    assert uid == UID
    assert ctr == CTR


def test_sdm_file_read_mac_empty_input():
    sv = bytes.fromhex("3CC300010080") + UID + CTR.to_bytes(3, "little")
    session_key = _cmac(FILE_KEY, sv)
    full = _cmac(session_key, b"")
    expected = bytes(full[i] for i in range(16) if i % 2 == 1)  # odd-indexed bytes -> 8 bytes
    assert len(expected) == 8
    assert ev2.sdm_file_read_mac(FILE_KEY, UID, CTR, b"") == expected


def test_sdm_file_read_mac_with_input():
    mac_input = b"file-bytes-under-mac"
    sv = bytes.fromhex("3CC300010080") + UID + CTR.to_bytes(3, "little")
    session_key = _cmac(FILE_KEY, sv)
    expected = bytes(_cmac(session_key, mac_input)[i] for i in range(16) if i % 2 == 1)
    assert ev2.sdm_file_read_mac(FILE_KEY, UID, CTR, mac_input) == expected
