"""Wire grammar and crypto for PIV management key (9B) authentication.

Every byte of the 9B exchange is fixed by the applet's case dispatch: it selects
GENERAL AUTHENTICATE case 4 or case 5 purely from which tags are present and whether
they carry data, so a stray tag or an off-by-one length silently becomes a different
command. These vectors pin the bytes the way test_perso.py pins GENERATE.
"""

from __future__ import annotations

import pytest

from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv import mgmt_auth as ma
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.util import tlv


def _hex(apdu) -> str:
    return apdu.to_bytes().hex().upper()


# --------------------------------------------------------------------- APDUs --
def test_witness_request_bytes():
    assert _hex(ma.witness_request_apdu(0x0C)) == "00870C9B047C02800000"
    assert _hex(ma.witness_request_apdu(0x08)) == "0087089B047C02800000"


def test_mutual_response_bytes():
    witness = bytes(range(16))
    challenge = bytes(range(16, 32))
    assert _hex(ma.mutual_response_apdu(0x0C, witness, challenge)) == (
        "00870C9B267C248010000102030405060708090A0B0C0D0E0F8110101112131415161718191A1B1C1D1E1F00"
    )


def test_clear_value_bytes():
    assert _hex(ma.clear_value_apdu(0x0C)) == "00240C9B029F00"


def test_set_value_bytes_per_mechanism():
    assert _hex(ma.set_value_apdu(0x0C, bytes(32))) == "00240C9B228020" + "00" * 32
    assert _hex(ma.set_value_apdu(0x08, bytes(16))) == "0024089B128010" + "00" * 16
    assert _hex(ma.set_value_apdu(0x0A, bytes(24))) == "00240A9B1A8018" + "00" * 24


def test_set_value_refuses_a_length_the_mechanism_cannot_hold():
    with pytest.raises(ma.MgmtKeyError, match="32-byte value"):
        ma.set_value_apdu(0x0C, bytes(16))


def test_set_value_refuses_a_non_aes_mechanism():
    with pytest.raises(ma.MgmtKeyError, match="not an AES mechanism"):
        ma.set_value_apdu(0x07, bytes(32))


# --------------------------------------------------------------------- crypto --
# FIPS-197 Appendix C vectors: the authentication is a single raw AES block.
_BLOCK = bytes.fromhex("00112233445566778899AABBCCDDEEFF")


def test_aes_ecb_single_block_matches_fips_197():
    key128 = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    key256 = bytes(range(32))
    assert ma.aes_ecb_encrypt(key128, _BLOCK).hex().upper() == "69C4E0D86A7B0430D8CDB78070B4C55A"
    assert ma.aes_ecb_encrypt(key256, _BLOCK).hex().upper() == "8EA2B7CA516745BFEAFC49904B496089"
    for key in (key128, key256):
        assert ma.aes_ecb_decrypt(key, ma.aes_ecb_encrypt(key, _BLOCK)) == _BLOCK


def test_aes_ecb_refuses_anything_but_one_block():
    with pytest.raises(ma.MgmtKeyError, match="16-byte block"):
        ma.aes_ecb_encrypt(bytes(16), bytes(15))


# -------------------------------------------------------------------- parsing --
def test_auth_field_reads_a_block_out_of_the_template():
    assert ma.auth_field(bytes.fromhex("7C128010" + "00" * 16), ma.TAG_WITNESS) == bytes(16)


@pytest.mark.parametrize(
    "response",
    [
        "8010" + "00" * 16,  # no 7C template at all
        "7C12" + "8110" + "00" * 16,  # 7C present, but the block is under tag 81
        "7C11" + "800F" + "00" * 15,  # 7C/80 present, 15 bytes where a block is due
    ],
)
def test_auth_field_rejects_every_other_shape(response):
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        ma.auth_field(bytes.fromhex(response), ma.TAG_WITNESS)
    assert excinfo.value.stage == "protocol"


# ------------------------------------------------------------------- material --
def test_mechanism_for_key_length():
    assert ma.mechanism_for_key_length(16) == 0x08
    assert ma.mechanism_for_key_length(24) == 0x0A
    assert ma.mechanism_for_key_length(32) == 0x0C
    assert ma.mechanism_for_key_length(15) is None


def test_probe_order_starts_with_what_the_material_can_serve():
    explicit_128 = ma.MgmtKeyMaterial("$PIV_MGMT_KEY", {0x08: bytes(16)})
    assert explicit_128.mechanisms() == (0x08, 0x0C, 0x0A)
    default = ma.MgmtKeyMaterial("--default-keys", {0x08: bytes(16), 0x0C: bytes(32)})
    assert default.mechanisms() == (0x0C, 0x08, 0x0A)


def test_key_for_a_mechanism_the_material_cannot_serve_points_at_the_env_var():
    default = ma.MgmtKeyMaterial("--default-keys", {0x08: bytes(16), 0x0C: bytes(32)})
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        default.key_for(0x0A)
    assert excinfo.value.stage == "key_length"
    assert "$PIV_MGMT_KEY" in str(excinfo.value)
    assert "48 hex characters" in str(excinfo.value)


def test_key_for_names_both_lengths_when_an_explicit_value_does_not_fit():
    material = ma.MgmtKeyMaterial("$PIV_MGMT_KEY", {0x0C: bytes(32)})
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        material.key_for(0x08)
    assert excinfo.value.stage == "key_length"
    assert "16-byte" in str(excinfo.value) and "32 bytes" in str(excinfo.value)


def test_error_serialises_stage_and_status_word():
    err = ma.MgmtKeyError("nope", stage="empty", sw=0x6983)
    assert err.to_dict() == {
        "error": "mgmt_key",
        "message": "nope",
        "stage": "empty",
        "sw": "6983",
    }
    assert ma.MgmtKeyError("nope", stage="protocol").to_dict()["sw"] is None


# ---------------------------------------------------------------- agreements --
def test_mechanism_tables_agree_with_the_rest_of_the_applet_code():
    # The detector gates on RSA; _RSA_MODULUS_LEN is keyimport's private table of the
    # same mechanisms. Reading it deliberately: two copies that drift are the bug.
    assert set(keyimport._RSA_MODULUS_LEN) == perso_mod.RSA_MECHANISMS
    assert set(ma.AES_MECHANISMS) == {0x08, 0x0A, 0x0C}
    assert set(ma.MECHANISM_PROBE_ORDER) == set(ma.AES_MECHANISMS)


def test_mechanism_name_uses_the_applet_algorithm_table():
    assert ma.mechanism_name(0x0C) == "AES-256"
    assert ma.mechanism_name(0xFE) == "0xfe"


# -------------------------------------------------------------------- tlv.peek --
def test_peek_reads_a_declared_length_from_a_header_alone():
    assert tlv.peek(bytes.fromhex("7F49820109") + bytes(251)) == (0x7F49, 265, 5)
    assert tlv.peek(bytes.fromhex("7F4981FF") + bytes(255)) == (0x7F49, 255, 4)
    assert tlv.peek(bytes.fromhex("8010") + bytes(16)) == (0x80, 16, 2)


def test_peek_returns_none_on_an_unreadable_header():
    assert tlv.peek(bytes.fromhex("7F498201")) is None  # cut inside the length field
    assert tlv.peek(b"") is None
