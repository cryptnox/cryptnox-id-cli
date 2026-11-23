"""Key sheets: delivery to the client, owner values to the service, the file on disk."""

import json

import pytest
from cryptography.hazmat.primitives import serialization

from cryptnox_id_cli.remote import keysheet

# Made by the service's reference implementation, so the two stay compatible.
# The private key is a throwaway generated for this test.
REFERENCE_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBflxbXCmMWe1AogG
DbyUGJEkohExJLeNZMR71tkpBDWhRANCAARfW1w4xVN+Tjo+8C3FzjvD6Pogpv86
rAN72FNM7lXDWALCkT+tt3Hti/brJnS6V9n76oZOydKNqJ5XAYGyZD9d
-----END PRIVATE KEY-----
"""
REFERENCE_BLOB = bytes.fromhex(
    "046ba56dab60083628076df07759f4ca742f9020863ab04c2c45e8a8446df05532975d40152cd68c76157662"
    "283f6df2e642f91193de266c67bd95ebf015eb3c6f61cd5ef710cbda0336d81a51b6f1d500c468401bd6e93c"
    "1621df0baac5662a3c20cf14e2cbac9959c2ed965286a422e40e861f7b6ea80fc5d6a409f2714698df24d616"
    "323c47df526cf7f4760e22c923fb2bd6a6457dc87db6af91b81764532fe1cf0c222947dfe0f9d4a63f08fd72"
    "560c8b67704f98e68c4abde309341d7b9fd8772ee803420af30d95da2c1867b695ddf3a9071a6172284f3000"
    "594e5ea2c28da606fa6485bc28c042493a1756d8e02dd69fc25cc6c24b402687a4b610a8b9aab8a1054097a9"
    "cea7bdca4f0a92ce71fb62e00090edc8532f09358d428ac52787f0f34b7108a0ad2e20"
)
REFERENCE_FILE = bytes.fromhex(
    "434e584b5331dca12e3c6f62b3dc0a4bb5c2acd2aca07406ad3b306119b18796ca75ee4a3e035d2af4568b43"
    "3a02db7c6f20a233cf8d50fa1223a4d854be6cb8bf9ce0b04cd780901a9e20e8814ce8e237004856d48e688a"
    "c6a5433bb8ce92cc185245b607f7361de15baabc743a39a9ca81ad5b105db469bc92f942379eb97f8fffd728"
    "c348e600e4bca543b547a25b076123ad9b87b0451bb83f73d0e92c5fec61656a13710a819c7d90b7438127f4"
    "4a12808840f8bdf393d71138df5d360b86f7dfd044d7bb2f35203338aeba89ce6ff69acfea14f8f136d76cdb"
    "6278e1c983e76679c628d6d7f48d1a69ab316a3b90b66801390b55680fc3101e6f11d229"
)
REFERENCE_PASSPHRASE = "correct horse"
REFERENCE_SHEET = {
    "v": 1,
    "op": "consumer-lock",
    "scp": "SCP03",
    "ssd_kvn1": "00112233445566778899AABBCCDDEEFF",
    "mgmt_key_9b": {"AES128": "0F0E0D0C0B0A09080706050403020100"},
    "kcv": {"ssd_kvn1": "3544E0", "mgmt_key_9b_aes128": "C1CCDA"},
}


def reference_private_key():
    return serialization.load_pem_private_key(REFERENCE_PRIVATE_KEY, password=None)


def test_a_sheet_made_by_the_reference_service_decrypts():
    sheet = keysheet.decrypt(
        reference_private_key(), REFERENCE_BLOB, context=keysheet.KEY_SHEET_CONTEXT
    )
    assert sheet == REFERENCE_SHEET


def test_a_file_written_by_the_reference_library_opens():
    assert keysheet.open_file(REFERENCE_FILE, REFERENCE_PASSPHRASE) == REFERENCE_SHEET


def test_delivery_round_trip_to_a_fresh_key():
    receiver = keysheet.generate_kex()
    payload = {"ssd_kvn1": "AA" * 16}
    blob = keysheet.encrypt_to(
        keysheet.public_bytes(receiver), payload, context=keysheet.PROVIDED_CONTEXT
    )
    assert keysheet.decrypt(receiver, blob, context=keysheet.PROVIDED_CONTEXT) == payload


def test_only_the_intended_key_decrypts():
    blob = keysheet.encrypt_to(
        keysheet.public_bytes(keysheet.generate_kex()), {"a": 1}, context=b"ctx"
    )
    with pytest.raises(keysheet.KeySheetError, match="does not decrypt"):
        keysheet.decrypt(keysheet.generate_kex(), blob, context=b"ctx")


def test_the_context_is_bound():
    receiver = keysheet.generate_kex()
    blob = keysheet.encrypt_to(
        keysheet.public_bytes(receiver), {"a": 1}, context=keysheet.PROVIDED_CONTEXT
    )
    with pytest.raises(keysheet.KeySheetError, match="does not decrypt"):
        keysheet.decrypt(receiver, blob, context=keysheet.KEY_SHEET_CONTEXT)


@pytest.mark.parametrize("offset", [0, 1, 70, -1])
def test_a_changed_byte_is_refused(offset):
    blob = bytearray(REFERENCE_BLOB)
    blob[offset] ^= 0x01
    with pytest.raises(keysheet.KeySheetError):
        keysheet.decrypt(reference_private_key(), bytes(blob), context=keysheet.KEY_SHEET_CONTEXT)


def test_a_short_blob_is_refused():
    with pytest.raises(keysheet.KeySheetError, match="too short"):
        keysheet.decrypt(keysheet.generate_kex(), bytes(92), context=b"ctx")


@pytest.mark.parametrize(
    "raw", [b"", bytes(65), b"\x04" + bytes(64), b"\x02" + bytes(32)], ids=lambda r: str(len(r))
)
def test_a_public_key_that_is_not_a_p256_point_is_refused(raw):
    with pytest.raises(keysheet.KeySheetError):
        keysheet.encrypt_to(raw, {"a": 1}, context=b"ctx")


def test_bad_base64_is_refused_with_its_name():
    with pytest.raises(keysheet.KeySheetError, match="key sheet is not valid base64"):
        keysheet.b64decode("not base64!", "key sheet")


def test_file_round_trip_and_wrong_passphrase():
    raw = keysheet.seal_file(REFERENCE_SHEET, "pass")
    assert raw.startswith(keysheet.FILE_MAGIC)
    assert keysheet.open_file(raw, "pass") == REFERENCE_SHEET
    with pytest.raises(keysheet.KeySheetError, match="wrong passphrase"):
        keysheet.open_file(raw, "other")


def test_file_never_holds_the_keys_in_clear():
    raw = keysheet.seal_file(REFERENCE_SHEET, "pass")
    assert REFERENCE_SHEET["ssd_kvn1"].encode() not in raw
    assert bytes.fromhex(REFERENCE_SHEET["ssd_kvn1"]) not in raw


@pytest.mark.parametrize(
    ("raw", "message"),
    [(b"PK\x03\x04" + bytes(60), "not a Cryptnox key sheet"), (b"CNXKS1" + bytes(20), "truncated")],
)
def test_other_files_are_refused(raw, message):
    with pytest.raises(keysheet.KeySheetError, match=message):
        keysheet.open_file(raw, "pass")


def test_an_empty_passphrase_is_refused():
    with pytest.raises(keysheet.KeySheetError, match="passphrase"):
        keysheet.seal_file(REFERENCE_SHEET, "")


def test_kcv_of_the_public_default_key():
    # The value GlobalPlatform tooling prints for 404142...4F as an AES key.
    assert keysheet.kcv_aes(bytes.fromhex("404142434445464748494A4B4C4D4E4F")).hex() == "504a77"


def test_sheet_keys_in_a_fixed_order():
    assert keysheet.sheet_keys(REFERENCE_SHEET) == [
        ("ssd_kvn1", REFERENCE_SHEET["ssd_kvn1"]),
        ("mgmt_key_9b_aes128", REFERENCE_SHEET["mgmt_key_9b"]["AES128"]),
    ]
    assert keysheet.sheet_keys({"ssd_kvn1": None, "mgmt_key_9b": {}}) == []


def test_check_values_are_compared():
    assert keysheet.check_kcvs(REFERENCE_SHEET) is True
    altered = json.loads(json.dumps(REFERENCE_SHEET))
    altered["kcv"]["ssd_kvn1"] = "000000"
    assert keysheet.check_kcvs(altered) is False
    missing = json.loads(json.dumps(REFERENCE_SHEET))
    del missing["kcv"]["mgmt_key_9b_aes128"]
    assert keysheet.check_kcvs(missing) is False


def test_nothing_to_compare_is_none():
    assert keysheet.check_kcvs({"scp": "SCP03", "kcv": {}}) is None
    scp02 = dict(REFERENCE_SHEET, scp="SCP02")
    assert keysheet.check_kcvs(scp02) is None
