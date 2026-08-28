"""Golden tests: secrets must never survive into a transcript."""

from cryptnox_id_cli.secrets.redaction import Redactor

PIN_HEX = "313233343536"  # ASCII "123456"


def test_verify_pin_data_is_redacted():
    # 00 20 00 80 Lc=08 <PIN padded with FF>
    apdu = bytes.fromhex("0020008008313233343536FFFF")
    out = Redactor().redact_command(apdu)
    assert PIN_HEX not in out
    assert "REDACTED" in out
    assert out.startswith("00200080")


def test_change_reference_data_redacted():
    apdu = bytes.fromhex("00240080" + "08" + "313233343536FFFF")
    assert PIN_HEX not in Redactor().redact_command(apdu)


def test_ctap_clientpin_redacted_but_getinfo_not():
    r = Redactor()
    client_pin = bytes.fromhex("801000000406AABBCC00")  # cmd byte 0x06 = clientPIN
    get_info = bytes.fromhex("80100000010400")  # cmd byte 0x04 = getInfo
    assert "AABBCC" not in r.redact_command(client_pin)
    assert r.redact_command(get_info) == "80100000010400"


def test_registered_secret_masked_everywhere():
    r = Redactor()
    r.register(b"123456")
    assert PIN_HEX not in r.mask("AA" + PIN_HEX + "BB")


def test_non_sensitive_command_untouched():
    select = "00A404000BA00000030800001000010000"
    assert Redactor().redact_command(bytes.fromhex(select)) == select


def test_put_key_data_masked_without_registration():
    # GlobalPlatform PUT KEY (INS 0xD8) carrying 16 bytes of key material, never registered.
    key = "AB" * 16
    apdu = bytes.fromhex("80D88101" + "10" + key)
    out = Redactor().redact_command(apdu)
    assert key not in out
    assert "REDACTED" in out
    assert out.startswith("80D88101")


def test_desfire_changekey_data_masked_without_registration():
    # ISO-wrapped DESFire ChangeKey (90 C4 ...) carrying key material + a trailing Le.
    key = "CD" * 16
    apdu = bytes.fromhex("90C40000" + "10" + key + "00")
    out = Redactor().redact_command(apdu)
    assert key not in out
    assert "REDACTED" in out


def test_mask_ignores_odd_nibble_offset_near_match():
    # Safety review 2026-08-21: registered bytes 12 34 must NOT match inside
    # A1 23 4F ("A1234F" contains "1234" at odd offset 1) - replacing there would
    # garble the surrounding nibbles of unrelated bytes.
    r = Redactor()
    r.register(bytes.fromhex("1234"))
    assert r.mask("A1234F") == "A1234F"


def test_mask_replaces_byte_aligned_occurrence():
    r = Redactor()
    r.register(bytes.fromhex("1234"))
    assert r.mask("AA1234BB") == "AA<REDACTED:2B>BB"


def test_mask_does_not_rewrite_an_inserted_marker():
    # "EDAC" is valid hex and appears inside "<REDACTED:...>"; masking a second
    # secret must skip markers already inserted for the first.
    r = Redactor()
    r.register(b"123456")
    r.register(bytes.fromhex("EDAC"))
    assert r.mask(PIN_HEX) == "<REDACTED:6B>"


def test_response_data_masked_for_general_authenticate_ins():
    # GENERAL AUTHENTICATE (INS 0x87) responses can carry key material (e.g. an
    # ECDH shared secret) that was never registered - masked by INS alone.
    r = Redactor()
    z = bytes.fromhex("CAFEBABE" * 4)
    assert r.redact_response_data(z, ins=0x87) == "<REDACTED:16B>"
    assert r.redact_response(z, 0x90, 0x00, ins=0x87) == "<REDACTED:16B>9000"


def test_response_data_untouched_for_non_sensitive_ins():
    r = Redactor()
    assert r.redact_response_data(bytes.fromhex("ABCD"), ins=0xCA) == "ABCD"
    assert r.redact_response(bytes.fromhex("ABCD"), 0x90, 0x00, ins=0xCA) == "ABCD9000"


def test_chained_change_reference_data_masked():
    # Key-import frames: ISO-chained (CLA 0x10) and SCP03-wrapped chained (CLA 0x94)
    # CHANGE REFERENCE DATA stays masked regardless of the CLA bits.
    component = "DE" * 8
    for cla in ("10", "94"):
        apdu = bytes.fromhex(cla + "24079C" + "08" + component)
        out = Redactor().redact_command(apdu)
        assert component not in out
        assert "REDACTED" in out
