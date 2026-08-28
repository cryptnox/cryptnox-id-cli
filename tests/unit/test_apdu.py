from cryptnox_id_cli.transport.apdu import APDU, Response


def test_case1_no_data_no_le():
    assert APDU(0x00, 0x20, 0x00, 0x80).to_bytes().hex().upper() == "00200080"


def test_case2_short_le_256():
    assert APDU(0x80, 0xCA, 0x9F, 0x7F, le=256).to_bytes().hex().upper() == "80CA9F7F00"


def test_case4_short_select():
    aid = bytes.fromhex("A000000308000010000100")
    apdu = APDU(0x00, 0xA4, 0x04, 0x00, data=aid, le=256)
    assert apdu.to_bytes().hex().upper() == "00A404000B" + aid.hex().upper() + "00"


def test_extended_length_command():
    data = bytes(300)
    raw = APDU(0x00, 0xDB, 0x3F, 0xFF, data=data, le=256).to_bytes()
    # 4-byte header, 0x00 marker, 2-byte Lc, data, 2-byte Le
    assert raw[4] == 0x00
    assert raw[5:7] == (300).to_bytes(2, "big")
    assert len(raw) == 4 + 3 + 300 + 2


def test_response_helpers():
    r = Response(b"\xab\xcd", 0x90, 0x00)
    assert r.ok and r.sw == 0x9000 and r.sw_hex() == "9000" and r.data_hex() == "ABCD"
    assert not Response(b"", 0x6A, 0x82).ok
