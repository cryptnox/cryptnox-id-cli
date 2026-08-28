import gzip

from cryptnox_id_cli.applets.piv import objects as obj


def test_get_data_apdu_chuid():
    o = obj.object_by_name("chuid")
    assert o is not None
    assert obj.get_data_apdu(o.oid).to_bytes().hex().upper() == "00CB3FFF055C035FC10200"


def test_unwrap_strips_tag53():
    printed = obj.object_by_name("printed")
    assert printed is not None
    assert obj.unwrap(printed.oid, bytes.fromhex("5305AABBCCDDEE")).hex().upper() == "AABBCCDDEE"


def test_unwrap_discovery_passthrough():
    data = bytes.fromhex("7E034F0100")
    assert obj.unwrap(bytes([0x7E]), data) == data


def test_extract_certificate_plain():
    container = bytes.fromhex("7003AABBCC710100FE00")
    assert obj.extract_certificate(container).hex().upper() == "AABBCC"


def test_extract_certificate_gzip():
    der = b"hello-this-is-a-fake-der-cert"
    comp = gzip.compress(der)
    container = bytes([0x70, len(comp)]) + comp + bytes.fromhex("710101") + b"\xfe\x00"
    assert obj.extract_certificate(container) == der


def test_extract_certificate_absent():
    assert obj.extract_certificate(bytes.fromhex("FE00")) is None
