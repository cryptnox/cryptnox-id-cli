from cryptnox_id_cli.applets.piv.apt import parse_apt
from cryptnox_id_cli.util import tlv

APT = bytes.fromhex(
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F50"
    "49687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369"
    "616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)


def test_simple_tlv():
    [node] = tlv.parse(bytes.fromhex("5305AABBCCDDEE"))
    assert node.tag == 0x53
    assert node.value.hex().upper() == "AABBCCDDEE"


def test_multibyte_tag():
    [node] = tlv.parse(bytes.fromhex("5FC10101AA"))
    assert node.tag == 0x5FC101
    assert node.value == b"\xaa"


def test_constructed_recursion_and_find():
    nodes = tlv.parse(bytes.fromhex("7E054F03A00000"))
    disc = tlv.find(nodes, 0x7E)
    assert disc is not None and disc.constructed
    aid = tlv.find(nodes, 0x4F)
    assert aid is not None and aid.value.hex().upper() == "A00000"


def test_parse_apt():
    info = parse_apt(APT)
    assert info.aid_hex == "A000000308000010000100"
    assert info.label == "OpenFIPS201"
    assert info.url is not None and info.url.endswith("800-73-4.pdf")
