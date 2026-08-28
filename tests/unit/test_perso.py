"""Perso grammar tests (GENERATE request, PIN padding, CHANGE REF DATA, PUT DATA)."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.applets.piv import perso
from cryptnox_id_cli.util import tlv


def test_generate_request_apdu():
    # 00 47 00 9A Lc=05 AC 03 80 01 11 Le=00
    assert (
        perso.generate_keypair_apdu(0x9A, 0x11).to_bytes().hex().upper() == "0047009A05AC0380011100"
    )


def test_pad_pin():
    assert perso.pad_pin(b"123456") == bytes.fromhex("313233343536FFFF")
    with pytest.raises(ValueError):
        perso.pad_pin(b"123456789")


def test_set_verifier_value_apdu():
    apdu = perso.set_verifier_value_apdu(0x80, perso.pad_pin(b"123456"))
    assert apdu.to_bytes().hex().upper() == "0024FF8008313233343536FFFF"


def test_parse_public_key_ec_roundtrip():
    priv = ec.generate_private_key(ec.SECP256R1())
    point = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    response = tlv.build_constructed(0x7F49, tlv.build(0x86, point))
    parsed = perso.parse_public_key(0x11, response)
    assert parsed.public_numbers() == priv.public_key().public_numbers()


def test_put_data_apdu():
    apdu = perso.put_data_apdu(bytes.fromhex("5FC102"), bytes.fromhex("AABB"))
    assert apdu.to_bytes().hex().upper() == "00DB3FFF095C035FC1025302AABB"


def test_put_data_discovery_is_bare_no_tag_list_no_53():
    """SP 800-73-4: the Discovery Object travels as the bare 7E TLV. Regression for the
    53-wrapper defect - the generic 5C+53 form made the applet store and echo the
    wrapper, and a 53-wrapped Discovery Object is rejected by the Windows inbox PIV
    minidriver (worse than absent, since the object is optional)."""
    discovery = bytes.fromhex("7E124F0BA0000003080000100001005F2F024010")
    apdu = perso.put_data_apdu(bytes([0x7E]), discovery)
    assert apdu.to_bytes().hex().upper() == "00DB3FFF14" + discovery.hex().upper()
    # No 5C tag list, no 53 wrapper anywhere in the CDATA.
    assert not perso.put_data_body(bytes([0x7E]), discovery).startswith(bytes([0x5C]))


def test_put_data_non_discovery_objects_keep_the_53_wrapper():
    # 7E is the exception, not a new rule: CHUID and friends still get 5C + 53.
    body = perso.put_data_body(bytes.fromhex("5FC107"), b"\x01")
    assert body.hex().upper() == "5C035FC107530101"
