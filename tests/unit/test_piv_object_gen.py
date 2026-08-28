"""Tests for the CHUID / CCC / Discovery object generators."""

import pytest

from cryptnox_id_cli.crypto import piv_objects
from cryptnox_id_cli.util import tlv


def test_chuid_structure():
    data = piv_objects.generate_chuid(guid=bytes(16), expiration="20400101")
    nodes = tlv.parse(data)
    tags = {n.tag for n in nodes}
    assert {0x30, 0x34, 0x35, 0x3E, 0xFE} <= tags
    guid = tlv.find(nodes, 0x34)
    assert guid is not None and len(guid.value) == 16
    assert tlv.find(nodes, 0x35).value == b"20400101"


def test_chuid_rejects_bad_guid():
    with pytest.raises(ValueError):
        piv_objects.generate_chuid(guid=b"short")


def test_ccc_card_identifier_is_21_bytes():
    nodes = tlv.parse(piv_objects.generate_ccc())
    f0 = tlv.find(nodes, 0xF0)
    assert f0 is not None and len(f0.value) == 21


def test_discovery_has_aid_and_application_pin_policy():
    nodes = tlv.parse(piv_objects.generate_discovery())
    disc = tlv.find(nodes, 0x7E)
    assert disc is not None
    scope = disc.children if disc.children else nodes
    assert tlv.find(scope, 0x4F) is not None
    policy = tlv.find(scope, 0x5F2F)
    # Fixed to Application PIN, primary (0x40 0x10); Global PIN not supported (ADR-0001).
    assert policy is not None and policy.value == b"\x40\x10"
