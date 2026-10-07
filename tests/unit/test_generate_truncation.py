"""The rule that decides a GENERATE response was cut short.

Getting this wrong in either direction is expensive: a false positive sends a working
card down a fallback that needs a key value it may not have, and a false negative is
the original failure (a partial template parsed as if complete). The rule therefore
reads only the card's own response - mechanism, status word, length, and the total the
template's own header declares - and every clause is pinned here.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.util import tlv

RSA2048 = 0x07
ECCP256 = 0x11


@pytest.fixture(scope="module")
def rsa_template() -> bytes:
    """A real 270-byte 7F49 template, as the applet builds it for RSA-2048."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    body = tlv.build(perso_mod.TAG_RSA_MODULUS, numbers.n.to_bytes(256, "big")) + tlv.build(
        perso_mod.TAG_RSA_EXPONENT, numbers.e.to_bytes(3, "big")
    )
    template = tlv.build(perso_mod.TAG_PUBKEY_TEMPLATE, body)
    assert len(template) == 270
    return template


@pytest.fixture(scope="module")
def ecc_template() -> bytes:
    point = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    )
    template = tlv.build(perso_mod.TAG_PUBKEY_TEMPLATE, tlv.build(perso_mod.TAG_ECC_POINT, point))
    assert len(template) == 70
    return template


def _resp(data: bytes, sw: int = 0x9000) -> Response:
    return Response(data, sw >> 8, sw & 0xFF)


def test_a_complete_template_is_not_truncated(rsa_template):
    assert perso_mod.generate_response_truncated(RSA2048, _resp(rsa_template)) is False
    assert perso_mod.parse_public_key(RSA2048, rsa_template).key_size == 2048


def test_a_256_byte_prefix_of_a_270_byte_template_is_truncated(rsa_template):
    cut = rsa_template[:256]
    assert perso_mod.generate_response_truncated(RSA2048, _resp(cut)) is True
    assert perso_mod.declared_template_bytes(cut) == 270


@pytest.mark.parametrize("sw", [0x6A80, 0x6F00, 0x6982])
def test_a_failed_response_is_never_truncation(rsa_template, sw):
    assert perso_mod.generate_response_truncated(RSA2048, _resp(rsa_template[:256], sw)) is False


def test_ecc_never_triggers_the_rule(ecc_template):
    # Even padded to exactly the cut length - the mechanism clause settles it, and an
    # ECC template is far too small to reach 256 bytes on any card.
    padded = ecc_template + bytes(256 - len(ecc_template))
    assert perso_mod.generate_response_truncated(ECCP256, _resp(padded)) is False
    assert perso_mod.generate_response_truncated(ECCP256, _resp(ecc_template)) is False


def test_a_response_that_is_not_a_public_key_template_is_not_truncation():
    assert perso_mod.generate_response_truncated(RSA2048, _resp(bytes(256))) is False
    assert perso_mod.declared_template_bytes(bytes(256)) is None


def test_a_header_declaring_exactly_the_received_length_is_not_truncation():
    # 7F49 82 00 FB + 251 bytes = 256 total: complete, and the comparison is strict.
    body = bytes.fromhex("7F498200FB") + bytes(251)
    assert len(body) == 256
    assert perso_mod.declared_template_bytes(body) == 256
    assert perso_mod.generate_response_truncated(RSA2048, _resp(body)) is False


@pytest.mark.parametrize("length", [255, 257])
def test_only_a_cut_at_the_requested_length_counts(rsa_template, length):
    assert perso_mod.generate_response_truncated(RSA2048, _resp(rsa_template[:length])) is False
