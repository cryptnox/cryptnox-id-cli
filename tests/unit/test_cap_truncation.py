"""The two response-layer behaviours, exercised through the real transport.

test_generate_truncation.py pins the rule against hand-built responses. This one puts
a model of the card's response layer behind a real ``CardSession`` and sends the real
``generate_keypair_apdu``, so the 61xx reassembly loop, the shipped APDU builder and
the detector are all in the loop together.

Limits, stated so nobody reads more into a pass: there is no secure-channel crypto
here, no key-object authorization, no GENERAL AUTHENTICATE, and therefore no evidence
that the plain path is *permitted* on any card - only that response framing behaves as
modelled. Response-MAC framing is deliberately not modelled; the CLI never asks for it.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.transport.pcsc import CardSession
from cryptnox_id_cli.util import tlv

RSA2048 = 0x07
ECCP256 = 0x11
MAX_RAPDU = 256


class VirtualApplet:
    """A RawConnection that answers GENERATE with a fixed template.

    ``chaining`` is the plain response path (and any card whose secured path chains):
    it hands out at most 256 bytes at a time and says 61xx while bytes remain.
    ``truncating`` is the secured path of a card that does not chain: it sends the
    first 256 bytes, reports success, and drops the rest.
    """

    def __init__(self, template: bytes, *, chaining: bool) -> None:
        self.template = template
        self.chaining = chaining
        self.pending = b""
        self.transcript: list[str] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        raw = bytes(apdu)
        self.transcript.append(raw.hex().upper())
        if raw[1] == 0xC0:  # GET RESPONSE
            return self._serve(self.pending)
        if raw[1] == perso_mod.INS_GENERATE_ASYMMETRIC:
            if not self.chaining:
                return list(self.template[:MAX_RAPDU]), 0x90, 0x00
            return self._serve(self.template)
        return [], 0x6A, 0x82

    def _serve(self, remaining: bytes) -> tuple[list[int], int, int]:
        chunk, self.pending = remaining[:MAX_RAPDU], remaining[MAX_RAPDU:]
        if self.pending:
            return list(chunk), 0x61, len(self.pending) & 0xFF
        return list(chunk), 0x90, 0x00

    def get_atr(self) -> bytes:
        return bytes.fromhex("3BFA1300008131FE454A434F5033")

    def disconnect(self) -> None:
        pass


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_template(rsa_key) -> bytes:
    numbers = rsa_key.public_key().public_numbers()
    body = tlv.build(perso_mod.TAG_RSA_MODULUS, numbers.n.to_bytes(256, "big")) + tlv.build(
        perso_mod.TAG_RSA_EXPONENT, numbers.e.to_bytes(3, "big")
    )
    return tlv.build(perso_mod.TAG_PUBKEY_TEMPLATE, body)


@pytest.fixture(scope="module")
def ecc_template() -> bytes:
    point = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    )
    return tlv.build(perso_mod.TAG_PUBKEY_TEMPLATE, tlv.build(perso_mod.TAG_ECC_POINT, point))


def _generate(template: bytes, *, chaining: bool, slot: int, mech: int):
    applet = VirtualApplet(template, chaining=chaining)
    session = CardSession(applet)
    return applet, session.transmit(perso_mod.generate_keypair_apdu(slot, mech))


def test_a_chaining_card_delivers_the_whole_template(rsa_template, rsa_key):
    applet, resp = _generate(rsa_template, chaining=True, slot=0x9A, mech=RSA2048)
    assert len(resp.data) == 270 and resp.ok
    assert applet.transcript.count("00C000000E") == 1
    assert perso_mod.generate_response_truncated(RSA2048, resp) is False
    parsed = perso_mod.parse_public_key(RSA2048, resp.data)
    assert parsed.public_numbers() == rsa_key.public_key().public_numbers()


def test_a_truncating_card_looks_successful_and_is_not(rsa_template):
    applet, resp = _generate(rsa_template, chaining=False, slot=0x9A, mech=RSA2048)
    assert (len(resp.data), resp.sw) == (256, 0x9000)
    assert not any(cmd.startswith("00C000") for cmd in applet.transcript), (
        "no 61xx was reported, so the transport had nothing to drain - the whole problem"
    )
    assert perso_mod.generate_response_truncated(RSA2048, resp) is True
    # This is the failure the fallback exists to prevent.
    with pytest.raises(ValueError, match="extends beyond buffer"):
        perso_mod.parse_public_key(RSA2048, resp.data)


@pytest.mark.parametrize("chaining", [True, False])
def test_ecc_is_unaffected_on_either_response_path(ecc_template, chaining):
    _, resp = _generate(ecc_template, chaining=chaining, slot=0x9A, mech=ECCP256)
    assert resp.ok and len(resp.data) == 70
    assert perso_mod.generate_response_truncated(ECCP256, resp) is False
    assert perso_mod.parse_public_key(ECCP256, resp.data).curve.name == "secp256r1"
