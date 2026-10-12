"""The 9B mutual-authentication driver against a loop-back card.

The applet decides in a fixed order - does the (key reference, mechanism) pair exist,
is it accessible on this interface, does it hold a value, does its role and attribute
bitmap permit this flow - and each answer is a different status word. The CLI's whole
diagnostic value on this path is turning those into a sentence naming the fix, so the
fake card below reproduces that ordering exactly and every branch is exercised.

Mirrors the loop-back style of test_scp02.py: an independent inline model of the card
side, driven through the real driver with an injected host challenge.
"""

from __future__ import annotations

import pytest

from cryptnox_id_cli.applets.piv import mgmt_auth as ma
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import StatusWordError
from cryptnox_id_cli.util import tlv

ATTR_PERMIT_EXTERNAL = 0x04
ATTR_PERMIT_MUTUAL = 0x08
ATTR_IMPORTABLE = 0x10

WITNESS = bytes.fromhex("A7E57B882467107902739D50387B3651")
CHALLENGE = bytes(range(16, 32))
KEY256 = bytes(range(32))
KEY128 = bytes(range(16))


class FakeMgmtCard:
    """A 9B key object with the applet's precondition ordering, and nothing else."""

    def __init__(
        self,
        *,
        key: bytes = KEY256,
        mechanism: int = 0x0C,
        attributes: int = ATTR_IMPORTABLE | ATTR_PERMIT_MUTUAL,
        initialised: bool = True,
        accessible: bool = True,
        card_key: bytes | None = None,
    ) -> None:
        self.key = key
        #: what the card actually enciphers with; differs from ``key`` to model a card
        #: that answers 9000 but does not hold the host's value.
        self.card_key = card_key if card_key is not None else key
        self.mechanism = mechanism
        self.attributes = attributes
        self.initialised = initialised
        self.accessible = accessible
        self.commands: list[str] = []

    def transmit(self, apdu: APDU, *, context: str | None = None) -> Response:
        self.commands.append(apdu.to_bytes().hex().upper())
        if apdu.p2 != 0x9B or apdu.p1 != self.mechanism:
            return Response(b"", 0x6A, 0x86)
        if not self.accessible:
            return Response(b"", 0x69, 0x82)
        if not self.initialised:
            return Response(b"", 0x69, 0x83)
        nodes = tlv.parse(apdu.data)
        template = tlv.find(nodes, ma.TAG_DYNAMIC_AUTH)
        assert template is not None
        fields = {child.tag: child.value for child in template.children}
        if set(fields) == {ma.TAG_WITNESS} and not fields[ma.TAG_WITNESS]:
            return self._case4()
        if set(fields) == {ma.TAG_WITNESS, ma.TAG_CHALLENGE}:
            return self._case5(fields[ma.TAG_WITNESS], fields[ma.TAG_CHALLENGE])
        return Response(b"", 0x6A, 0x80)

    def _case4(self) -> Response:
        if not self.attributes & ATTR_PERMIT_MUTUAL:
            return Response(b"", 0x69, 0x85)
        body = tlv.build_constructed(
            ma.TAG_DYNAMIC_AUTH,
            tlv.build(ma.TAG_WITNESS, ma.aes_ecb_encrypt(self.card_key, WITNESS)),
        )
        return Response(body, 0x90, 0x00)

    def _case5(self, witness: bytes, challenge: bytes) -> Response:
        if witness != WITNESS:
            return Response(b"", 0x69, 0x82)
        body = tlv.build_constructed(
            ma.TAG_DYNAMIC_AUTH,
            tlv.build(ma.TAG_RESPONSE, ma.aes_ecb_encrypt(self.card_key, challenge)),
        )
        return Response(body, 0x90, 0x00)


def _material(source: str = "$PIV_MGMT_KEY", **keys: bytes) -> ma.MgmtKeyMaterial:
    return ma.MgmtKeyMaterial(source, {int(k[1:], 16): v for k, v in keys.items()})


DEFAULT_MATERIAL = ma.MgmtKeyMaterial("--default-keys", {0x08: KEY128, 0x0C: KEY256})


def _auth(card: FakeMgmtCard, material: ma.MgmtKeyMaterial, **kw):
    return ma.authenticate(card.transmit, material, challenge=CHALLENGE, **kw)


# --------------------------------------------------------------------- happy --
def test_mutual_authentication_sends_exactly_two_frames_back_to_back():
    card = FakeMgmtCard()
    auth = _auth(card, _material(m0C=KEY256))
    assert auth == ma.MgmtAuth(mechanism=0x0C, source="$PIV_MGMT_KEY")
    assert len(card.commands) == 2, "an extra command between the two halves resets the card"
    assert card.commands[0] == "00870C9B047C02800000"
    # The second frame must carry the deciphered witness the card is waiting for.
    assert WITNESS.hex().upper() in card.commands[1]
    assert CHALLENGE.hex().upper() in card.commands[1]


def test_a_card_whose_9b_is_aes_128_is_found_by_probing_past_6a86():
    card = FakeMgmtCard(key=KEY128, mechanism=0x08)
    auth = _auth(card, DEFAULT_MATERIAL)
    assert auth.mechanism == 0x08
    # AES-256 first (the built-in profiles' shape), rejected, then AES-128.
    assert len(card.commands) == 3
    assert card.commands[0].startswith("00870C9B")
    assert card.commands[1].startswith("0087089B")


# ------------------------------------------------------------ card-state rows --
def test_no_key_object_at_all_names_every_mechanism_probed():
    card = FakeMgmtCard(mechanism=0x99)  # matches no candidate
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _auth(card, DEFAULT_MATERIAL)
    assert excinfo.value.stage == "missing"
    assert excinfo.value.to_dict()["sw"] == "6A86"
    for name in ("AES-256", "AES-128", "AES-192"):
        assert name in str(excinfo.value)
    assert len(card.commands) == 3


def test_an_object_without_a_value_points_at_the_command_that_loads_one():
    card = FakeMgmtCard(initialised=False)
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _auth(card, _material(m0C=KEY256))
    assert excinfo.value.stage == "empty"
    assert excinfo.value.to_dict()["sw"] == "6983"
    assert "set-mgmt-key" in str(excinfo.value)
    assert len(card.commands) == 1, "no case 5 may follow a refused witness request"


def test_an_object_permitting_only_external_authentication_is_reported_as_unusable():
    card = FakeMgmtCard(attributes=ATTR_IMPORTABLE | ATTR_PERMIT_EXTERNAL)
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _auth(card, _material(m0C=KEY256))
    assert excinfo.value.stage == "unusable"
    assert "PERMIT_MUTUAL" in str(excinfo.value)


@pytest.mark.parametrize(
    ("contactless", "fragment"),
    [(True, "contactless (PICC) interface"), (False, "use the contact reader")],
)
def test_access_refusal_shapes_its_advice_around_the_interface(contactless, fragment):
    card = FakeMgmtCard(accessible=False)
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _auth(card, _material(m0C=KEY256), contactless=contactless)
    assert excinfo.value.stage == "access"
    assert fragment in str(excinfo.value)


def test_an_unexpected_status_word_falls_through_to_the_status_word_error():
    card = FakeMgmtCard()
    card.transmit = lambda apdu, **kw: Response(b"", 0x6F, 0x00)  # type: ignore[method-assign]
    with pytest.raises(StatusWordError, match="9B witness request"):
        _auth(card, _material(m0C=KEY256))


# --------------------------------------------------------------- key mismatch --
def test_the_wrong_host_key_is_reported_as_a_key_mismatch():
    card = FakeMgmtCard(key=KEY256)
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _auth(card, _material(m0C=bytes(32)))
    assert excinfo.value.stage == "key_mismatch"
    assert "$PIV_MGMT_KEY" in str(excinfo.value)


def test_a_card_that_accepts_the_witness_but_answers_wrongly_fails_verification():
    # The card takes the host's witness (so it knows the key the host used) but
    # enciphers the challenge under a different one: only the host's check catches it.
    card = FakeMgmtCard(key=KEY256)
    card._case5 = lambda witness, challenge: Response(  # type: ignore[method-assign]
        tlv.build_constructed(
            ma.TAG_DYNAMIC_AUTH,
            tlv.build(ma.TAG_RESPONSE, ma.aes_ecb_encrypt(bytes(32), bytes(16))),
        ),
        0x90,
        0x00,
    )
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _auth(card, _material(m0C=KEY256))
    assert excinfo.value.stage == "card_verify"


def test_a_value_of_the_wrong_length_is_caught_before_any_crypto_runs():
    card = FakeMgmtCard(key=KEY128, mechanism=0x08)
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _auth(card, _material(m0C=KEY256))
    assert excinfo.value.stage == "key_length"
    assert "16-byte" in str(excinfo.value) and "32 bytes" in str(excinfo.value)
    assert len(card.commands) == 2, "probe found AES-128 at the second try; no case 5 followed"


# --------------------------------------------------------------------- probe --
def test_probe_reports_the_card_state_without_completing_the_exchange():
    assert ma.probe(FakeMgmtCard(mechanism=0x99).transmit, ma.MECHANISM_PROBE_ORDER) == (
        ma.MgmtKeyProbe(mechanism=None, sw=0x6A86, witness=None)
    )
    empty = ma.probe(FakeMgmtCard(initialised=False).transmit, ma.MECHANISM_PROBE_ORDER)
    assert (empty.mechanism, empty.sw, empty.witness) == (0x0C, 0x6983, None)
    ready = ma.probe(FakeMgmtCard().transmit, ma.MECHANISM_PROBE_ORDER)
    assert (ready.mechanism, ready.sw) == (0x0C, 0x9000)
    assert ready.witness == ma.aes_ecb_encrypt(KEY256, WITNESS)
