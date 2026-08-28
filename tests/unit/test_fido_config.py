"""FIDO authenticatorConfig (0x0D): request shaping + pinUvAuthParam construction.

The pinUvAuthParam is a MAC over ``32×0xFF || 0x0D || subCommand || subCommandParams``
(the 0xFF prefix is mandated by CTAP 2.1, not a card quirk).
"""

import hashlib
import hmac as _hmac

import cbor2

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client
from cryptnox_id_cli.transport.pcsc import CardSession

TOKEN = bytes(range(32))


class FakeConfigCard:
    """Accepts any authenticatorConfig call and records the raw APDUs."""

    def __init__(self):
        self.sent: list[bytes] = []

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.sent.append(raw)
        if raw[1] == 0xA4:  # SELECT
            return list(b"FIDO_2_1"), 0x90, 0x00
        return [0x00], 0x90, 0x00  # CTAP status 0x00, empty body

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


def _last_req(card: FakeConfigCard) -> tuple[int, dict]:
    """(CTAP command byte, decoded CBOR request map) of the last non-SELECT APDU."""
    raw = card.sent[-1]
    lc = raw[4]
    payload = raw[5 : 5 + lc]
    return payload[0], cbor2.loads(payload[1:])


def _expect_param(token: bytes, sub: int, sub_params: dict | None, version: int) -> bytes:
    msg = b"\xff" * 32 + bytes([c.CTAP_AUTHENTICATOR_CONFIG, sub])
    if sub_params is not None:
        msg += cbor2.dumps(sub_params, canonical=True)
    mac = _hmac.new(token, msg, hashlib.sha256).digest()
    return mac[:16] if version == 1 else mac


def test_toggle_always_uv_auth_param():
    card = FakeConfigCard()
    Ctap2Client(CardSession(card)).toggle_always_uv(pin_uv_token=TOKEN, protocol=1)
    cmd, req = _last_req(card)
    assert cmd == c.CTAP_AUTHENTICATOR_CONFIG
    assert req[c.AC_SUBCOMMAND] == c.AC_TOGGLE_ALWAYS_UV
    assert c.AC_SUBCOMMAND_PARAMS not in req  # no sub-params for toggleAlwaysUv
    assert req[c.AC_PIN_UV_AUTH_PROTOCOL] == 1
    assert req[c.AC_PIN_UV_AUTH_PARAM] == _expect_param(TOKEN, c.AC_TOGGLE_ALWAYS_UV, None, 1)


def test_set_min_pin_length_params_and_auth():
    card = FakeConfigCard()
    Ctap2Client(CardSession(card)).set_min_pin_length(6, pin_uv_token=TOKEN, protocol=1)
    cmd, req = _last_req(card)
    assert cmd == c.CTAP_AUTHENTICATOR_CONFIG
    assert req[c.AC_SUBCOMMAND] == c.AC_SET_MIN_PIN_LENGTH
    sub = req[c.AC_SUBCOMMAND_PARAMS]
    assert sub == {c.ACP_NEW_MIN_PIN_LENGTH: 6}
    assert req[c.AC_PIN_UV_AUTH_PARAM] == _expect_param(TOKEN, c.AC_SET_MIN_PIN_LENGTH, sub, 1)


def test_protocol_two_uses_full_32_byte_mac():
    card = FakeConfigCard()
    Ctap2Client(CardSession(card)).toggle_always_uv(pin_uv_token=TOKEN, protocol=2)
    _, req = _last_req(card)
    assert req[c.AC_PIN_UV_AUTH_PROTOCOL] == 2
    assert len(req[c.AC_PIN_UV_AUTH_PARAM]) == 32
    assert req[c.AC_PIN_UV_AUTH_PARAM] == _expect_param(TOKEN, c.AC_TOGGLE_ALWAYS_UV, None, 2)


def test_no_token_omits_auth_param():
    """Unprotected authenticator path: no token -> no pinUvAuthParam/protocol."""
    card = FakeConfigCard()
    Ctap2Client(CardSession(card)).toggle_always_uv(pin_uv_token=None)
    _, req = _last_req(card)
    assert req[c.AC_SUBCOMMAND] == c.AC_TOGGLE_ALWAYS_UV
    assert c.AC_PIN_UV_AUTH_PARAM not in req
    assert c.AC_PIN_UV_AUTH_PROTOCOL not in req


def test_set_min_pin_length_optional_params_included():
    card = FakeConfigCard()
    Ctap2Client(CardSession(card)).set_min_pin_length(
        8, rp_ids=["example.com"], force_change_pin=True, pin_uv_token=TOKEN
    )
    _, req = _last_req(card)
    sub = req[c.AC_SUBCOMMAND_PARAMS]
    assert sub[c.ACP_NEW_MIN_PIN_LENGTH] == 8
    assert sub[c.ACP_MIN_PIN_LENGTH_RP_IDS] == ["example.com"]
    assert sub[c.ACP_FORCE_CHANGE_PIN] is True
    # the MAC must cover the exact canonical sub-params bytes that were sent
    assert req[c.AC_PIN_UV_AUTH_PARAM] == _expect_param(TOKEN, c.AC_SET_MIN_PIN_LENGTH, sub, 1)
