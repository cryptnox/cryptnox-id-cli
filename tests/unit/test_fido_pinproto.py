"""FIDO PIN/UV auth protocol tests: crypto roundtrips + an end-to-end card loopback."""

import hashlib

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.applets.fido import pinproto
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client
from cryptnox_id_cli.applets.fido.errors import CtapStatusError
from cryptnox_id_cli.transport.pcsc import CardSession


def _sha256(b):
    return hashlib.sha256(b).digest()


# -- pure crypto ------------------------------------------------------------- #
def test_proto1_roundtrip_and_mac_len():
    proto = pinproto.ProtocolOne(bytes(range(32)))
    pt = b"A" * 32
    assert proto.decrypt(proto.encrypt(pt)) == pt
    assert len(proto.authenticate(b"message")) == 16


def test_proto2_roundtrip_iv_prepended_and_full_mac():
    proto = pinproto.ProtocolTwo(bytes(range(64)))
    pt = b"B" * 16
    ct = proto.encrypt(pt)
    assert len(ct) == 32  # 16-byte IV + one 16-byte block
    assert proto.decrypt(ct) == pt
    assert len(proto.authenticate(b"message")) == 32


@pytest.mark.parametrize("version", [1, 2])
def test_encapsulate_loopback(version):
    # The platform and the "card" must derive the same shared secret.
    card_priv = ec.generate_private_key(ec.SECP256R1())
    card_cose = pinproto.public_key_to_cose(card_priv.public_key())
    platform_cose, proto = pinproto.encapsulate(card_cose, version)
    z = card_priv.exchange(ec.ECDH(), pinproto.cose_to_public_key(platform_cose))
    cls = {1: pinproto.ProtocolOne, 2: pinproto.ProtocolTwo}[version]
    assert proto.shared_secret == cls.kdf(z)


def test_pad_pin_and_hash():
    padded = pinproto.pad_pin("1234")
    assert len(padded) == 64 and padded[:4] == b"1234" and padded[4:] == b"\x00" * 60
    assert pinproto.pin_hash_left16("1234") == _sha256(b"1234")[:16]
    with pytest.raises(ValueError):
        pinproto.pad_pin("12")  # too short
    with pytest.raises(ValueError):
        pinproto.pad_pin("x" * 64)  # too long


# -- end-to-end against a card that implements the protocol ------------------ #
class FakeFidoCard:
    def __init__(self, protocol=1):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.protocol = protocol
        self.pin: bytes | None = None
        self.token = bytes(range(32))
        self.sent: list[bytes] = []

    def _proto(self, platform_cose):
        z = self.priv.exchange(ec.ECDH(), pinproto.cose_to_public_key(platform_cose))
        cls = {1: pinproto.ProtocolOne, 2: pinproto.ProtocolTwo}[self.protocol]
        return cls(cls.kdf(z))

    def _resp(self, status, payload=None):
        body = bytes([status]) + (cbor2.dumps(payload) if payload is not None else b"")
        return list(body), 0x90, 0x00

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.sent.append(raw)
        if raw[1] == 0xA4:  # SELECT
            return list(b"FIDO_2_1"), 0x90, 0x00
        lc = raw[4]
        payload = raw[5 : 5 + lc]
        cmd, params = payload[0], (cbor2.loads(payload[1:]) if len(payload) > 1 else {})
        if cmd != c.CTAP_CLIENT_PIN:
            return self._resp(0x01)
        sub = params.get(c.CP_SUBCOMMAND)
        if sub == c.PIN_GET_KEY_AGREEMENT:
            return self._resp(
                0x00, {c.CPR_KEY_AGREEMENT: pinproto.public_key_to_cose(self.priv.public_key())}
            )
        proto = self._proto(params[c.CP_KEY_AGREEMENT])
        if sub == c.PIN_SET_PIN:
            enc = params[c.CP_NEW_PIN_ENC]
            if proto.authenticate(enc) != params[c.CP_PIN_UV_AUTH_PARAM]:
                return self._resp(0x33)
            self.pin = proto.decrypt(enc).rstrip(b"\x00")
            return self._resp(0x00)
        if sub == c.PIN_CHANGE_PIN:
            if proto.decrypt(params[c.CP_PIN_HASH_ENC]) != _sha256(self.pin)[:16]:
                return self._resp(0x31)
            if (
                proto.authenticate(params[c.CP_NEW_PIN_ENC] + params[c.CP_PIN_HASH_ENC])
                != params[c.CP_PIN_UV_AUTH_PARAM]
            ):
                return self._resp(0x33)
            self.pin = proto.decrypt(params[c.CP_NEW_PIN_ENC]).rstrip(b"\x00")
            return self._resp(0x00)
        if sub in (c.PIN_GET_PIN_TOKEN, c.PIN_GET_TOKEN_USING_PIN):
            if proto.decrypt(params[c.CP_PIN_HASH_ENC]) != _sha256(self.pin)[:16]:
                return self._resp(0x31)
            return self._resp(0x00, {c.CPR_PIN_UV_AUTH_TOKEN: proto.encrypt(self.token)})
        return self._resp(0x02)

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


@pytest.mark.parametrize("version", [1, 2])
def test_set_then_get_token_roundtrip(version):
    card = FakeFidoCard(protocol=version)
    ctap = Ctap2Client(CardSession(card))
    ctap.set_pin("1234", protocol=version)
    assert card.pin == b"1234"
    assert ctap.get_pin_token("1234", protocol=version) == card.token


def test_change_pin():
    card = FakeFidoCard(protocol=1)
    card.pin = b"1234"
    ctap = Ctap2Client(CardSession(card))
    ctap.change_pin("1234", "567890", protocol=1)
    assert card.pin == b"567890"


def test_wrong_pin_token_raises_pin_invalid():
    card = FakeFidoCard(protocol=1)
    card.pin = b"1234"
    ctap = Ctap2Client(CardSession(card))
    with pytest.raises(CtapStatusError) as exc:
        ctap.get_pin_token("9999", protocol=1)
    assert exc.value.status == 0x31


def test_get_token_with_permissions_uses_0x09():
    card = FakeFidoCard(protocol=1)
    card.pin = b"1234"
    ctap = Ctap2Client(CardSession(card))
    ctap.get_pin_token("1234", protocol=1, permissions=c.PERM_GET_ASSERTION, rp_id="example.com")
    # The last CTAP request carried the permissions subcommand + rpId.
    last = card.sent[-1]
    params = cbor2.loads(last[6:-1])
    assert params[c.CP_SUBCOMMAND] == c.PIN_GET_TOKEN_USING_PIN
    assert params[c.CP_PERMISSIONS] == c.PERM_GET_ASSERTION
    assert params[c.CP_RP_ID] == "example.com"
