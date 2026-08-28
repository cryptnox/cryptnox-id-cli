"""makeCredential / getAssertion: request shaping, authData parsing, sign/verify loopback."""

import hashlib
import hmac as _hmac
import os

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.applets.fido import authdata, pinproto
from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client
from cryptnox_id_cli.transport.pcsc import CardSession


def _sha256(b):
    return hashlib.sha256(b).digest()


class FakeCredCard:
    """A card that really generates credential keypairs, builds authData, and signs -
    so the platform's makeCredential -> getAssertion -> verify round-trip is exercised."""

    def __init__(self):
        self.creds: dict[bytes, ec.EllipticCurvePrivateKey] = {}
        self.sign_count = 0
        self.sent: list[bytes] = []

    def _resp(self, status, payload=None):
        body = bytes([status]) + (cbor2.dumps(payload) if payload is not None else b"")
        return list(body), 0x90, 0x00

    def _auth_data(self, rp_id, attested):
        self.sign_count += 1
        flags = 0x45 if attested else 0x05  # UP|UV(|AT)
        ad = _sha256(rp_id.encode()) + bytes([flags]) + self.sign_count.to_bytes(4, "big")
        if attested:
            cred_id, priv = attested
            cose = pinproto.public_key_to_cose(priv.public_key())
            cose[c.COSE_ALG] = c.COSE_ALG_ES256
            ad += bytes(16) + len(cred_id).to_bytes(2, "big") + cred_id + cbor2.dumps(cose)
        return ad

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.sent.append(raw)
        if raw[1] == 0xA4:
            return list(b"FIDO_2_1"), 0x90, 0x00
        lc = raw[4]
        payload = raw[5 : 5 + lc]
        cmd, params = payload[0], cbor2.loads(payload[1:])
        if cmd == c.CTAP_MAKE_CREDENTIAL:
            rp_id = params[c.MC_RP]["id"]
            priv = ec.generate_private_key(ec.SECP256R1())
            cred_id = os.urandom(16)
            self.creds[cred_id] = priv
            ad = self._auth_data(rp_id, attested=(cred_id, priv))
            return self._resp(0x00, {c.MCR_FMT: "none", c.MCR_AUTH_DATA: ad, c.MCR_ATT_STMT: {}})
        if cmd == c.CTAP_GET_ASSERTION:
            rp_id, cdh = params[c.GA_RP_ID], params[c.GA_CLIENT_DATA_HASH]
            allow = params.get(c.GA_ALLOW_LIST)
            cred_id = allow[0]["id"] if allow else next(iter(self.creds))
            priv = self.creds[cred_id]
            ad = self._auth_data(rp_id, attested=None)
            sig = priv.sign(ad + cdh, ec.ECDSA(hashes.SHA256()))
            return self._resp(
                0x00,
                {
                    c.GAR_CREDENTIAL: {"id": cred_id, "type": "public-key"},
                    c.GAR_AUTH_DATA: ad,
                    c.GAR_SIGNATURE: sig,
                },
            )
        return self._resp(0x01)

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


def test_register_then_assert_verifies():
    card = FakeCredCard()
    ctap = Ctap2Client(CardSession(card))
    cred = ctap.make_credential(
        client_data_hash=os.urandom(32), rp_id="example.com", user_id=b"user-1"
    )
    assert cred["credential_id"] in card.creds
    cdh = os.urandom(32)
    assertion = ctap.get_assertion(
        rp_id="example.com", client_data_hash=cdh, allow_credential_ids=[cred["credential_id"]]
    )
    assert authdata.verify_es256_assertion(
        cred["credential_public_key"], assertion["auth_data"], cdh, assertion["signature"]
    )
    # A different clientDataHash must NOT verify against the same signature.
    assert not authdata.verify_es256_assertion(
        cred["credential_public_key"],
        assertion["auth_data"],
        os.urandom(32),
        assertion["signature"],
    )


def test_make_credential_pin_uv_auth_param():
    card = FakeCredCard()
    ctap = Ctap2Client(CardSession(card))
    token = bytes(range(32))
    cdh = b"\x11" * 32
    ctap.make_credential(
        client_data_hash=cdh, rp_id="example.com", user_id=b"u", pin_uv_token=token, protocol=1
    )
    req = cbor2.loads(card.sent[-1][6:-1])
    assert req[c.MC_PIN_UV_AUTH_PROTOCOL] == 1
    assert req[c.MC_PIN_UV_AUTH_PARAM] == _hmac.new(token, cdh, hashlib.sha256).digest()[:16]
    assert req[c.MC_PUB_KEY_CRED_PARAMS] == [{"alg": c.COSE_ALG_ES256, "type": "public-key"}]


def test_parse_authenticator_data_without_attestation():
    raw = _sha256(b"rp") + bytes([0x05]) + (7).to_bytes(4, "big")
    ad = authdata.parse_authenticator_data(raw)
    assert ad.user_present and ad.user_verified
    assert ad.sign_count == 7
    assert ad.credential_id is None


def test_parse_authenticator_data_truncated_raises():
    with pytest.raises(ValueError):
        authdata.parse_authenticator_data(b"\x00" * 10)
