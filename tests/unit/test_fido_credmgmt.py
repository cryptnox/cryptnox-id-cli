"""FIDO authenticatorCredentialManagement: request shaping + enumeration walk."""

import hashlib
import hmac as _hmac

import cbor2

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client
from cryptnox_id_cli.transport.pcsc import CardSession

TOKEN = bytes(range(32))


class FakeCredMgmtCard:
    """One RP (example.com) with two resident credentials."""

    def __init__(self):
        self.sent: list[bytes] = []
        self.deleted: list[bytes] = []

    def _resp(self, status, payload=None):
        body = bytes([status]) + (cbor2.dumps(payload) if payload is not None else b"")
        return list(body), 0x90, 0x00

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.sent.append(raw)
        if raw[1] == 0xA4:
            return list(b"FIDO_2_1"), 0x90, 0x00
        lc = raw[4]
        payload = raw[5 : 5 + lc]
        cmd, params = payload[0], cbor2.loads(payload[1:])
        if cmd != c.CTAP_CREDENTIAL_MANAGEMENT:
            return self._resp(0x01)
        sub = params[c.CM_SUBCOMMAND]
        if sub == c.CM_GET_CREDS_METADATA:
            return self._resp(0x00, {c.CMR_EXISTING_RESIDENT_COUNT: 2, c.CMR_MAX_REMAINING: 10})
        if sub == c.CM_ENUMERATE_RPS_BEGIN:
            return self._resp(
                0x00,
                {
                    c.CMR_RP: {"id": "example.com"},
                    c.CMR_RP_ID_HASH: b"\xaa" * 32,
                    c.CMR_TOTAL_RPS: 1,
                },
            )
        if sub == c.CM_ENUMERATE_CREDS_BEGIN:
            return self._resp(
                0x00,
                {
                    c.CMR_USER: {"id": b"u1", "name": "alice"},
                    c.CMR_CREDENTIAL_ID: {"id": b"cred-1", "type": "public-key"},
                    c.CMR_PUBLIC_KEY: {1: 2},
                    c.CMR_TOTAL_CREDENTIALS: 2,
                },
            )
        if sub == c.CM_ENUMERATE_CREDS_NEXT:
            return self._resp(
                0x00,
                {
                    c.CMR_USER: {"id": b"u2", "name": "bob"},
                    c.CMR_CREDENTIAL_ID: {"id": b"cred-2", "type": "public-key"},
                    c.CMR_PUBLIC_KEY: {1: 2},
                },
            )
        if sub == c.CM_DELETE_CREDENTIAL:
            self.deleted.append(params[c.CM_SUBCOMMAND_PARAMS][c.CMP_CREDENTIAL_ID]["id"])
            return self._resp(0x00)
        return self._resp(0x01)

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


def test_get_creds_metadata_and_auth_param():
    card = FakeCredMgmtCard()
    ctap = Ctap2Client(CardSession(card))
    assert ctap.get_creds_metadata(TOKEN, protocol=1) == (2, 10)
    req = cbor2.loads(card.sent[-1][6:-1])
    # pinUvAuthParam = HMAC(token, subCommand byte)[:16] (no sub-params)
    expect = _hmac.new(TOKEN, bytes([c.CM_GET_CREDS_METADATA]), hashlib.sha256).digest()[:16]
    assert req[c.CM_PIN_UV_AUTH_PARAM] == expect
    assert req[c.CM_PIN_UV_AUTH_PROTOCOL] == 1


def test_enumerate_credentials_walks_rps_and_creds():
    card = FakeCredMgmtCard()
    creds = Ctap2Client(CardSession(card)).enumerate_credentials(TOKEN, protocol=1)
    assert [(x["rp_id"], x["user"]["name"], x["credential_id"]) for x in creds] == [
        ("example.com", "alice", b"cred-1"),
        ("example.com", "bob", b"cred-2"),
    ]


def test_delete_credential_sends_id_and_auth():
    card = FakeCredMgmtCard()
    Ctap2Client(CardSession(card)).delete_credential(b"cred-1", TOKEN, protocol=1)
    assert card.deleted == [b"cred-1"]
    req = cbor2.loads(card.sent[-1][6:-1])
    sub_params = req[c.CM_SUBCOMMAND_PARAMS]
    msg = bytes([c.CM_DELETE_CREDENTIAL]) + cbor2.dumps(sub_params, canonical=True)
    assert req[c.CM_PIN_UV_AUTH_PARAM] == _hmac.new(TOKEN, msg, hashlib.sha256).digest()[:16]
