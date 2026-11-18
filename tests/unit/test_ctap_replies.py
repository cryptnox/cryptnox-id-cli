# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""CTAP2 client: what it does with replies a well-behaved double never sends."""

from __future__ import annotations

import hashlib
import hmac

import cbor2
import pytest
from _cardfakes import QueueConn
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.applets.fido import pinproto
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client, describe_get_info
from cryptnox_id_cli.applets.fido.errors import CtapStatusError
from cryptnox_id_cli.transport.errors import AppletNotFoundError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession

TOKEN = bytes(range(32))
CDH = b"\x11" * 32


def ctap(status=0x00, payload=None):
    """One CTAP reply as the applet frames it: status byte, then CBOR."""
    body = bytes([status]) + (cbor2.dumps(payload) if payload is not None else b"")
    return body, 0x90, 0x00


def client(*replies):
    conn = QueueConn(replies)
    return Ctap2Client(CardSession(conn)), conn


def request(frame: bytes) -> tuple[int, dict]:
    payload = frame[5 : 5 + frame[4]]
    return payload[0], cbor2.loads(payload[1:])


def card_key():
    return pinproto.public_key_to_cose(ec.generate_private_key(ec.SECP256R1()).public_key())


@pytest.mark.parametrize(
    ("sw", "error", "message"),
    [
        ((0x6A, 0x82), AppletNotFoundError, "not found"),
        ((0x69, 0x85), StatusWordError, "SELECT FIDO"),
    ],
)
def test_select_refusals(sw, error, message):
    cl, _ = client((b"", *sw))
    with pytest.raises(error, match=message):
        cl.select()


@pytest.mark.parametrize(
    ("reply", "error", "message"),
    [
        ((b"", 0x6D, 0x00), StatusWordError, "SW=6D00"),
        ((b"", 0x90, 0x00), CtapStatusError, "0x7F"),  # 9000 with no CTAP status byte
    ],
)
def test_command_rejects_a_frame_without_a_ctap_status(reply, error, message):
    cl, _ = client(reply)
    with pytest.raises(error, match=message):
        cl.get_info()


@pytest.mark.parametrize(
    ("call", "reply"),
    [
        (lambda cl: cl.get_info(), ctap(payload=[1, 2])),
        (lambda cl: cl.get_key_agreement(), ctap(payload={})),
        (
            lambda cl: cl.make_credential(client_data_hash=CDH, rp_id="x", user_id=b"u"),
            ctap(payload={}),
        ),
        (
            lambda cl: cl.get_assertion(rp_id="x", client_data_hash=CDH),
            ctap(payload={c.GAR_AUTH_DATA: b"a"}),
        ),
    ],
    ids=[
        "getInfo-not-a-map",
        "keyAgreement-missing",
        "makeCredential-no-authData",
        "getAssertion-no-signature",
    ],
)
def test_a_reply_missing_its_required_field_is_invalid_cbor(call, reply):
    cl, _ = client(reply)
    with pytest.raises(CtapStatusError) as exc:
        call(cl)
    assert exc.value.status == 0x12


def test_token_request_with_permissions_but_no_rp_id_and_a_reply_without_a_token():
    cl, conn = client(ctap(payload={c.CPR_KEY_AGREEMENT: card_key()}), ctap(payload={}))
    with pytest.raises(CtapStatusError, match="WithPermissions"):
        cl.get_pin_token("1234", permissions=c.PERM_CREDENTIAL_MGMT)
    _, params = request(conn.sent[-1])
    assert params[c.CP_SUBCOMMAND] == c.PIN_GET_TOKEN_USING_PIN
    assert c.CP_RP_ID not in params


def test_empty_replies_degrade_to_unknown_counts():
    cl, _ = client(ctap(), ctap())
    assert cl.pin_retries() == (None, None)
    assert cl.get_creds_metadata(TOKEN) == (0, 0)


def test_a_retries_reply_that_is_not_a_map_is_unknown():
    cl, _ = client(ctap(payload=[3, False]))
    assert cl.pin_retries() == (None, None)


def test_resident_key_is_requested_with_the_rk_option():
    cl, conn = client(ctap(payload={}))
    with pytest.raises(CtapStatusError):
        cl.make_credential(
            client_data_hash=CDH, rp_id="example.com", user_id=b"u", resident_key=True
        )
    _, params = request(conn.sent[-1])
    assert params[c.MC_OPTIONS] == {"rk": True}


def test_assertion_with_a_token_and_no_allow_list():
    cl, conn = client(ctap(payload={c.GAR_AUTH_DATA: b"a", c.GAR_SIGNATURE: b"s"}))
    out = cl.get_assertion(rp_id="example.com", client_data_hash=CDH, pin_uv_token=TOKEN)
    assert out == {
        "auth_data": b"a",
        "signature": b"s",
        "credential_id": None,
        "number_of_credentials": None,
    }
    _, params = request(conn.sent[-1])
    assert c.GA_ALLOW_LIST not in params
    assert params[c.GA_PIN_UV_AUTH_PARAM] == hmac.new(TOKEN, CDH, hashlib.sha256).digest()[:16]
    assert params[c.GA_PIN_UV_AUTH_PROTOCOL] == 1


def test_enumeration_with_no_credentials_stored_is_empty():
    cl, _ = client(ctap(status=0x2E))
    assert cl.enumerate_credentials(TOKEN) == []


def test_enumeration_reraises_any_other_ctap_error():
    cl, _ = client(ctap(status=0x33))
    with pytest.raises(CtapStatusError) as exc:
        cl.enumerate_credentials(TOKEN)
    assert exc.value.status == 0x33


def test_enumeration_with_an_empty_rp_reply_is_empty():
    cl, conn = client(ctap())
    assert cl.enumerate_credentials(TOKEN) == []
    assert len(conn.sent) == 1


def test_enumeration_walks_every_rp_and_skips_malformed_entries():
    cl, conn = client(
        ctap(
            payload={
                c.CMR_RP: {"id": "a.example"},
                c.CMR_RP_ID_HASH: b"\xaa" * 32,
                c.CMR_TOTAL_RPS: 2,
            }
        ),
        ctap(payload={c.CMR_RP: {"id": "b.example"}, c.CMR_RP_ID_HASH: b"\xbb" * 32}),
        ctap(),  # a.example: credentials reply carries no map
        ctap(
            payload={
                c.CMR_USER: {"name": "bob"},
                c.CMR_CREDENTIAL_ID: {"id": b"c1"},
                c.CMR_TOTAL_CREDENTIALS: 2,
            }
        ),
        ctap(),  # b.example: the second credential carries no map
    )
    creds = cl.enumerate_credentials(TOKEN)
    assert creds == [
        {"rp_id": "b.example", "user": {"name": "bob"}, "credential_id": b"c1", "public_key": None}
    ]
    subs = [request(f)[1][c.CM_SUBCOMMAND] for f in conn.sent]
    assert subs == [
        c.CM_ENUMERATE_RPS_BEGIN,
        c.CM_ENUMERATE_RPS_NEXT,
        c.CM_ENUMERATE_CREDS_BEGIN,
        c.CM_ENUMERATE_CREDS_BEGIN,
        c.CM_ENUMERATE_CREDS_NEXT,
    ]
    assert request(conn.sent[3])[1][c.CM_SUBCOMMAND_PARAMS] == {c.CMP_RP_ID_HASH: b"\xbb" * 32}


def test_get_info_description_without_aaguid_keeps_only_algorithm_maps():
    info = {c.INFO_AAGUID: b"short", c.INFO_ALGORITHMS: [{"alg": -7, "type": "public-key"}, "junk"]}
    out = describe_get_info(info)
    assert out["aaguid"] is None and out["cryptnox_aaguid"] is None
    assert out["algorithms"] == [{"alg": -7, "type": "public-key"}]
