# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``info``: what each detected card state looks like in both output modes."""

from __future__ import annotations

import json

import pytest
from _cardfakes import run_both_modes, self_signed_der, wire_session

CONTACT = "ACS ACR39U ICC Reader 0"
PICC = "ACS ACR1552 1S CL Reader PICC 0"
WIRED_ATR = "3BD518FF8191FE1FC38073C821100A"
CL_ATR = "3B8180018080"

SELECT_ISD = "00A4040008A00000015100000000"
GET_CPLC = "80CA9F7F00"
# IC fabrication date, IC serial 01234567, batch 0042 at body[10:18].
CPLC_BODY = "4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
    "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
    "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
GET_STATUS = "00CB3F00055C032F475300"
STATUS_SECURED = "531880010F8101008201008301008401008501008601008701FF"
VERIFY_PIN, VERIFY_PUK = "00200080", "00200081"
CHUID, CCC, PRINTED = (
    "00CB3FFF055C035FC10200",
    "00CB3FFF055C035FC10700",
    "00CB3FFF055C035FC10900",
)
SELECT_FIDO = "00A4040008A0000006472F000100"
CTAP_GETINFO = "80100000010400"
GETINFO_V2 = "00A10182684649444F5F325F30665532465F5632"  # {1: ["FIDO_2_0", "U2F_V2"]}
SELECT_DEFAULT = "00A4040000"
SELECT_GENUINE = "00A4040008A00000100002470100"
GENUINE_INFO = "8001000000"
GENUINE_LEAF = "80020000000000"
DESFIRE_VERSION = "9060000000"
# One frame carrying all 28 GetVersion bytes: storage code 0x1A = 8192 bytes.
EV2_VERSION = "04010112001A0504010102001A050411223344556601020304052021"


def _personalized_contact(pin_answer: str = "63C3", leaf_cn: str = "Device DEV-TEST-01"):
    return (
        CONTACT,
        WIRED_ATR,
        {
            SELECT_ISD: "|9000",
            GET_CPLC: f"9F7F2A{CPLC_BODY}|9000",
            SELECT_PIV: f"{APT}|9000",
            GET_STATUS: f"{STATUS_SECURED}|9000",
            VERIFY_PIN: f"|{pin_answer}",
            VERIFY_PUK: "|63C5",
            CHUID: "5303AABBCC|9000",
            CCC: "5303AABBCC|9000",
            PRINTED: "5303AABBCC|9000",
            SELECT_FIDO: "|9000",
            CTAP_GETINFO: f"{GETINFO_V2}|9000",
            SELECT_DEFAULT: "|9000",
            SELECT_GENUINE: "|9000",
            GENUINE_INFO: "01000711|9000",
            GENUINE_LEAF: f"{self_signed_der(leaf_cn).hex()}|9000",
        },
    )


def _blank_contactless():
    # PIN and PUK are contact-only on the built-in profiles: 6982 over PICC.
    return (
        PICC,
        CL_ATR,
        {
            DESFIRE_VERSION: f"{EV2_VERSION}|9100",
            SELECT_PIV: f"{APT}|9000",
            VERIFY_PIN: "|6982",
            VERIFY_PUK: "|6982",
        },
    )


def _invoke(mock_connection, monkeypatch, reader, atr, exchanges, deny=()):
    wire_session(monkeypatch, mock_connection(atr, exchanges, list(deny)), reader_name=reader)
    as_json, human = run_both_modes(["info"])
    assert as_json.exit_code == 0, as_json.output
    assert human.exit_code == 0, human.output
    return json.loads(as_json.stdout), " ".join(human.output.split())


def test_personalized_card_shows_every_applet_detail(mock_connection, monkeypatch):
    payload, text = _invoke(mock_connection, monkeypatch, *_personalized_contact())

    assert payload["reader"] == CONTACT
    assert payload["cplc"]["uid"] == "4301012345670042"
    assert payload["cplc"]["ic_serial"] == "01234567"
    assert payload["piv"]["state"] == "PivPersonalized"
    assert payload["piv"]["secured"] is True
    assert payload["fido"]["versions"] == ["FIDO_2_0", "U2F_V2"]
    assert payload["genuine"]["state"] == "GenuinenessPersonalized"
    assert payload["desfire"]["state"] == "DesfireNeedsContactlessReader"

    assert f"Reader: {CONTACT}" in text
    assert f"ATR: {WIRED_ATR}" in text
    assert "Serial: 01234567 (CPLC)" in text
    assert "UID: 4301012345670042 (CPLC)" in text
    assert "OpenFIPS201, PIN 3 tries, finalized" in text
    assert "FIDO_2_0, U2F_V2" in text
    assert "CN=Device DEV-TEST-01" in text
    assert "PIV objects present: chuid, ccc, printed" in text
    assert "* DESFire EV2 (the default MIFARE applet) did not answer" in text


def test_a_pin_already_verified_shows_as_set(mock_connection, monkeypatch):
    _, text = _invoke(mock_connection, monkeypatch, *_personalized_contact(pin_answer="9000"))
    assert "OpenFIPS201, PIN set, finalized" in text


def test_contactless_card_shows_desfire_version_and_no_pin_detail(mock_connection, monkeypatch):
    payload, text = _invoke(mock_connection, monkeypatch, *_blank_contactless())

    assert payload["reader"] == PICC
    assert payload["cplc"] is None
    assert payload["desfire"]["version"]["uid"] == "04112233445566"
    assert payload["piv"]["state"] == "PivPartiallyPersonalized"
    assert payload["piv"]["pin"]["refused_on_interface"] is True
    assert payload["genuine"]["state"] == "GenuinenessNeedsContactReader"

    assert "Serial:" not in text and "UID: 4301" not in text
    assert "EV2 8192 B, UID 04112233445566" in text
    assert "│ OpenFIPS201 │" in text
    assert "finalized" not in text
    assert "PIV objects present: none" in text
    assert "* PIN/PUK state not readable" in text
    assert "contact-only" in text


def test_card_without_piv_lists_no_objects(mock_connection, monkeypatch):
    payload, text = _invoke(mock_connection, monkeypatch, CONTACT, WIRED_ATR, {})

    assert payload["piv"]["state"] == "PivNotPresent"
    assert payload["piv"]["objects_present"] == {}
    assert "PivNotPresent" in text
    assert "PIV objects present" not in text


@pytest.mark.parametrize(
    "answer",
    [f"9F7F2A{CPLC_BODY}", f"9F7F81 2A{CPLC_BODY}", f"9F7F82002A{CPLC_BODY}", CPLC_BODY],
    ids=["short-length", "long-form-81", "long-form-82", "no-tag"],
)
def test_cplc_serial_and_uid_from_every_length_form(mock_connection, monkeypatch, answer):
    exchanges = {SELECT_ISD: "|9000", GET_CPLC: f"{answer.replace(' ', '')}|9000"}
    payload, text = _invoke(mock_connection, monkeypatch, CONTACT, WIRED_ATR, exchanges)

    assert payload["cplc"]["ic_serial"] == "01234567"
    assert payload["cplc"]["uid"] == "4301012345670042"
    assert "Serial: 01234567 (CPLC)" in text


@pytest.mark.parametrize(
    ("exchanges", "deny"),
    [
        ({SELECT_ISD: "|6A82"}, ()),
        ({SELECT_ISD: "|9000", GET_CPLC: "|6A88"}, ()),
        ({SELECT_ISD: "|9000", GET_CPLC: "|9000"}, ()),
        ({}, (SELECT_ISD,)),
    ],
    ids=["isd-refused", "cplc-refused", "cplc-empty", "transmit-error"],
)
def test_cplc_is_null_when_it_cannot_be_read(mock_connection, monkeypatch, exchanges, deny):
    payload, text = _invoke(mock_connection, monkeypatch, CONTACT, WIRED_ATR, exchanges, deny)

    assert payload["cplc"] is None
    assert "(CPLC)" not in text


@pytest.mark.parametrize("common_name", ["Device a[/x]b", "Device [b]S[/b]"])
def test_the_genuineness_subject_is_printed_as_written(mock_connection, monkeypatch, common_name):
    _, text = _invoke(mock_connection, monkeypatch, *_personalized_contact(leaf_cn=common_name))
    assert f"CN={common_name}" in text
