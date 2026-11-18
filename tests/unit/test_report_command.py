# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``report``: every subcommand's envelope, each section's states, and ``--out``."""

from __future__ import annotations

import json

import pytest
from _cardfakes import run_both_modes, self_signed_der, wire_session

READER = "ACS ACR39U ICC Reader 0"
ATR = "3BD518FF8191FE1FC38073C821100A"
SELECT_ISD = "00A4040008A00000015100000000"
GET_CPLC = "80CA9F7F00"
CPLC = "9F7F2A4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
    "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
    "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
SELECT_FIDO = "00A4040008A0000006472F000100"
CTAP_GETINFO = "80100000010400"
GETINFO_V2 = "00A10182684649444F5F325F30665532465F5632"  # {1: ["FIDO_2_0", "U2F_V2"]}
SELECT_GENUINE = "00A4040008A00000100002470100"
GENUINE_INFO = "8001000000"
GENUINE_LEAF = "80020000000000"
DESFIRE_VERSION = "9060000000"
DESFIRE_FREE = "906E000000"
DESFIRE_AIDS = "906A000000"
EV2_VERSION = "04010112001A0504010102001A050411223344556601020304052021"


def _full_card(leaf_cn: str = "Device DEV-TEST-01") -> dict[str, str]:
    return {
        SELECT_ISD: "|9000",
        GET_CPLC: f"{CPLC}|9000",
        DESFIRE_VERSION: f"{EV2_VERSION}|9100",
        DESFIRE_FREE: "001000|9100",
        DESFIRE_AIDS: "010203AABBCC|9100",
        SELECT_PIV: f"{APT}|9000",
        "00200080": "|63C3",
        "00200081": "|63C5",
        SELECT_FIDO: "322E30|9000",
        CTAP_GETINFO: f"{GETINFO_V2}|9000",
        SELECT_GENUINE: "|9000",
        GENUINE_INFO: "01000711|9000",
        GENUINE_LEAF: f"{self_signed_der(leaf_cn).hex()}|9000",
    }


@pytest.fixture
def wire(monkeypatch, mock_connection):
    def _wire(exchanges, deny=()):
        conn = mock_connection(ATR, exchanges, list(deny))
        wire_session(monkeypatch, conn, reader_name=READER)

    return _wire


def _report(args):
    as_json, human = run_both_modes(["report", *args])
    assert as_json.exit_code == 0, as_json.output
    assert human.exit_code == 0, human.output
    return json.loads(as_json.stdout), human.output


@pytest.mark.parametrize(
    ("kind", "sections"),
    [
        ("card", {"reader", "state", "cplc"}),
        ("piv", {"piv"}),
        ("mifare", {"mifare"}),
        ("fido", {"fido"}),
        ("genuine", {"genuine"}),
        ("full", {"mifare", "card", "piv", "fido", "genuine"}),
    ],
)
def test_every_report_carries_the_envelope_and_its_sections(wire, kind, sections):
    wire(_full_card())
    payload, human = _report([kind])

    envelope = {"report", "generated_by", "generated_at", "safe_to_share"}
    assert set(payload) == envelope | sections
    assert payload["report"] == kind and payload["safe_to_share"] is True
    assert json.loads(human)["report"] == kind  # human mode prints the same JSON


def test_full_report_reads_each_function(wire):
    wire(_full_card())
    payload, _ = _report(["full"])

    assert payload["mifare"] == {
        "state": "DesfireReachable",
        "version": payload["mifare"]["version"],
        "free_memory": 4096,
        "applications": ["010203", "AABBCC"],
    }
    assert payload["card"]["reader"] == READER
    assert payload["card"]["cplc"]["uid"] == "4301012345670042"
    assert payload["piv"]["pin"]["retries_remaining"] == 3
    assert payload["fido"]["select_version"] == "2.0"
    assert payload["fido"]["get_info"]["versions"] == ["FIDO_2_0", "U2F_V2"]
    assert payload["genuine"]["leaf_subject"] == "CN=Device DEV-TEST-01"


@pytest.mark.parametrize(
    ("exchanges", "state", "detail"),
    [
        ({}, "GenuinenessNotPresent", {"note"}),
        ({SELECT_GENUINE: "|9000"}, "GenuinenessPresent", {"leaf_subject", "info", "note"}),
        ({SELECT_GENUINE: "|6985"}, "Unknown", {"error"}),
    ],
    ids=["absent", "blank", "refused"],
)
def test_genuine_section_states(wire, exchanges, state, detail):
    wire(exchanges)
    payload, _ = _report(["genuine"])

    section = payload["genuine"]
    assert section["state"] == state
    assert set(section) == {"state"} | detail


@pytest.mark.parametrize(
    ("exchanges", "deny", "state"),
    [
        ({}, (SELECT_FIDO,), "FidoBlockedByOS"),
        ({}, (), "FidoNotPresent"),
        ({SELECT_FIDO: "|6985"}, (), "Unknown"),
    ],
    ids=["blocked-by-os", "absent", "refused"],
)
def test_fido_section_states(wire, exchanges, deny, state):
    wire(exchanges, deny)
    payload, _ = _report(["fido"])

    assert payload["fido"]["state"] == state


@pytest.mark.parametrize(
    ("exchanges", "state"),
    [
        ({}, "DesfireNeedsContactlessReader"),
        ({DESFIRE_VERSION: "|91AE"}, "Unknown"),
        ({DESFIRE_VERSION: f"{EV2_VERSION}|9100", DESFIRE_AIDS: "|9100"}, "DesfireReachable"),
    ],
    ids=["contact-reader", "refused", "free-memory-refused"],
)
def test_mifare_section_states(wire, exchanges, state):
    wire(exchanges)
    payload, _ = _report(["mifare"])

    assert payload["mifare"]["state"] == state
    if state == "DesfireReachable":  # free memory refused: reported as unknown, not fatal
        assert payload["mifare"]["free_memory"] is None


def test_out_writes_the_report_and_says_where(wire, tmp_path):
    wire({})
    out = tmp_path / "genuine.json"
    payload, human = _report(["genuine", "--out", str(out)])

    assert json.loads(out.read_text(encoding="utf-8"))["genuine"] == payload["genuine"]
    assert f"Report written to {out}" in " ".join(human.split())


@pytest.mark.xfail(strict=True, reason="the human report is printed as console markup")
@pytest.mark.parametrize("common_name", ["Device a[/x]b", "Device [b]S[/b]"])
def test_human_report_is_the_json_as_written(wire, common_name):
    wire(_full_card(leaf_cn=common_name))
    _, human = _report(["genuine"])

    assert json.loads(human)["genuine"]["leaf_subject"] == f"CN={common_name}"


@pytest.mark.xfail(strict=True, reason="the --out path is printed as console markup")
def test_out_names_a_path_with_brackets_as_written(wire, tmp_path):
    wire({})
    folder = tmp_path / "old [draft]"
    folder.mkdir()
    out = folder / "genuine.json"
    _, human = _report(["genuine", "--out", str(out)])

    assert out.exists()
    assert f"Report written to {out}" in " ".join(human.split())
