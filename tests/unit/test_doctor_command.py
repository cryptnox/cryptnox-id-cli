# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``doctor``: each applet verdict, each PC/SC failure, and the Windows elevation row."""

from __future__ import annotations

import json

import pytest
from _cardfakes import run_both_modes, self_signed_der, wire_pcsc

from cryptnox_id_cli.cli.commands import doctor as doctor_cmd
from cryptnox_id_cli.transport.errors import (
    CardAccessDeniedError,
    NoCardError,
    NoReadersError,
    TransportError,
)
from cryptnox_id_cli.transport.pcsc import ReaderInfo

READER = "ACS ACR39U ICC Reader 0"
ATR = "3BD518FF8191FE1FC38073C821100A"
INFOS = [ReaderInfo(0, READER, True, bytes.fromhex(ATR))]
SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
    "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
    "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
SELECT_FIDO = "00A4040008A0000006472F000100"
CTAP_GETINFO = "80100000010400"
SELECT_GENUINE = "00A4040008A00000100002470100"
GENUINE_LEAF = "80020000000000"
DESFIRE_VERSION = "9060000000"
EV2_VERSION = "04010112001A0504010102001A050411223344556601020304052021"


@pytest.fixture
def doctor(monkeypatch, mock_connection):
    def _doctor(exchanges=None, deny=(), **patches):
        conn = mock_connection(ATR, exchanges or {}, list(deny))
        wire_pcsc(monkeypatch, doctor_cmd, conn, reader_name=READER, infos=INFOS)
        monkeypatch.setattr(doctor_cmd, "is_windows", lambda: False)
        for name, value in patches.items():
            monkeypatch.setattr(doctor_cmd, name, value)
        as_json, human = run_both_modes(["doctor"])
        assert as_json.exit_code == human.exit_code
        payload = json.loads(as_json.stdout)
        checks = {c["check"]: (c["status"], c["detail"]) for c in payload["checks"]}
        return payload, checks, as_json.exit_code, " ".join(human.output.split())

    return _doctor


def _raise(exc):
    def fn(*_args, **_kwargs):
        raise exc

    return fn


HEALTHY = {
    SELECT_PIV: f"{APT}|9000",
    SELECT_FIDO: "|9000",
    CTAP_GETINFO: "00A10181684649444F5F325F30|9000",
    DESFIRE_VERSION: f"{EV2_VERSION}|9100",
    SELECT_GENUINE: "|9000",
    GENUINE_LEAF: f"{self_signed_der('Device DEV-TEST-01').hex()}|9000",
}


@pytest.mark.parametrize(
    ("exchanges", "deny", "expected"),
    [
        (
            HEALTHY,
            (),
            {
                "PIV applet": ("ok", "selectable (PivPrePersonalized)"),
                "FIDO2 applet": ("ok", "FidoPersonalized"),
                "DESFire (contactless)": ("ok", "reachable"),
                "Genuineness applet": ("ok", "personalized (run `genuine verify` to prove)"),
            },
        ),
        (
            {SELECT_PIV: "|6985", DESFIRE_VERSION: "|91AE", SELECT_GENUINE: "|9000"},
            (SELECT_FIDO,),
            {
                "PIV applet": ("warn", "state unknown"),
                "FIDO2 applet": (
                    "warn",
                    "blocked by OS; run from an Administrator terminal to manage FIDO2",
                ),
                "DESFire (contactless)": ("warn", "Unknown"),
                "Genuineness applet": ("warn", "present but not personalized (no leaf cert)"),
            },
        ),
        (
            {SELECT_FIDO: "|6985", SELECT_GENUINE: "|6985"},
            (),
            {"FIDO2 applet": ("warn", "Unknown"), "Genuineness applet": ("warn", "Unknown")},
        ),
    ],
    ids=["healthy", "unknown-piv-blocked-fido", "unknown-fido-genuine"],
)
def test_each_applet_verdict(doctor, exchanges, deny, expected):
    payload, checks, code, text = doctor(exchanges, deny)

    assert code == 0 and payload["ok"] is True
    assert checks["Card present"] == ("ok", f"ATR {ATR}")
    for name, verdict in expected.items():
        assert checks[name] == verdict
    assert "No blocking issues." in text


@pytest.mark.parametrize(
    ("patches", "failed"),
    [
        (
            {"reader_states": _raise(TransportError("Cannot reach the PC/SC service."))},
            "PC/SC service",
        ),
        (
            {"pick_reader": _raise(NoReadersError("No PC/SC readers found."))},
            "Reader (Cryptnox/ACS-first)",
        ),
        ({"connect": _raise(NoCardError("No card present."))}, "Card present"),
        ({"connect": _raise(CardAccessDeniedError("sharing violation"))}, "Card connection"),
    ],
    ids=["no-service", "no-reader", "no-card", "connect-refused"],
)
def test_a_failed_check_stops_the_chain_and_exits_2(doctor, patches, failed):
    payload, checks, code, text = doctor(**patches)

    assert code == 2 and payload["ok"] is False
    assert list(checks)[-1] == failed and checks[failed][0] == "fail"
    assert "PIV applet" not in checks
    assert "Some checks failed." in text


@pytest.mark.parametrize(
    ("elevated", "status", "detail"),
    [
        (True, "ok", "Administrator (FIDO2 reachable)"),
        (False, "info", "not elevated; FIDO2 needs admin"),
        (None, "info", "could not determine elevation"),
    ],
    ids=["elevated", "not-elevated", "unknown"],
)
def test_windows_reports_elevation(doctor, elevated, status, detail):
    _, checks, code, text = doctor(is_windows=lambda: True, is_elevated=lambda: elevated)

    assert code == 0
    assert checks["Windows elevation"][0] == status
    assert checks["Windows elevation"][1].startswith(detail)
    assert f"Windows elevation │ {status}" in text


def test_elevation_is_not_reported_off_windows(doctor):
    _, checks, _, _ = doctor()

    assert "Windows elevation" not in checks
