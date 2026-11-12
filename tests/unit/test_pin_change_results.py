# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What ``pin change``, ``pin unblock`` and ``puk change`` read into the card's answer.

``63C0`` (retry counter exhausted) proves a blocked verifier. ``6983`` does not: the
applet answers it for a blocked PIN or PUK and, over a contactless reader, when the
verifier's contactless limit is reached while contact tries remain.
"""

from __future__ import annotations

import json

import pytest
from _cardfakes import run_both_modes, wire_session

SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
PICC_READER = "ACS ACR1552 1S CL Reader PICC 0"
PIN_CHANGE = "002400801031323334FFFFFFFF35363738FFFFFFFF"
PIN_UNBLOCK = "002C008010313233343536373830303030FFFFFFFF"
PUK_CHANGE = "002400811031323334353637383837363534333231"

COMMANDS = [
    pytest.param(
        ["piv", "pin", "change"],
        PIN_CHANGE,
        {"CRYPTNOX_PIV_PIN": "1234", "CRYPTNOX_PIV_NEW_PIN": "5678"},
        "PIN",
        id="pin-change",
    ),
    pytest.param(
        ["piv", "pin", "unblock"],
        PIN_UNBLOCK,
        {"CRYPTNOX_PIV_PUK": "12345678", "CRYPTNOX_PIV_NEW_PIN": "0000"},
        "PUK",
        id="pin-unblock",
    ),
    pytest.param(
        ["piv", "puk", "change"],
        PUK_CHANGE,
        {"CRYPTNOX_PIV_PUK": "12345678", "CRYPTNOX_PIV_NEW_PUK": "87654321"},
        "PUK",
        id="puk-change",
    ),
]


def _wire(monkeypatch, mock_connection, apdu: str, sw: str, reader_name: str | None = None):
    exchanges = {SELECT_PIV: f"{APT}|9000", apdu: f"|{sw}"}
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []), reader_name=reader_name)


def _both(args, env):
    as_json, human = run_both_modes(args, env=env)
    return json.loads(as_json.stdout), human.output


@pytest.mark.parametrize(("args", "apdu", "env", "verifier"), COMMANDS)
def test_an_exhausted_counter_is_a_proven_block(
    monkeypatch, mock_connection, args, apdu, env, verifier
):
    _wire(monkeypatch, mock_connection, apdu, "63C0")
    payload, human = _both(args, env)
    assert payload["changed"] is False
    assert payload["retries_remaining"] == 0
    assert payload["blocked"] is True
    assert "now blocked" in payload["recovery"]
    assert "now blocked" in human


@pytest.mark.parametrize(("args", "apdu", "env", "verifier"), COMMANDS)
def test_tries_left_is_not_a_block(monkeypatch, mock_connection, args, apdu, env, verifier):
    _wire(monkeypatch, mock_connection, apdu, "63C2")
    payload, human = _both(args, env)
    assert payload["changed"] is False
    assert payload["retries_remaining"] == 2
    assert not {"blocked", "recovery", "hint"} & payload.keys()
    assert "now blocked" not in human


@pytest.mark.parametrize(("args", "apdu", "env", "verifier"), COMMANDS)
def test_6983_names_both_causes_and_the_status_check(
    monkeypatch, mock_connection, args, apdu, env, verifier
):
    _wire(monkeypatch, mock_connection, apdu, "6983")
    payload, human = _both(args, env)
    assert payload["changed"] is False
    assert not {"blocked", "recovery"} & payload.keys()
    hint = payload["hint"]
    assert hint.startswith(f"The {verifier} is blocked, or ")
    assert "`piv pin status`" in hint
    if verifier == "PIN":
        assert "`piv pin unblock`" in hint
    else:
        assert "no recovery path" in hint
    assert "now blocked" not in human
    assert f"The {verifier} is blocked" in human and "status" in human


def test_6983_names_a_reader_that_advertises_contactless(monkeypatch, mock_connection):
    args, apdu, env, _ = COMMANDS[0].values
    _wire(monkeypatch, mock_connection, apdu, "6983", reader_name=PICC_READER)
    payload, human = _both(args, env)
    assert payload["hint"].endswith(f"Reader '{PICC_READER}' advertises a contactless interface.")
    assert "ACR1552" in human and "advertises" in human
