# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What ``pin change``, ``pin unblock`` and ``puk change`` read into the card's answer.

``63C0`` comes from a verifier with no retry limit, never a block. ``6983`` is a block
over contact; over contactless, or when the interface is not known, it may only be the
verifier's contactless limit while contact tries remain.
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


GET_STATUS = "00CB3F00055C032F475300"
CONTACT_STATUS = "5306800107860100"


def _wire(
    monkeypatch,
    mock_connection,
    apdu: str,
    sw: str,
    reader_name: str | None = None,
    status: str | None = None,
):
    exchanges = {SELECT_PIV: f"{APT}|9000", apdu: f"|{sw}"}
    if status:
        exchanges[GET_STATUS] = f"{status}|9000"
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []), reader_name=reader_name)


def _both(args, env):
    as_json, human = run_both_modes(args, env=env)
    return json.loads(as_json.stdout), human.output


@pytest.mark.parametrize(("args", "apdu", "env", "verifier"), COMMANDS)
def test_63c0_is_a_verifier_without_a_retry_limit(
    monkeypatch, mock_connection, args, apdu, env, verifier
):
    _wire(monkeypatch, mock_connection, apdu, "63C0")
    payload, human = _both(args, env)
    assert payload["changed"] is False
    assert not {"blocked", "recovery", "retries_remaining", "hint"} & payload.keys()
    assert payload["message"] == f"Verification failed; this {verifier} has no retry limit."
    assert "is blocked" not in human and "now blocked" not in human


@pytest.mark.parametrize(("args", "apdu", "env", "verifier"), COMMANDS)
def test_6983_over_contact_is_a_block_with_its_recovery(
    monkeypatch, mock_connection, args, apdu, env, verifier
):
    _wire(monkeypatch, mock_connection, apdu, "6983", status=CONTACT_STATUS)
    payload, human = _both(args, env)
    assert payload["changed"] is False
    assert payload["blocked"] is True and "hint" not in payload
    assert payload["message"] == f"The {verifier} is blocked."
    recovery = "`piv pin unblock`" if verifier == "PIN" else "no recovery path"
    assert recovery in payload["recovery"] and recovery in human


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
    assert payload["message"] == f"No {verifier} tries left over this interface."
    hint = payload["hint"]
    assert hint.startswith(f"The {verifier} is blocked, or ")
    assert "`piv pin status`" in hint
    if verifier == "PIN":
        assert "`piv pin unblock`" in hint
    else:
        assert "no recovery path" in hint
    assert f"The {verifier} is blocked, or" in human and "status" in human


def test_6983_names_a_reader_that_advertises_contactless(monkeypatch, mock_connection):
    args, apdu, env, _ = COMMANDS[0].values
    _wire(monkeypatch, mock_connection, apdu, "6983", reader_name=PICC_READER)
    payload, human = _both(args, env)
    assert payload["hint"].endswith(f"Reader '{PICC_READER}' advertises a contactless interface.")
    assert "ACR1552" in human and "advertises" in human


@pytest.mark.parametrize(("args", "apdu", "env", "verifier"), COMMANDS)
def test_6983_hint_says_to_check_from_a_contact_reader(
    monkeypatch, mock_connection, args, apdu, env, verifier
):
    _wire(monkeypatch, mock_connection, apdu, "6983")
    payload, _ = _both(args, env)
    assert "`piv pin status` from a contact reader" in payload["hint"]
