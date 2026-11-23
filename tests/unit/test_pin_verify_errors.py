# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""`verifier.require_pin` must not claim a blocked PIN unless the card actually said so.

``6983`` over contact is a block. Without that evidence the card may only have reached
the PIN's contactless limit, with contact tries left. ``63C0`` is a PIN without a retry
limit.
"""

from __future__ import annotations

import pytest
from _cardfakes import run_both_modes, wire_session

from cryptnox_id_cli.applets.piv import verifier
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession

SELECT_PIV = "00A404000BA00000030800001000010000"
VERIFY_123456 = "0020008008313233343536FFFF"
GET_STATUS = "00CB3F00055C032F475300"
PICC_ATR = "3B8180018080"  # PC/SC-composed contactless ATR
PICC_READER = "ACS ACR1552 1S CL Reader PICC 0"


def _require(mock_connection, sw: str, *, atr: str = "3B00", reader=None, status=None):
    exchanges = {VERIFY_123456: f"|{sw}"}
    if status:
        exchanges[GET_STATUS] = f"{status}|9000"
    conn = mock_connection(atr, exchanges, [])
    verifier.require_pin(PivApplet(CardSession(conn, reader_name=reader)), b"123456")


def test_success_does_not_raise(mock_connection):
    _require(mock_connection, "9000")


def test_no_retry_limit_is_not_called_blocked(mock_connection):
    with pytest.raises(CryptnoxError) as exc:
        _require(mock_connection, "63C0")
    msg = str(exc.value)
    assert "no retry limit" in msg and "blocked" not in msg
    assert exc.value.exit_code == 1


def test_6983_over_contact_states_blocked_and_names_the_puk_path(mock_connection):
    with pytest.raises(CryptnoxError) as exc:
        _require(mock_connection, "6983", status="5306800107860100")
    msg = str(exc.value)
    assert "The PIN is blocked." in msg and "pin unblock" in msg
    assert exc.value.exit_code == 1


def test_6983_without_contact_evidence_does_not_assert_a_blocked_pin(mock_connection):
    with pytest.raises(CryptnoxError) as exc:
        _require(mock_connection, "6983")
    msg = str(exc.value)
    assert "The PIN is blocked, or" in msg  # hedged, both causes named
    assert "pin status" in msg  # non-decrementing check offered first


def test_wrong_pin_with_tries_left_surfaces_the_remaining_count(mock_connection):
    with pytest.raises(StatusWordError) as exc:
        _require(mock_connection, "63C5")
    msg = str(exc.value)
    assert "5 attempt(s) remaining" in msg
    assert "blocked" not in msg  # must not imply a blocked PIN


def test_other_failures_stay_generic(mock_connection):
    with pytest.raises(StatusWordError):
        _require(mock_connection, "6A82")


def test_6983_names_the_contactless_limit_and_a_contact_reader(mock_connection):
    with pytest.raises(CryptnoxError) as exc:
        _require(mock_connection, "6983")
    msg = str(exc.value)
    assert "The PIN is blocked, or the card's contactless limit for it is reached" in msg
    assert "`piv pin status` from a contact reader" in msg
    assert "never populated" not in msg


def test_6983_names_a_reader_that_advertises_contactless(mock_connection):
    with pytest.raises(CryptnoxError) as exc:
        _require(mock_connection, "6983", atr=PICC_ATR, reader=PICC_READER)
    assert str(exc.value).endswith(f"Reader '{PICC_READER}' advertises a contactless interface.")


def test_a_pin_protected_read_refused_with_6983_names_both_causes(monkeypatch, mock_connection):
    exchanges = {SELECT_PIV: "|9000", VERIFY_123456: "|6983"}
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []))
    args = ["piv", "objects", "read", "--object", "printed"]
    for result in run_both_modes(args, env={"CRYPTNOX_PIV_PIN": "123456"}):
        assert result.exit_code == 1, result.output
        assert "contactless limit" in result.output
        assert "never populated" not in result.output
