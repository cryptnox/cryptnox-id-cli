# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""`_check_pin_verify` must not claim a blocked PIN unless the card actually said so.

Only 63C0 (retry counter exhausted) proves it. The card also answers 6983 over a
contactless reader once the PIN's contactless limit is reached, with contact tries left.
"""

from __future__ import annotations

import pytest
from _cardfakes import RecordingConn, run_both_modes, wire_session

from cryptnox_id_cli.cli.commands.piv import _check_pin_verify
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession

SELECT_PIV = "00A404000BA00000030800001000010000"
VERIFY_123456 = "0020008008313233343536FFFF"
PICC_ATR = "3B8180018080"  # PC/SC-composed contactless ATR
PICC_READER = "ACS ACR1552 1S CL Reader PICC 0"


class _Resp:
    def __init__(self, sw: int) -> None:
        self.sw = sw
        self.sw1 = sw >> 8
        self.sw2 = sw & 0xFF
        self.ok = sw == 0x9000


def test_success_does_not_raise():
    _check_pin_verify(_Resp(0x9000))


def test_exhausted_counter_states_blocked_and_names_the_puk_path():
    with pytest.raises(CryptnoxError) as exc:
        _check_pin_verify(_Resp(0x63C0))  # 0 tries remaining
    msg = str(exc.value)
    assert "blocked" in msg and "0 tries" in msg
    assert "pin unblock" in msg


def test_6983_does_not_assert_a_blocked_pin():
    # The regression: 6983 used to say "PIN is blocked" outright.
    with pytest.raises(CryptnoxError) as exc:
        _check_pin_verify(_Resp(0x6983))
    msg = str(exc.value)
    assert "The PIN is blocked, or" in msg  # hedged, both causes named
    assert "pin status" in msg  # non-decrementing check offered first


def test_wrong_pin_with_tries_left_surfaces_the_remaining_count():
    with pytest.raises(StatusWordError) as exc:
        _check_pin_verify(_Resp(0x63C5))
    msg = str(exc.value)
    assert "5 attempt(s) remaining" in msg
    assert "blocked" not in msg  # must not imply a blocked PIN


def test_other_failures_stay_generic():
    with pytest.raises(StatusWordError):
        _check_pin_verify(_Resp(0x6A82))


def test_6983_names_the_contactless_limit_and_a_contact_reader():
    with pytest.raises(CryptnoxError) as exc:
        _check_pin_verify(_Resp(0x6983))
    msg = str(exc.value)
    assert "The PIN is blocked, or the card's contactless limit for it is reached" in msg
    assert "`piv pin status` from a contact reader" in msg
    assert "never populated" not in msg


def test_6983_names_a_reader_that_advertises_contactless():
    session = CardSession(RecordingConn(atr=bytes.fromhex(PICC_ATR)), reader_name=PICC_READER)
    with pytest.raises(CryptnoxError) as exc:
        _check_pin_verify(_Resp(0x6983), session)
    assert str(exc.value).endswith(f"Reader '{PICC_READER}' advertises a contactless interface.")


def test_a_pin_protected_read_refused_with_6983_names_both_causes(monkeypatch, mock_connection):
    exchanges = {SELECT_PIV: "|9000", VERIFY_123456: "|6983"}
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []))
    args = ["piv", "objects", "read", "--object", "printed"]
    for result in run_both_modes(args, env={"CRYPTNOX_PIV_PIN": "123456"}):
        assert result.exit_code == 1, result.output
        assert "contactless limit" in result.output
        assert "never populated" not in result.output
