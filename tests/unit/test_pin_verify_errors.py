"""`_check_pin_verify` must not claim a blocked PIN unless the card actually said so.

Only 63C0 (retry counter exhausted) proves it. 6983 is also returned when the PIN
cannot be used for the operation at hand - e.g. a key slot the profile never
populated - so asserting "PIN is blocked" there sent people to `pin unblock` for a
card whose PIN was fine.
"""

from __future__ import annotations

import pytest

from cryptnox_id_cli.cli.commands.piv import _check_pin_verify
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError


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
    assert "either the PIN is blocked, or" in msg  # hedged, both causes named
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
