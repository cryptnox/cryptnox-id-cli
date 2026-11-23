# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv pin change``, ``unblock``, ``verify`` and ``status`` and ``puk change``: what is sent,
and what each answer prints."""

from __future__ import annotations

import json

import pytest
from _cardfakes import QueueConn, run_both_modes, wire_session

SELECT_PIV = "00A404000BA00000030800001000010000"
#: The applet's status object read back over contact (no tag 86), and a refused read.
CONTACT_STATUS = (bytes.fromhex("5306800107860100"), 0x90, 0x00)
NO_STATUS = (b"", 0x6A, 0x82)


def _pad(v: str) -> str:
    return v.encode().hex().upper().ljust(16, "F")


@pytest.fixture
def card(monkeypatch, acs_transcript):
    apt = bytes.fromhex(acs_transcript["exchanges"][SELECT_PIV].split("|")[0])

    def _wire(*replies, reader="Fake Reader 00 00"):
        """Two runs (JSON, human) of SELECT then the given replies."""
        conn = QueueConn([(apt, 0x90, 0x00), *replies] * 2)
        wire_session(monkeypatch, conn, reader_name=reader)
        return conn

    return _wire


CHANGE = [
    pytest.param(
        ["pin", "change", "--old-pin", "1234", "--new-pin", "567890"],
        "00240080",
        "1234",
        "567890",
        "PIN",
        "piv pin unblock",
        id="pin-change",
    ),
    pytest.param(
        ["pin", "unblock", "--puk", "12345678", "--new-pin", "567890"],
        "002C0080",
        "12345678",
        "567890",
        "PIN",
        "no recovery path",
        id="pin-unblock",
    ),
    pytest.param(
        ["puk", "change", "--old-puk", "12345678", "--new-puk", "87654321"],
        "00240081",
        "12345678",
        "87654321",
        "PUK",
        "no recovery path",
        id="puk-change",
    ),
]


@pytest.mark.parametrize(("args", "header", "old", "new", "label", "hint"), CHANGE)
@pytest.mark.parametrize(
    ("sw", "changed", "retries", "blocked"),
    [
        (0x9000, True, None, False),
        (0x63C2, False, 2, False),
        (0x63C0, False, None, False),
        (0x6983, False, None, True),
    ],
    ids=["ok", "wrong", "no-retry-limit", "blocked-over-contact"],
)
def test_change_secret(card, args, header, old, new, label, hint, sw, changed, retries, blocked):
    extra = [CONTACT_STATUS] if sw == 0x6983 else []
    conn = card((b"", sw >> 8, sw & 0xFF), *extra)
    as_json, human = run_both_modes(["piv", *args])
    assert conn.sent[1].hex().upper() == f"{header}10{_pad(old)}{_pad(new)}"
    payload = json.loads(as_json.stdout)
    assert payload["changed"] is changed and payload["sw"] == f"{sw:04X}"
    assert payload.get("retries_remaining") == retries
    assert payload.get("blocked", False) is blocked
    assert (hint in payload.get("recovery", "")) is blocked
    if changed:
        assert f"{label} changed." in human.output
    else:
        assert f"{label} not changed:" in human.output and f"(SW={sw:04X})" in human.output
        assert (hint in human.output) is blocked


@pytest.mark.parametrize(
    ("sw", "reader", "verified", "expect"),
    [
        (0x9000, "Fake Reader 00 00", True, "PIN verified."),
        (0x63C1, "Fake Reader 00 00", False, "1 attempt(s) remaining"),
        (0x6982, "ACS ACR1552 1S CL Reader PICC 0", False, "advertises a contactless interface"),
    ],
    ids=["ok", "wrong", "contactless"],
)
def test_pin_verify(card, sw, reader, verified, expect):
    extra = [NO_STATUS] if sw == 0x6982 else []
    conn = card((b"", sw >> 8, sw & 0xFF), *extra, reader=reader)
    as_json, human = run_both_modes(["piv", "pin", "verify", "--pin", "1234"])
    assert conn.sent[1].hex().upper() == f"0020008008{_pad('1234')}"
    payload = json.loads(as_json.stdout)
    assert payload["verified"] is verified and payload["sw"] == f"{sw:04X}"
    assert ("retries_remaining" in payload) is (sw == 0x63C1)
    assert expect in payload["message"] or verified
    assert expect in human.output.replace("\n", " ")


@pytest.mark.parametrize(
    ("pin_sw", "puk_sw", "lines"),
    [
        (0x63C3, 0x6983, ["PIN (80): 3 tries left", "PUK (81): blocked"]),
        (0x6A88, 0x9000, ["PIN (80): not configured", "PUK (81): configured"]),
        (0x6982, 0x6982, ["not usable over this interface", "contact-only"]),
    ],
    ids=["tries-blocked", "unset-verified", "refused"],
)
def test_pin_status_human(card, pin_sw, puk_sw, lines):
    status = {0x6983: [CONTACT_STATUS], 0x6982: [NO_STATUS]}.get(puk_sw, [])
    card((b"", pin_sw >> 8, pin_sw & 0xFF), (b"", puk_sw >> 8, puk_sw & 0xFF), *status)
    as_json, human = run_both_modes(["piv", "pin", "status"])
    assert as_json.exit_code == 0 and human.exit_code == 0
    assert ("note" in json.loads(as_json.stdout)) is (pin_sw == 0x6982)
    text = " ".join(human.output.split())
    for line in lines:
        assert line in text
