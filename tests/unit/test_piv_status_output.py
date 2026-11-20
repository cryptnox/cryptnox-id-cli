# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv status``: the finalize state and the PIN and PUK lines it prints."""

from __future__ import annotations

import json

import pytest
from _cardfakes import ResponseAdapter, run_both_modes, wire_session
from test_factory_preperso_commands import PivAdminCard

from cryptnox_id_cli.transport.apdu import Response


class PinCard(PivAdminCard):
    """Answers the empty VERIFY for PIN (80) and PUK (81) with a chosen status word."""

    def __init__(self, pin_sw=None, **kw):
        super().__init__(**kw)
        self.pin_sw = pin_sw or {}

    def transmit(self, apdu):
        raw = bytes(apdu)
        if raw[:2] == b"\x00\x20" and len(raw) == 4 and raw[3] in self.pin_sw:
            return Response(b"", *self.pin_sw[raw[3]])
        return super().transmit(raw)


def _status(monkeypatch, **kw):
    wire_session(monkeypatch, ResponseAdapter(PinCard(**kw)))
    as_json, human = run_both_modes(["piv", "status"])
    assert as_json.exit_code == 0, as_json.output
    return json.loads(as_json.stdout), " ".join(human.output.split())


@pytest.mark.parametrize(
    ("secured", "line"),
    [
        (True, "Structure: finalized (SECURED), no further pre-personalization"),
        (False, "Structure: not finalized"),
    ],
    ids=["finalized", "open"],
)
def test_status_names_the_finalize_state(monkeypatch, secured, line):
    payload, text = _status(monkeypatch, secured=secured)
    assert payload["secured"] is secured
    assert line in text


def test_status_shows_tries_left_and_a_blocked_puk(monkeypatch):
    payload, text = _status(monkeypatch, pin_sw={0x80: (0x63, 0xC3), 0x81: (0x69, 0x83)})
    assert payload["pin"]["retries_remaining"] == 3 and payload["puk"]["blocked"] is True
    assert "PIN (80): set, 3 tries left" in text
    assert "PUK (81): set, 0 tries left (blocked)" in text


def test_status_without_a_piv_applet_prints_no_pin_lines(monkeypatch):
    payload, text = _status(monkeypatch, present=False)
    assert payload["state"] == "PivNotPresent" and payload["pin"] is None
    assert "Structure: finalize state not readable" in text
    assert "PIN (80)" not in text and "PUK (81)" not in text
