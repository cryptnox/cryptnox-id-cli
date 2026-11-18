# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The ``readers`` command: payload shape and each recommendation branch."""

import json

import pytest
from _cardfakes import run_both_modes

from cryptnox_id_cli.cli.commands import readers as readers_cmd
from cryptnox_id_cli.transport.pcsc import ReaderInfo

CRYPTNOX = "Cryptnox CryptnoxCR 00 00"
ACS_PICC = "ACS ACR1552 1S CL Reader PICC 0"
GENERIC = "Generic Smartcard Reader 00 00"
ATR = bytes.fromhex("3BD518FF8191FE1FC38073C821100A")


@pytest.fixture
def readers(monkeypatch):
    # readers.py binds reader_states only, so wire_pcsc's connect/pick_reader do not apply.
    def _set(*infos):
        monkeypatch.setattr(readers_cmd, "reader_states", lambda: list(infos))

    return _set


def _payload(result):
    return json.loads(result.output)


def test_no_readers_reports_empty_and_recommends_nothing(readers):
    readers()
    js, human = run_both_modes(["readers"])
    assert js.exit_code == 0 and human.exit_code == 0
    assert _payload(js) == {
        "readers": [],
        "recommended_reader": None,
        "preferred_with_card": [],
    }
    assert "No PC/SC readers found" in human.output


def test_single_preferred_reader_with_a_card_is_recommended(readers):
    readers(ReaderInfo(0, CRYPTNOX, True, ATR))
    js, human = run_both_modes(["readers"])
    payload = _payload(js)
    assert payload["recommended_reader"] == CRYPTNOX
    assert payload["preferred_with_card"] == [0]
    assert payload["readers"][0] == {
        "index": 0,
        "name": CRYPTNOX,
        "card_present": True,
        "atr": ATR.hex().upper(),
        "preferred": True,
    }
    assert "--reader 0" in human.output


def test_two_preferred_readers_with_cards_refuses_to_choose(readers):
    # The refusal mirrors select_reader: guessing between a contact and a contactless
    # interface would target the wrong applet.
    readers(ReaderInfo(0, CRYPTNOX, True, ATR), ReaderInfo(1, ACS_PICC, True, ATR))
    js, human = run_both_modes(["readers"])
    payload = _payload(js)
    assert payload["recommended_reader"] is None
    assert payload["preferred_with_card"] == [0, 1]
    assert "Multiple Cryptnox/ACS readers have a card" in human.output
    assert "--reader 0" in human.output and "--reader 1" in human.output


def test_preferred_reader_without_a_card_says_so(readers):
    readers(ReaderInfo(0, CRYPTNOX, False, b""))
    js, human = run_both_modes(["readers"])
    payload = _payload(js)
    assert payload["recommended_reader"] is None
    assert payload["readers"][0]["atr"] is None
    assert "has no card" in human.output


def test_only_a_third_party_reader_asks_for_an_explicit_choice(readers):
    readers(ReaderInfo(0, GENERIC, True, ATR))
    js, human = run_both_modes(["readers"])
    payload = _payload(js)
    assert payload["readers"][0]["preferred"] is False
    assert payload["recommended_reader"] is None
    assert "No Cryptnox/ACS reader detected" in human.output
