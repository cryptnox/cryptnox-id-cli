# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``mifare app delete`` reports an application deleted once the card no longer finds it.

The card answers DeleteApplication with a bare OK, without a MAC even in an
authenticated session, because deleting the selected application ends the session.
The CLI then selects the AID and expects APPLICATION_NOT_FOUND.
"""

from __future__ import annotations

import pytest
from _cardfakes import QueueConn, run, wire_session
from test_ev2 import RNDB, FakeEv2Card

from cryptnox_id_cli.applets.mifare import desfire as df
from cryptnox_id_cli.applets.mifare import ev2

AID = "010203"
SELECT_AID = bytes.fromhex("905A000003" + AID + "00")
DELETE = ["--yes", "--json", "mifare", "app", "delete", "--aid", AID]
MODES = [pytest.param([], id="plain"), pytest.param(["--zero-key"], id="authenticated")]


class _AppCard(FakeEv2Card):
    """Holds one application; ``relay=True`` answers DeleteApplication without deleting it."""

    def __init__(self, *, relay: bool = False) -> None:
        super().__init__(bytes(16), RNDB, ti=bytes.fromhex("A1B2C3D4"))
        self.relay = relay
        self.present = True
        self.sent: list[bytes] = []

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.sent.append(raw)
        if raw[1] in (ev2.CMD_AUTHENTICATE_EV2_FIRST, ev2.CMD_ADDITIONAL_FRAME):
            return super().transmit(apdu)
        if raw[1] == df.CMD_SELECT_APPLICATION:
            return [], 0x91, (0x00 if self.present else 0xA0)
        if raw[1] == df.CMD_DELETE_APPLICATION:
            if not self.relay:
                self.present = False
                self.rnda = None
            return [], 0x91, 0x00
        return [], 0x91, 0x1C


@pytest.mark.parametrize("mode", MODES)
def test_deleted_is_reported_once_the_application_no_longer_selects(monkeypatch, mode):
    card = _AppCard()
    wire_session(monkeypatch, card)
    result = run([*DELETE, *mode])
    assert result.exit_code == 0, result.output
    assert '"deleted": true' in result.output
    assert not card.present
    assert card.sent[-1] == SELECT_AID


@pytest.mark.parametrize("mode", MODES)
def test_an_ok_that_left_the_application_in_place_is_an_error(monkeypatch, mode):
    card = _AppCard(relay=True)
    wire_session(monkeypatch, card)
    result = run([*DELETE, *mode])
    assert result.exit_code == 1, result.output
    assert f"application {AID} still selects" in result.output
    assert '"deleted"' not in result.output
    assert card.present


def test_any_other_answer_to_the_check_is_a_desfire_error(monkeypatch):
    wire_session(monkeypatch, QueueConn([(b"", 0x91, 0x00), (b"", 0x91, 0x1C)]))
    result = run(DELETE)
    assert result.exit_code == df.DesfireError.exit_code, result.output
    assert "SelectApplication" in result.output and "ILLEGAL_COMMAND_CODE" in result.output
