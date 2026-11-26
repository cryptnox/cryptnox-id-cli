# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""A PIV object whose read fails is unknown, not absent, and the quickstart planner does
not plan a write over an object it could not read."""

from __future__ import annotations

import json

import pytest
from _cardfakes import ResponseAdapter, run, wire_session
from test_detector_failures import GET_CHUID, detect
from test_piv_preperso_commands import PivAdminCard
from test_quickstart import OPTS, _facts
from test_state_detector import APT, SELECT_PIV

from cryptnox_id_cli.cli.commands.piv.quickstart.plan import _plan_quickstart
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.errors import CryptnoxError, TransportError


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ((b"", 0x6A, 0x82), False),
        ((b"\x53\x00", 0x90, 0x00), False),
        ((b"", 0x69, 0x82), True),
        ((b"", 0x6F, 0x00), None),
        (TransportError("glitch"), None),
    ],
    ids=["not-created", "empty", "access-gated", "unexpected-sw", "transport-error"],
)
def test_the_detector_keeps_an_unread_object_apart_from_an_absent_one(answer, expected):
    st, _ = detect(
        {SELECT_PIV: (bytes.fromhex(APT), 0x90, 0x00), GET_CHUID: answer},
        probe_fido=False,
        probe_desfire=False,
        probe_genuine=False,
    )
    assert st.piv_objects["chuid"] is expected


@pytest.mark.parametrize(("name", "field"), [("CHUID", "chuid_present"), ("CCC", "ccc_present")])
def test_the_planner_refuses_to_write_over_an_object_it_could_not_read(name, field):
    with pytest.raises(CryptnoxError, match=f"could not read the card's {name}"):
        _plan_quickstart(_facts(**{field: None}), OPTS)


class UnreadChuidCard(PivAdminCard):
    def transmit(self, apdu):
        if bytes(apdu).hex().upper() == GET_CHUID:
            return Response(b"", 0x6F, 0x00)
        return super().transmit(apdu)


def test_status_shows_an_unread_object_as_unknown(monkeypatch):
    wire_session(monkeypatch, ResponseAdapter(UnreadChuidCard()))
    as_json = run(["--json", "piv", "status"])
    assert json.loads(as_json.stdout)["objects_present"]["chuid"] is None
    human = run(["piv", "status"])
    (row,) = [line for line in human.output.splitlines() if "chuid" in line]
    assert "unknown" in row
