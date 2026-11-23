# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The detector's promise: one failing probe never aborts the others, and each applet
whose probe fails is reported as unknown with the reason, never as absent."""

from __future__ import annotations

import cbor2
import pytest
from test_state_detector import APT, SELECT_PIV

from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import DesfireState, FidoState, GenuinenessState, PivState
from cryptnox_id_cli.transport.errors import TransportError
from cryptnox_id_cli.transport.pcsc import CardSession

GET_VERSION = "9060000000"
SELECT_FIDO = "00A4040008A0000006472F000100"
GET_INFO = "80100000010400"
SELECT_GENUINE = "00A4040008A00000100002470100"
SELECT_DEFAULT = "00A4040000"
GET_CHUID = "00CB3FFF055C035FC10200"
GET_PRINTED = "00CB3FFF055C035FC10900"
REFUSED = (b"", 0x69, 0x85)
FIDO_OK = (b"FIDO_2_0", 0x90, 0x00)
VERSION = bytes.fromhex("04010112001A0504010102011A0504A1B2C3D4E5F6BA1C0B2D3E2324")


class ScriptedCard:
    """Answers by exact command hex; a scripted exception is raised instead. Else 6A82."""

    def __init__(self, script):
        self.script = script
        self.sent: list[str] = []

    def transmit(self, apdu):
        key = bytes(apdu).hex().upper()
        self.sent.append(key)
        reply = self.script.get(key, (b"", 0x6A, 0x82))
        if isinstance(reply, BaseException):
            raise reply
        data, sw1, sw2 = reply
        return list(data), sw1, sw2

    def get_atr(self):
        return b"\x3b\x00"

    def disconnect(self):
        pass


def detect(script, **probes):
    card = ScriptedCard(script)
    return StateDetector(CardSession(card), **probes).detect(), card


def test_every_probe_failing_differently_still_yields_a_verdict_for_each_applet():
    st, _ = detect(
        {
            GET_VERSION: (bytes(10), 0x91, 0x00),  # too short to be a GetVersion answer
            SELECT_PIV: REFUSED,
            SELECT_FIDO: TransportError("reader hiccup"),
            SELECT_GENUINE: REFUSED,
        }
    )
    assert (st.desfire, st.piv, st.fido, st.genuine) == (
        DesfireState.UNKNOWN,
        PivState.UNKNOWN,
        FidoState.UNKNOWN,
        GenuinenessState.UNKNOWN,
    )
    assert "DESFire probe failed; state unknown." in st.notes
    assert any(n.startswith("PIV select error:") and "6985" in n for n in st.notes)
    assert "FIDO2 select error: reader hiccup" in st.notes
    assert any(n.startswith("Genuineness select error:") and "6985" in n for n in st.notes)


def test_desfire_that_answers_get_version_is_reachable_with_its_version():
    st, _ = detect({GET_VERSION: (VERSION, 0x91, 0x00)}, probe_fido=False, probe_genuine=False)
    assert st.desfire == DesfireState.REACHABLE
    assert st.desfire_version["vendor"] == "NXP"
    assert st.desfire_version["uid"] == "04A1B2C3D4E5F6"


@pytest.mark.parametrize(
    ("script", "state", "versions", "note"),
    [
        ({SELECT_FIDO: REFUSED}, FidoState.UNKNOWN, None, "FIDO2 select returned SW=6985."),
        (
            {SELECT_FIDO: FIDO_OK, GET_INFO: TransportError("lost")},
            FidoState.SELECTABLE,
            None,
            "CTAP getInfo error: lost",
        ),
        (
            {
                SELECT_FIDO: FIDO_OK,
                GET_INFO: (b"\x00" + cbor2.dumps({1: ["U2F_V2", "FIDO_2_0"]}), 0x90, 0x00),
            },
            FidoState.PERSONALIZED,
            ["U2F_V2", "FIDO_2_0"],
            None,
        ),
        (
            {SELECT_FIDO: FIDO_OK, GET_INFO: (b"\x00" + cbor2.dumps([1]), 0x90, 0x00)},
            FidoState.PERSONALIZED,
            None,
            None,
        ),
    ],
    ids=["select-refused", "getinfo-fails", "personalized", "personalized-unparsable"],
)
def test_fido_verdicts(script, state, versions, note):
    st, _ = detect(script, probe_desfire=False, probe_genuine=False)
    assert st.fido == state
    assert st.fido_versions == versions
    if note:
        assert note in st.notes


def test_an_object_read_that_fails_does_not_stop_the_other_reads():
    st, card = detect(
        {SELECT_PIV: (bytes.fromhex(APT), 0x90, 0x00), GET_CHUID: TransportError("glitch")},
        probe_fido=False,
        probe_desfire=False,
        probe_genuine=False,
    )
    assert len(st.piv_objects) == 9
    assert card.sent.index(GET_PRINTED) > card.sent.index(GET_CHUID)


def test_the_selection_reset_retries_without_le_when_the_card_wants_case_3():
    st, card = detect({SELECT_DEFAULT: (b"", 0x67, 0x00)}, probe_fido=False, probe_desfire=False)
    i = card.sent.index(SELECT_DEFAULT)
    assert card.sent[i + 1] == "00A40400"
    assert st.genuine == GenuinenessState.NOT_PRESENT


@pytest.mark.parametrize(
    ("puk", "state"),
    [
        ((b"", 0x63, 0xC3), PivState.PARTIALLY_PERSONALIZED),
        (TransportError("gone"), PivState.PARTIALLY_PERSONALIZED),
    ],
    ids=["puk-answers", "puk-probe-fails"],
)
def test_a_failed_puk_probe_keeps_the_pin_and_its_rung(puk, state):
    st, _ = detect(
        {
            SELECT_PIV: (bytes.fromhex(APT), 0x90, 0x00),
            "00200080": (b"", 0x63, 0xC3),
            "00200081": puk,
        },
        probe_fido=False,
        probe_desfire=False,
        probe_genuine=False,
    )
    assert st.piv == state
    assert st.piv_pin is not None and st.piv_pin.retries == 3
    assert (st.piv_puk is None) == isinstance(puk, BaseException)
