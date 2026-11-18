# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""A card without the genuineness applet: what `genuine` and the detector say."""

from __future__ import annotations

import contextlib
import json

import pytest
from click.testing import CliRunner

from cryptnox_id_cli.applets.genuine.genuine import GenuinenessApplet
from cryptnox_id_cli.cli.commands import genuine as genuine_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import CardState, FidoState, GenuinenessState
from cryptnox_id_cli.transport.errors import AppletNotFoundError
from cryptnox_id_cli.transport.pcsc import CardSession


class _Session:
    def __init__(self, reader_name: str, atr: bytes) -> None:
        self.reader_name = reader_name
        self.atr = atr


@pytest.mark.parametrize(
    ("reader", "atr", "reason", "text"),
    [
        (
            "ACS ACR39U ICC Reader 00 00",
            bytes.fromhex("3BFA1300008131FE454A434F5033"),
            "not_on_card",
            "FIDO2 attestation",
        ),
        (
            "ACS ACR1552 1S CL Reader PICC 0",
            bytes.fromhex("3B8180018080"),
            "contactless",
            "contact reader",
        ),
    ],
)
@pytest.mark.parametrize("command", ["info", "verify"])
def test_not_found_says_why(monkeypatch, reader, atr, reason, text, command):
    @contextlib.contextmanager
    def session(self):
        yield _Session(reader, atr)

    def not_found(self):
        raise AppletNotFoundError("not found")

    monkeypatch.setattr(AppContext, "open_session", session)
    monkeypatch.setattr(GenuinenessApplet, "select", not_found)
    result = CliRunner().invoke(root, ["--json", "genuine", command])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["reason"] == reason
    human = CliRunner().invoke(root, ["genuine", command])
    assert text in " ".join(human.output.split())


@pytest.mark.parametrize(
    ("fido", "noted"), [(FidoState.PERSONALIZED, True), (FidoState.NOT_PRESENT, False)]
)
def test_detector_points_a_fido2_card_at_fido2_attestation(mock_connection, fido, noted):
    detector = StateDetector(CardSession(mock_connection("3B00", {}, [])))
    st = CardState(fido=fido)
    detector._detect_genuineness(st)
    assert st.genuine == GenuinenessState.NOT_PRESENT
    assert any("FIDO2 attestation" in n for n in st.notes) is noted


def test_the_hint_names_fido2_attestation():
    assert "FIDO2 attestation" in genuine_cmd.FIDO2_ATTESTATION_HINT


def test_a_contactless_reader_without_a_desfire_answer_is_still_contactless(mock_connection):
    from cryptnox_id_cli.state.model import DesfireState

    detector = StateDetector(CardSession(mock_connection("3B00", {}, [])))
    st = CardState(fido=FidoState.PERSONALIZED, desfire=DesfireState.NO_ANSWER_CONTACTLESS)
    detector._detect_genuineness(st)
    assert st.genuine == GenuinenessState.NEEDS_CONTACT_READER
    assert not any("FIDO2 attestation" in n for n in st.notes)


def test_a_card_that_left_the_field_still_gets_an_answer(monkeypatch):
    class _Gone:
        reader_name = "ACS ACR39U ICC Reader 00 00"

        @property
        def atr(self):
            raise RuntimeError("Failed to get status: The smart card has been removed")

    @contextlib.contextmanager
    def session(self):
        yield _Gone()

    def not_found(self):
        raise AppletNotFoundError("not found")

    monkeypatch.setattr(AppContext, "open_session", session)
    monkeypatch.setattr(GenuinenessApplet, "select", not_found)
    result = CliRunner().invoke(root, ["--json", "genuine", "info"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["reason"] == "not_on_card"
