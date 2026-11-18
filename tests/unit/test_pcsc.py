# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The pyscard boundary: reader enumeration, connect() and the exception mapping.

pyscard is substituted at its own module attributes, so pcsc.py runs unmodified, and
a command run through AppContext.open_session reaches the double through the real
pick_reader/connect path rather than through wire_session.
"""

from __future__ import annotations

import json

import pytest
import smartcard.scard as scard
import smartcard.System
from _cardfakes import QueueConn, RecordingConn, run, run_both_modes
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException, NoCardException

from cryptnox_id_cli.transport import pcsc
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import (
    CardAccessDeniedError,
    NoCardError,
    ReaderNotFoundError,
    TransportError,
)

CONTEXT = 0xC0FFEE
ACS = "ACS ACR39U ICC Reader 00 00"
PICC = "ACS ACR1552 1S CL Reader PICC 0"
GENERIC = "Generic Smartcard Reader 00 00"
ATR = bytes.fromhex("3BFA1300008131FE454A434F503331")
NO_ACCESS = 0x80100027


class FakeScard:
    """pyscard's SCard* calls over a reader table of ``name -> ATR`` (``None``: no card)."""

    def __init__(self, table, *, establish=scard.SCARD_S_SUCCESS, listed=scard.SCARD_S_SUCCESS):
        self.table = table
        self.establish = establish
        self.listed = listed
        self.released: list[int] = []
        self.polled = None

    def install(self, monkeypatch):
        monkeypatch.setattr(scard, "SCardEstablishContext", lambda scope: (self.establish, CONTEXT))
        monkeypatch.setattr(
            scard, "SCardListReaders", lambda ctx, groups: (self.listed, list(self.table))
        )
        monkeypatch.setattr(scard, "SCardGetStatusChange", self._status)
        monkeypatch.setattr(scard, "SCardReleaseContext", self.released.append)
        return self

    def _status(self, ctx, timeout, states):
        self.polled = (timeout, states)
        out = []
        for name, _ in states:
            atr = self.table[name]
            state = (
                scard.SCARD_STATE_PRESENT | scard.SCARD_STATE_CHANGED
                if atr
                else scard.SCARD_STATE_EMPTY
            )
            out.append((name, state, list(atr or b"")))
        return scard.SCARD_S_SUCCESS, out


class FakeCardConnection:
    """A pyscard CardConnection; ``connect`` raises the queued errors in turn."""

    def __init__(self, card, *, errors=()):
        self.card = card
        self.errors = list(errors)
        self.protocols: list[int | None] = []

    def connect(self, protocol=None):
        self.protocols.append(protocol)
        if self.errors:
            raise self.errors.pop(0)

    def transmit(self, apdu):
        return self.card.transmit(apdu)

    def getATR(self):  # noqa: N802 - pyscard's name
        return list(ATR)

    def disconnect(self):
        pass


class FakeReader:
    def __init__(self, name, conn):
        self.name, self.conn = name, conn

    def __str__(self):
        return self.name

    def createConnection(self):  # noqa: N802 - pyscard's name
        return self.conn


@pytest.fixture
def plug(monkeypatch):
    """Put readers on the bus: ``plug({name: (atr, FakeCardConnection)})``."""

    def _plug(readers, **scard_kwargs):
        fake = FakeScard({n: atr for n, (atr, _) in readers.items()}, **scard_kwargs)
        fake.install(monkeypatch)
        objs = [FakeReader(n, conn) for n, (_, conn) in readers.items()]
        monkeypatch.setattr(smartcard.System, "readers", lambda: objs)
        return fake

    return _plug


def test_reader_states_reports_presence_and_atr_then_releases_the_context(plug):
    fake = plug({ACS: (ATR, None), PICC: (None, None)})
    infos = pcsc.reader_states()
    assert infos == [pcsc.ReaderInfo(0, ACS, True, ATR), pcsc.ReaderInfo(1, PICC, False, b"")]
    assert fake.polled == (0, [(ACS, scard.SCARD_STATE_UNAWARE), (PICC, scard.SCARD_STATE_UNAWARE)])
    assert fake.released == [CONTEXT]


def test_reader_states_without_the_pcsc_service_explains_how_to_start_it(plug):
    fake = plug({}, establish=scard.SCARD_E_NO_SERVICE)
    with pytest.raises(TransportError, match="start pcscd"):
        pcsc.reader_states()
    assert fake.released == []


@pytest.mark.parametrize("listed", [scard.SCARD_E_NO_READERS_AVAILABLE, scard.SCARD_S_SUCCESS])
def test_no_readers_is_an_empty_list_and_still_releases(plug, listed):
    fake = plug({}, listed=listed)
    assert pcsc.reader_states() == []
    assert fake.released == [CONTEXT]


def test_connect_uses_the_default_protocol_and_adapts_the_connection(plug):
    card = RecordingConn(([0xAB], 0x90, 0x00))
    conn = FakeCardConnection(card)
    plug({ACS: (ATR, conn)})
    pc = pcsc.connect(ACS)
    assert conn.protocols == [None]
    assert pc.transmit([0x00, 0xCA, 0x00, 0x00]) == ([0xAB], 0x90, 0x00)
    assert pc.get_atr() == ATR
    assert card.frames == [bytes.fromhex("00CA0000")]


def test_connect_to_an_unknown_reader_is_reader_not_found(plug):
    plug({ACS: (ATR, FakeCardConnection(RecordingConn()))})
    with pytest.raises(ReaderNotFoundError, match="Reader not found: Nope"):
        pcsc.connect("Nope")


def test_connect_without_a_card_is_no_card(plug):
    plug({ACS: (None, FakeCardConnection(None, errors=[NoCardException("no card", hresult=-1)]))})
    with pytest.raises(NoCardError, match="No card present"):
        pcsc.connect(ACS)


def test_connect_refused_by_the_os_is_access_denied_with_the_hresult(plug):
    refused = CardConnectionException("Unable to connect", hresult=NO_ACCESS)
    conn = FakeCardConnection(None, errors=[refused])
    plug({ACS: (ATR, conn)})
    with pytest.raises(CardAccessDeniedError) as exc:
        pcsc.connect(ACS)
    assert exc.value.hresult == NO_ACCESS
    assert conn.protocols == [None]  # no protocol fallback after an OS refusal


@pytest.mark.parametrize(
    ("failures", "tried"),
    [
        (1, [None, CardConnection.T1_protocol]),
        (2, [None, CardConnection.T1_protocol, CardConnection.T0_protocol]),
    ],
)
def test_connect_falls_back_to_t1_then_t0(plug, failures, tried):
    conn = FakeCardConnection(
        RecordingConn(), errors=[CardConnectionException("proto mismatch")] * failures
    )
    plug({ACS: (ATR, conn)})
    assert isinstance(pcsc.connect(ACS), pcsc.PCSCConnection)
    assert conn.protocols == tried


def test_connect_gives_up_when_every_protocol_fails(plug):
    conn = FakeCardConnection(None, errors=[CardConnectionException("mute card")] * 3)
    plug({ACS: (ATR, conn)})
    with pytest.raises(TransportError, match="Cannot connect to card in .*mute card"):
        pcsc.connect(ACS)


class _Raises:
    def __init__(self, exc):
        self.exc = exc

    def transmit(self, apdu):
        raise self.exc


@pytest.mark.parametrize(
    ("exc", "expected", "message"),
    [
        (CardConnectionException("x", hresult=NO_ACCESS), CardAccessDeniedError, "0x80100027"),
        (CardConnectionException("Card was removed."), TransportError, "APDU transmit failed"),
    ],
)
def test_transmit_errors_are_mapped(exc, expected, message):
    with pytest.raises(expected, match=message) as info:
        pcsc.PCSCConnection(_Raises(exc)).transmit([0x00, 0xA4, 0x04, 0x00])
    assert type(info.value) is expected


def test_wrong_le_is_resent_with_the_length_the_card_asked_for():
    conn = QueueConn([([], 0x6C, 0x10), (bytes(16), 0x90, 0x00)])
    resp = pcsc.CardSession(conn).transmit(APDU(0x80, 0xCA, 0x9F, 0x7F, le=256))
    assert resp.ok and resp.data == bytes(16)
    assert [f.hex().upper() for f in conn.sent] == ["80CA9F7F00", "80CA9F7F10"]


def test_chained_send_stops_at_the_first_refused_block():
    conn = QueueConn([([], 0x6A, 0x80)])
    resp = pcsc.CardSession(conn).transmit_chained(
        APDU(0x00, 0xDB, 0x3F, 0xFF, data=bytes(300)), block_size=200
    )
    assert resp.sw == 0x6A80
    assert len(conn.sent) == 1 and conn.sent[0][0] == 0x10  # chaining bit, never the last block


def test_a_command_reaches_the_card_through_the_real_pcsc_path(plug):
    card = RecordingConn(([0x01, 0x02], 0x90, 0x00))
    plug({GENERIC: (ATR, FakeCardConnection(card))})  # the only reader, though not preferred
    js, human = run_both_modes(["apdu", "send", "--hex", "80CA9F7F00"])
    assert js.exit_code == 0 and human.exit_code == 0, human.output
    assert json.loads(js.stdout)["data"] == "0102"
    assert "SW:   9000" in human.stdout
    assert card.frames == [bytes.fromhex("80CA9F7F00")] * 2


def test_verbose_traces_the_apdus_on_stderr(plug):
    plug({ACS: (ATR, FakeCardConnection(RecordingConn()))})
    result = run(["--verbose", "apdu", "send", "--hex", "00A4040000"])
    assert result.exit_code == 0, result.output
    assert "apdu > 00A4040000" in result.stderr
    assert "apdu < 9000" in result.stderr


def test_two_preferred_readers_without_a_card_refuse_to_guess(plug):
    plug({ACS: (None, None), PICC: (None, None)})
    js, human = run_both_modes(["apdu", "send", "--hex", "00A4040000"])
    assert js.exit_code == human.exit_code == 3
    payload = json.loads(js.stdout)
    assert payload["error"] == "reader_not_found"
    assert "none with a card" in payload["message"]
    assert "pass --reader" in human.output
