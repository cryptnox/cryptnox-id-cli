# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""EV2 secure messaging against cards that misbehave: framing, chaining and MAC refusals."""

from __future__ import annotations

import pytest
from _cardfakes import QueueConn, RecordingConn, ResponseAdapter
from test_ev2 import ChainCard, ChangeKeyCard

from cryptnox_id_cli.applets.mifare import desfire as df
from cryptnox_id_cli.applets.mifare import ev2
from cryptnox_id_cli.applets.mifare.desfire import DesfireError, DesfireTransport
from cryptnox_id_cli.transport.pcsc import CardSession

KEY = bytes(16)
TI = bytes.fromhex("AABBCCDD")


def session(ctr=0):
    return ev2.Ev2Session(k_enc=bytes(range(16)), k_mac=KEY, ti=TI, cmd_ctr=ctr)


def dtx(conn):
    return DesfireTransport(CardSession(conn))


def test_auth_refuses_a_non_aes_key_before_talking_to_the_card():
    conn = QueueConn([])
    with pytest.raises(ev2.Ev2Error, match="16-byte AES key"):
        ev2.authenticate_ev2_first(dtx(conn), 0, bytes(8))
    assert conn.sent == []


@pytest.mark.parametrize(
    ("replies", "error", "message"),
    [
        ([(b"", 0x91, 0xAE)], DesfireError, "AuthenticateEV2First"),
        ([(bytes(8), 0x91, 0xAF)], ev2.Ev2Error, "E\\(RndB\\) length 8"),
        (
            [(bytes(16), 0x91, 0xAF), (bytes(16), 0x91, 0x00)],
            ev2.Ev2Error,
            "final auth response length 16",
        ),
    ],
    ids=["card-refuses", "short-rndb", "short-final"],
)
def test_auth_rejects_malformed_card_answers(replies, error, message):
    with pytest.raises(error, match=message):
        ev2.authenticate_ev2_first(dtx(QueueConn(replies)), 0, KEY)


def test_a_chained_response_is_reassembled_and_mac_checked():
    data = b"\x01\x02\x03\x04"
    mac = session(ctr=1).response_mac(0x00, data)
    conn = QueueConn([(data[:3], 0x91, 0xAF), (data[3:] + mac, 0x91, 0x00)])
    assert ev2.command_macked(dtx(conn), session(), df.CMD_READ_DATA, b"\x01") == data
    assert conn.sent[1].hex().upper() == "90AF000000"


def test_a_card_that_never_stops_asking_for_frames_is_abandoned():
    conn = RecordingConn(([], 0x91, 0xAF))
    with pytest.raises(ev2.Ev2Error, match="kept requesting response frames"):
        ev2.command_macked(dtx(conn), session(), df.CMD_READ_DATA, b"\x01")
    assert len(conn.frames) == 1 + ev2.MAX_RESPONSE_FRAMES


@pytest.mark.parametrize(
    "send",
    [
        lambda t, s: ev2.command_macked(t, s, df.CMD_WRITE_DATA, bytes(40), max_frame=16),
        lambda t, s: ev2.command_full(
            t, s, df.CMD_WRITE_DATA, header=b"\x01", plaintext=bytes(40), max_frame=16
        ),
    ],
    ids=["mac", "full"],
)
def test_a_card_that_stops_requesting_command_frames_is_an_error(send):
    conn = QueueConn([(b"", 0x91, 0x00)])
    with pytest.raises(ev2.Ev2Error, match="did not request command frame 1"):
        send(dtx(conn), session())
    assert len(conn.sent) == 1


def test_a_session_ending_command_may_answer_without_a_mac():
    s = session()
    out = ev2.command_macked(
        dtx(QueueConn([(b"", 0x91, 0x00)])),
        s,
        df.CMD_DELETE_APPLICATION,
        b"\x01\x02\x03",
        terminates_session=True,
    )
    assert out == b"" and s.cmd_ctr == 1


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        ((b"\x01\x02", 0x91, 0x00), "response MAC missing"),
        ((bytes(10), 0x91, 0x00), "MAC verification failed"),
    ],
)
@pytest.mark.parametrize(
    "send",
    [
        lambda t, s: ev2.command_macked(t, s, df.CMD_READ_DATA, b"\x01"),
        lambda t, s: ev2.command_full(t, s, df.CMD_READ_DATA, header=b"\x01"),
    ],
    ids=["mac", "full"],
)
def test_a_bad_response_mac_is_refused(send, reply, message):
    with pytest.raises(ev2.Ev2Error, match=message):
        send(dtx(QueueConn([reply])), session())


def test_full_mode_surfaces_the_card_status():
    with pytest.raises(DesfireError) as exc:
        ev2.command_full(
            dtx(QueueConn([(b"", 0x91, 0x9D)])), session(), df.CMD_READ_DATA, header=b"\x01"
        )
    assert exc.value.status == 0x9D


def test_a_full_write_longer_than_one_frame_is_chain_sent():
    s = session()
    card = ChainCard(total_len=1 + 48 + 8, resp_mac=session(ctr=1).response_mac(0x00, b""))
    assert (
        ev2.command_full(dtx(card), s, df.CMD_WRITE_DATA, header=b"\x01", plaintext=bytes(40))
        == b""
    )
    assert [f[1] for f in card.frames] == [df.CMD_WRITE_DATA, 0xAF]
    macked = bytes(card.recv[:-8])
    assert bytes(card.recv[-8:]) == session().command_mac(df.CMD_WRITE_DATA, macked)


@pytest.mark.parametrize(
    "change",
    [
        lambda t, s: ev2.change_key_same(t, s, 0, bytes(8)),
        lambda t, s: ev2.change_key_cross(t, s, 1, bytes(16), bytes(8)),
    ],
    ids=["same", "cross"],
)
def test_change_key_refuses_non_aes_keys_before_sending(change):
    conn = QueueConn([])
    with pytest.raises(ev2.Ev2Error, match="16 bytes"):
        change(dtx(conn), session())
    assert conn.sent == []


def test_change_file_settings_sends_the_settings_encrypted_behind_the_file_number():
    s = session()
    card = ChangeKeyCard(k_enc=s.k_enc, k_mac=s.k_mac, ti=TI)
    wire = ResponseAdapter(card)
    settings = bytes.fromhex("40EEE0")
    ev2.change_file_settings(dtx(wire), s, 0x02, settings)
    assert wire.log[0].startswith("905F0000" + "19" + "02")  # Lc = file no + 16 enc + 8 MAC
    assert card.key_data[:3] == settings and card.key_data[3] == 0x80
    assert s.cmd_ctr == 1
