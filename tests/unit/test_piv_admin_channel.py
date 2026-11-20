# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``PivAdmin``: opening the admin secure channel, and sending before one is open;
``piv admin authenticate`` over it."""

from __future__ import annotations

import json

import pytest
from _cardfakes import QueueConn, ResponseAdapter, run_both_modes, wire_session
from _piv_card import UnwrappingScp03Card
from test_scp02 import FakeScp02Card
from test_scp03 import GP_KEY, FakeScp03Card

from cryptnox_id_cli.applets.piv.admin import SCP02, InitializeUpdateRejected, PivAdmin
from cryptnox_id_cli.transport.errors import Scp03Error
from cryptnox_id_cli.transport.pcsc import CardSession
from cryptnox_id_cli.transport.scp02 import Scp02Keys
from cryptnox_id_cli.transport.scp03 import Scp03Keys

SELECT_PIV = "00A404000BA00000030800001000010000"


def _admin(conn) -> PivAdmin:
    return PivAdmin(CardSession(conn))


@pytest.mark.parametrize(
    ("reply", "error", "message"),
    [
        ((b"", 0x6A, 0x88), InitializeUpdateRejected, "INITIALIZE UPDATE rejected \\(SW=6A88\\)"),
        ((bytes(11), 0x90, 0x00), Scp03Error, "response too short \\(11 bytes\\)"),
        ((bytes(11) + b"\x01" + bytes(16), 0x90, 0x00), Scp03Error, "keyInfo SCP id = 0x01"),
    ],
    ids=["refused", "short", "unsupported-scp"],
)
def test_open_refuses_what_it_cannot_use(reply, error, message):
    admin = _admin(QueueConn([reply]))
    with pytest.raises(error, match=message):
        admin.open(Scp03Keys.same(GP_KEY))
    assert admin.scp is None


def test_open_detects_scp02_and_adapts_an_scp03_key_triple():
    card = FakeScp02Card(Scp02Keys(GP_KEY, GP_KEY, GP_KEY), bytes.fromhex("0001"), bytes(6))
    admin = _admin(ResponseAdapter(card))
    admin.open(Scp03Keys.same(GP_KEY))
    assert admin.scp_version == SCP02


@pytest.mark.parametrize("send", ["send", "send_chained"])
def test_sending_before_the_channel_is_open_is_refused(send):
    admin = _admin(QueueConn([]))
    with pytest.raises(Scp03Error, match="secure channel not open"):
        if send == "send":
            admin.self_test_read()
        else:
            admin.send_chained(0xDB, 0x3F, 0xFF, bytes(10))


def test_a_chained_send_stops_at_the_first_refused_block():
    conn = ResponseAdapter(FakeScp03Card(Scp03Keys.same(GP_KEY), bytes.fromhex("1122334455667788")))
    admin = _admin(conn)
    admin.open(Scp03Keys.same(GP_KEY))
    resp = admin.send_chained(0xDB, 0x3F, 0xFF, bytes(500), block_size=200)
    assert resp.sw == 0x6D00  # the double refuses every secured command
    chained = [c for c in conn.log if c[2:4] == "DB"]
    assert len(chained) == 1 and chained[0][:2] == "14"  # first block only, chaining bit set


@pytest.mark.parametrize(
    ("reply", "verdict"),
    [((b"", 0x90, 0x00), "OK"), ((b"", 0x6A, 0x82), "OK"), ((b"", 0x6D, 0x00), "unexpected")],
    ids=["read", "absent", "refused"],
)
def test_admin_authenticate_reports_the_round_trip(monkeypatch, reply, verdict):
    card = UnwrappingScp03Card(on_secured=lambda ins, p1, p2, body: reply)
    conn = ResponseAdapter(card, answers={SELECT_PIV: ([0x6F, 0x00], 0x90, 0x00)})
    wire_session(monkeypatch, conn)
    as_json, human = run_both_modes(["piv", "admin", "authenticate", "--default-keys"])
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["self_test_ok"] is (verdict == "OK")
    assert payload["self_test_sw"] == f"{reply[1]:02X}{reply[2]:02X}"
    text = " ".join(human.output.split())
    assert "SCP03 secure channel established (mutual authentication OK)." in text
    assert "Security level: 0x03 (C-MAC + C-ENC)" in text
    assert f"Admin round-trip (wrapped GET DATA): SW={payload['self_test_sw']} -> {verdict}" in text
