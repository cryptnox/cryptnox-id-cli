# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``factory piv preperso finalize`` and ``load-config`` over a real SCP03 handshake."""

from __future__ import annotations

import json

import pytest
from _cardfakes import ResponseAdapter, fake_tty, run, wire_session
from test_scp03 import GP_KEY, FakeScp03Card
from test_state_detector import APT, GET_STATUS, SELECT_PIV

from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.scp03 import Scp03Keys


class PivAdminCard(FakeScp03Card):
    """SELECT PIV, the 2F4753 status object, and an SW for each wrapped PUT DATA ADMIN."""

    def __init__(self, *, secured=False, present=True, put_sws=(), secure_on_put=True):
        super().__init__(Scp03Keys.same(GP_KEY), bytes.fromhex("1122334455667788"))
        self.secured, self.present = secured, present
        self.put_sws, self.secure_on_put = list(put_sws), secure_on_put

    def transmit(self, apdu):
        raw = bytes(apdu)
        if raw.hex().upper() == SELECT_PIV:
            return (
                Response(bytes.fromhex(APT), 0x90, 0x00)
                if self.present
                else Response(b"", 0x6A, 0x82)
            )
        if raw.hex().upper() == GET_STATUS:
            state = "0F" if self.secured else "07"
            return Response(bytes.fromhex(f"53068001{state}860100"), 0x90, 0x00)
        if raw[0] & 0x04 and raw[1] == 0xDB:
            sw = self.put_sws.pop(0) if self.put_sws else 0x9000
            self.secured = self.secured or (sw == 0x9000 and self.secure_on_put)
            return Response(b"", sw >> 8, sw & 0xFF)
        return super().transmit(raw)


def _wire(monkeypatch, **kw):
    conn = ResponseAdapter(PivAdminCard(**kw))
    wire_session(monkeypatch, conn)
    return conn


def _wrapped_puts(conn):
    return [c for c in conn.log if c.startswith("04DB")]


FINALIZE = ["factory", "piv", "preperso", "finalize", "--default-keys"]
CONFIRMED = [*FINALIZE, "--i-understand-this-is-irreversible"]


@pytest.mark.parametrize("json_mode", [True, False])
@pytest.mark.parametrize("applet_confirms", [True, False])
def test_finalize_sends_secure_applet_over_scp03(monkeypatch, json_mode, applet_confirms):
    conn = _wire(monkeypatch, secure_on_put=applet_confirms)
    result = run(["--json", *CONFIRMED] if json_mode else CONFIRMED)
    assert result.exit_code == 0, result.output
    assert any(c.startswith("8050") for c in conn.log)
    assert any(c.startswith("8482") for c in conn.log)
    assert len(_wrapped_puts(conn)) == 1
    if json_mode:
        payload = json.loads(result.stdout)
        assert (payload["finalized"], payload["secured"]) == (True, applet_confirms)
    else:
        word = "SECURED confirmed" if applet_confirms else "SECURED not confirmed by the applet"
        assert "Applet finalized" in result.stdout and word in result.stdout


@pytest.mark.parametrize(
    ("card", "args", "message"),
    [
        ({"put_sws": [0x6982]}, CONFIRMED, "SECURE APPLET (finalize)"),
        ({"secured": True}, CONFIRMED, "already SECURED"),
        ({"present": False}, CONFIRMED, "PIV applet is not selectable"),
        ({}, FINALIZE, "requires --i-understand-this-is-irreversible"),
    ],
)
def test_finalize_refusals(monkeypatch, card, args, message):
    conn = _wire(monkeypatch, **card)
    result = run(["--json", *args])
    assert result.exit_code not in (0, None)
    assert message in result.stdout
    if "put_sws" not in card:
        assert not any(c.startswith("8050") for c in conn.log)


def test_finalize_dry_run_plans_without_a_channel(monkeypatch):
    conn = _wire(monkeypatch)
    as_json = run(["--json", "--dry-run", *CONFIRMED])
    human = run(["--dry-run", *CONFIRMED])
    assert json.loads(as_json.stdout)["would_finalize"] is True
    assert "would finalize (SECURE APPLET) - no command sent" in human.stdout
    assert not any(c.startswith("8050") for c in conn.log)


@pytest.mark.parametrize(("typed", "finalized"), [("FINALIZE-PIV", True), ("finalize", False)])
def test_finalize_on_a_terminal_wants_the_phrase(monkeypatch, typed, finalized):
    conn = _wire(monkeypatch)
    fake_tty(monkeypatch, factory_cmd)
    result = run(FINALIZE, input=f"{typed}\n")
    assert (result.exit_code == 0) is finalized, result.output
    assert "This is IRREVERSIBLE" in result.output
    assert len(_wrapped_puts(conn)) == int(finalized)


LOAD = ["factory", "piv", "preperso", "load-config", "--profile", "ssh", "--default-keys"]


@pytest.mark.parametrize("json_mode", [True, False])
def test_load_config_opens_one_channel_per_operation(monkeypatch, json_mode):
    conn = _wire(monkeypatch, secure_on_put=False)
    result = run(["--json", "--yes", *LOAD] if json_mode else ["--yes", *LOAD])
    assert result.exit_code == 0, result.output
    puts = _wrapped_puts(conn)
    assert len(puts) == 17
    assert sum(c.startswith("8050") for c in conn.log) == len(puts)
    if json_mode:
        payload = json.loads(result.stdout)
        assert payload["applied"] is True and all(op["ok"] for op in payload["operations"])
    else:
        assert "Applied profile 'ssh' (17 operations)" in result.stdout


@pytest.mark.parametrize("json_mode", [True, False])
def test_load_config_stops_at_the_first_refusal(monkeypatch, json_mode):
    conn = _wire(monkeypatch, put_sws=[0x9000, 0x9000, 0x6A80], secure_on_put=False)
    result = run(["--json", "--yes", *LOAD] if json_mode else ["--yes", *LOAD])
    assert result.exit_code == 6
    assert len(_wrapped_puts(conn)) == 3
    if json_mode:
        ops = json.loads(result.stdout)["operations"]
        assert [op["sw"] for op in ops] == ["9000", "9000", "6A80"]
    else:
        assert "Stopped at" in result.stdout and "SW=6A80" in result.stdout


def test_load_config_declined_sends_nothing(monkeypatch):
    conn = _wire(monkeypatch)
    result = run(LOAD, input="n\n")
    assert result.exit_code != 0
    assert "They are permanent" in result.output
    assert conn.log == []
