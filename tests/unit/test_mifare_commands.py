# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``mifare keys change``, ``mifare read`` and ``mifare sdm read`` through the session seam."""

from __future__ import annotations

import json

import pytest
from _cardfakes import ResponseAdapter, run, run_both_modes, wire_session
from test_ev2 import RNDB, ChangeKeyCard, FakeEv2Card, FullCard

from cryptnox_id_cli.applets.mifare import ev2

TI = bytes.fromhex("A1B2C3D4")
NEW_KEY = bytes(range(16, 32))
AUTH_KEY = bytes(range(0x40, 0x50))
FILE_DATA = bytes(range(0xA0, 0xB4))  # 20 bytes


class Ev2Card:
    """SelectApplication and AuthenticateEV2First in front of a secure-messaging double.

    Each authentication starts a new ``make_sm`` session, collected in ``sessions``; the
    one after the first uses ``next_key``, the key a same-key ChangeKey installed.
    """

    def __init__(self, key: bytes, make_sm, next_key: bytes | None = None) -> None:
        self.keys = [key, next_key or key]
        self.make_sm = make_sm
        self.sessions: list = []
        self.auth: FakeEv2Card | None = None

    def transmit(self, apdu):
        raw = bytes(apdu)
        if raw[1] == 0x5A:
            return [], 0x91, 0x00
        if raw[1] == ev2.CMD_AUTHENTICATE_EV2_FIRST:
            key = self.keys[min(len(self.sessions), 1)]
            self.auth = FakeEv2Card(key, RNDB, TI)
        if raw[1] in (ev2.CMD_AUTHENTICATE_EV2_FIRST, ev2.CMD_ADDITIONAL_FRAME) and self.auth:
            reply = self.auth.transmit(raw)
            if raw[1] == ev2.CMD_ADDITIONAL_FRAME and reply[2] == 0x00:
                k_enc, k_mac = ev2.derive_session_keys(self.auth.key, self.auth.rnda, RNDB)
                self.sessions.append(self.make_sm(k_enc, k_mac, TI))
                self.auth = None
            return reply
        return self.sessions[-1].transmit(raw)


def _wire(monkeypatch, key, make_sm, answers=None, next_key=None):
    card = Ev2Card(key, make_sm, next_key)
    conn = ResponseAdapter(card, answers=answers)
    wire_session(monkeypatch, conn)
    return card, conn


def _full_card(k_enc, k_mac, ti):
    card = FullCard(k_enc, k_mac, ti)
    card.store[: len(FILE_DATA)] = FILE_DATA
    return card


CHANGE = ["mifare", "keys", "change", "--aid", "010203", "--new-key-env", "NEWK"]


@pytest.mark.parametrize("json_mode", [True, False])
def test_same_key_change_sends_the_new_key_and_version(monkeypatch, json_mode):
    card, conn = _wire(monkeypatch, bytes(16), ChangeKeyCard, next_key=NEW_KEY)
    monkeypatch.setenv("NEWK", NEW_KEY.hex())
    args = ["--yes", *CHANGE, "--zero-key", "--key-version", "16"]
    result = run(["--json", *args] if json_mode else args)
    assert result.exit_code == 0, result.output
    assert card.sessions[0].key_data[:17] == NEW_KEY + b"\x10"
    assert len(card.sessions) == 2  # the new key authenticated afterwards
    assert conn.log[0] == "905A00000301020300" and conn.log[1].startswith("907100000200")
    change = next(line for line in conn.log if line.startswith("90C4"))
    assert change.startswith("90C4000029" + "00")  # ChangeKey, key 0, 1+32+8 bytes
    if json_mode:
        assert json.loads(result.stdout)["mode"] == "same"
    else:
        assert "Changed key 0" in result.stdout and "(same-key)" in result.stdout
    assert NEW_KEY.hex().upper() not in result.output.upper()


@pytest.mark.parametrize("json_mode", [True, False])
def test_cross_key_change_authenticates_with_the_other_key(monkeypatch, json_mode):
    card, conn = _wire(monkeypatch, AUTH_KEY, ChangeKeyCard)
    monkeypatch.setenv("NEWK", NEW_KEY.hex())
    monkeypatch.setenv("AUTHK", AUTH_KEY.hex())
    args = ["--yes", *CHANGE, "--key-no", "1", "--zero-key", "--auth-key-no", "0"]
    args += ["--auth-key-env", "AUTHK", "--key-version", "5"]
    result = run(["--json", *args] if json_mode else args)
    assert result.exit_code == 0, result.output
    assert card.sessions[0].key_data[:21] == NEW_KEY + b"\x05" + ev2.desfire_crc32(NEW_KEY)
    assert len(card.sessions) == 1
    assert conn.log[1].startswith("907100000200")  # authenticated as key 0
    if json_mode:
        payload = json.loads(result.stdout)
        assert (payload["mode"], payload["key_no"], payload["auth_key_no"]) == ("cross", 1, 0)
    else:
        assert "cross-key; authenticated with key 0" in result.stdout


@pytest.mark.parametrize(
    ("extra", "env", "message"),
    [
        (["--zero-key"], {}, "environment variable NEWK is not set"),
        (["--zero-key"], {"NEWK": "0011"}, "new AES key must be 16 bytes"),
        (["--zero-key", "--auth-zero-key"], {"NEWK": NEW_KEY.hex()}, "--auth-* options need"),
        (
            ["--zero-key", "--auth-key-no", "1", "--key-no", "0"],
            {"NEWK": NEW_KEY.hex()},
            "cross-key change needs",
        ),
        (["--zero-key", "--key-env", "K"], {"NEWK": NEW_KEY.hex()}, "mutually exclusive"),
    ],
    ids=["new-key-unset", "new-key-short", "auth-without-other-key", "cross-without-key", "both"],
)
def test_key_change_refuses_bad_input_before_touching_the_card(monkeypatch, extra, env, message):
    _, conn = _wire(monkeypatch, bytes(16), ChangeKeyCard)
    monkeypatch.delenv("NEWK", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    result = run(["--yes", *CHANGE, *extra])
    assert result.exit_code != 0
    assert message in result.output
    assert conn.log == []


def test_key_change_declined_sends_nothing(monkeypatch):
    _, conn = _wire(monkeypatch, bytes(16), ChangeKeyCard)
    monkeypatch.setenv("NEWK", NEW_KEY.hex())
    result = run([*CHANGE, "--zero-key"], input="n\n")
    assert result.exit_code != 0
    assert "keep the new key safe" in result.output
    assert conn.log == []


def test_key_change_with_the_wrong_current_key_is_refused(monkeypatch):
    card, _ = _wire(monkeypatch, AUTH_KEY, ChangeKeyCard)
    monkeypatch.setenv("NEWK", NEW_KEY.hex())
    result = run(["--json", "--yes", *CHANGE, "--zero-key"])
    assert result.exit_code == 9
    assert "AUTHENTICATION_ERROR" in result.stdout
    assert card.sessions == []


PLAIN_READ = "90BD0000070100000000000000"
READ = ["mifare", "read", "--aid", "010203", "--file-id", "01"]


def test_plain_read_shows_the_bytes(monkeypatch):
    _wire(monkeypatch, bytes(16), FullCard, answers={PLAIN_READ: (FILE_DATA, 0x91, 0x00)})
    as_json, human = run_both_modes(READ)
    assert json.loads(as_json.stdout)["hex"] == FILE_DATA.hex().upper()
    assert f"file 01 (20 B): {FILE_DATA.hex().upper()}" in human.stdout


@pytest.mark.parametrize("json_mode", [True, False])
def test_full_read_decrypts_over_ev2(monkeypatch, json_mode):
    _, conn = _wire(monkeypatch, bytes(16), _full_card)
    args = [*READ, "--full", "--length", "20", "--zero-key"]
    result = run(["--json", *args] if json_mode else args)
    assert result.exit_code == 0, result.output
    assert conn.log[-1].startswith("90BD00000F01000000140000")  # header in the clear, + MAC
    shown = FILE_DATA.hex().upper()
    assert (json.loads(result.stdout)["hex"] == shown) if json_mode else (shown in result.stdout)


def test_read_to_a_file_keeps_the_bytes_off_stdout(monkeypatch, tmp_path):
    _wire(monkeypatch, bytes(16), FullCard, answers={PLAIN_READ: (FILE_DATA, 0x91, 0x00)})
    out = tmp_path / "file01.bin"
    as_json, human = run_both_modes([*READ, "--out", str(out)])
    assert out.read_bytes() == FILE_DATA
    assert json.loads(as_json.stdout)["hex"] is None
    assert f"Read 20 bytes -> {out}" in human.stdout


def test_full_read_needs_a_length(monkeypatch):
    _, conn = _wire(monkeypatch, bytes(16), FullCard)
    result = run([*READ, "--full", "--zero-key"])
    assert result.exit_code == 2
    assert "--full requires --length" in result.output
    assert conn.log == []


GET_VERSION = "9060000000"
EV3_VERSION = "04010133001A0504010103001A050411223344556601020304052021"
SELECT_APP = "905A00000301020300"
SDM_READ = "90BD0000070200000000000000"
SDM_URL = "https://x.example/t?picc=" + "00" * 16 + "&c=" + "11" * 8


def _sdm_tag(monkeypatch, text: str) -> None:
    answers = {
        GET_VERSION: (bytes.fromhex(EV3_VERSION), 0x91, 0x00),
        SELECT_APP: (b"", 0x91, 0x00),
        SDM_READ: (text.encode(), 0x91, 0x00),
    }
    wire_session(monkeypatch, ResponseAdapter(FullCard(bytes(16), bytes(16), TI), answers=answers))


def test_sdm_read_reports_the_url_and_the_mac_verdict(monkeypatch):
    _sdm_tag(monkeypatch, SDM_URL)
    as_json, human = run_both_modes(["mifare", "sdm", "read", "--aid", "010203", "--file-id", "02"])
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["url"] == SDM_URL
    assert payload["sdmmac_valid"] is False
    assert f"NDEF: {SDM_URL}" in human.stdout


@pytest.mark.xfail(strict=True, reason="the tag's NDEF text is printed as console markup")
@pytest.mark.parametrize("tail", ["&n=a[/x]b", "&n=[b]S[/b]"])
def test_sdm_read_prints_the_ndef_text_as_written(monkeypatch, tail):
    _sdm_tag(monkeypatch, SDM_URL + tail)
    result = run(["mifare", "sdm", "read", "--aid", "010203", "--file-id", "02"])
    assert result.exit_code == 0, result.output
    assert f"NDEF: {SDM_URL}{tail}" in result.stdout
