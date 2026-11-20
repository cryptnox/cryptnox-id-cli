# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``mifare`` listing, create, value, record, ``keys authenticate`` and ``format`` commands.

Plain commands run against a scripted card. The value and record commands run in EV2 MAC
mode against ``MacFile``, which checks every command MAC and MACs every answer.
"""

from __future__ import annotations

import json

import pytest
from _cardfakes import RecordingConn, ResponseAdapter, fake_tty, run, run_both_modes, wire_session
from test_ev2 import RNDB, FakeEv2Card
from test_mifare_commands import TI, Ev2Card

from cryptnox_id_cli.applets.mifare import desfire as df
from cryptnox_id_cli.applets.mifare import ev2
from cryptnox_id_cli.cli.commands import mifare as mifare_cmd

AID = "010203"
GET_VERSION = "9060000000"
EV2_VERSION = "04010112001A0504010102001A050411223344556601020304052021"
GET_FREE = "906E000000"
GET_AIDS = "906A000000"
SELECT_APP = "905A00000301020300"
GET_FILE_IDS = "906F000000"
GET_KEY_SETTINGS = "9045000000"
OK = (b"", 0x91, 0x00)


def _scripted(monkeypatch, answers: dict[str, tuple[bytes, int, int]]) -> ResponseAdapter:
    """Answers by exact command hex; anything else is refused with ILLEGAL_COMMAND_CODE."""
    conn = ResponseAdapter(RecordingConn(([], 0x91, 0x1C)), answers=answers)
    wire_session(monkeypatch, conn)
    return conn


def _recorder(monkeypatch) -> RecordingConn:
    """A card that accepts every command; the test reads what was sent."""
    conn = RecordingConn(([], 0x91, 0x00))
    wire_session(monkeypatch, conn)
    return conn


def test_version_reports_the_hardware_and_software(monkeypatch):
    _scripted(monkeypatch, {GET_VERSION: (bytes.fromhex(EV2_VERSION), 0x91, 0x00)})
    as_json, human = run_both_modes(["mifare", "version"])
    payload = json.loads(as_json.stdout)
    assert (payload["vendor"], payload["generation"], payload["uid"]) == (
        "NXP",
        "EV2",
        "04112233445566",
    )
    assert payload["storage_bytes"] == 8192
    text = " ".join(human.output.split())
    assert "Generation: DESFire EV2" in text and "UID: 04112233445566" in text
    assert "batch: 0102030405 week 20/year 21" in text


@pytest.mark.parametrize(
    ("free", "aids", "free_shown", "aids_shown"),
    [
        (
            (bytes.fromhex("001000"), 0x91, 0x00),
            b"\x01\x02\x03\xaa\xbb\xcc",
            "4096",
            "010203, AABBCC",
        ),
        ((b"", 0x91, 0x9D), b"", "n/a", "none"),
    ],
    ids=["two-apps", "free-memory-refused-no-apps"],
)
def test_info_shows_version_free_memory_and_applications(
    monkeypatch, free, aids, free_shown, aids_shown
):
    _scripted(
        monkeypatch,
        {
            GET_VERSION: (bytes.fromhex(EV2_VERSION), 0x91, 0x00),
            GET_FREE: free,
            GET_AIDS: (aids, 0x91, 0x00),
        },
    )
    as_json, human = run_both_modes(["mifare", "info"])
    payload = json.loads(as_json.stdout)
    assert payload["free_memory"] == (None if free_shown == "n/a" else int(free_shown))
    text = " ".join(human.output.split())
    assert f"Free mem: {free_shown}" in text
    assert f"Applications ({len(aids) // 3}): {aids_shown}" in text


def test_free_memory(monkeypatch):
    _scripted(monkeypatch, {GET_FREE: (bytes.fromhex("002000"), 0x91, 0x00)})
    as_json, human = run_both_modes(["mifare", "free-memory"])
    assert json.loads(as_json.stdout) == {"free_memory": 8192}
    assert "Free memory: 8192 bytes" in human.output


@pytest.mark.parametrize(
    ("aids", "shown"),
    [(b"\x01\x02\x03\xaa\xbb\xcc", ["010203", "AABBCC"]), (b"", [])],
    ids=["two", "none"],
)
def test_apps_list(monkeypatch, aids, shown):
    _scripted(monkeypatch, {GET_AIDS: (aids, 0x91, 0x00)})
    as_json, human = run_both_modes(["mifare", "apps", "list"])
    assert json.loads(as_json.stdout) == {"applications": shown}
    if shown:
        assert all(aid in human.output for aid in shown)
    else:
        assert "No applications (only the PICC master level)." in human.output


@pytest.mark.parametrize(
    ("ids", "shown"), [(b"\x01\x02", ["01", "02"]), (b"", [])], ids=["two", "none"]
)
def test_files_list(monkeypatch, ids, shown):
    _scripted(monkeypatch, {SELECT_APP: OK, GET_FILE_IDS: (ids, 0x91, 0x00)})
    as_json, human = run_both_modes(["mifare", "files", "list", "--aid", AID])
    assert json.loads(as_json.stdout) == {"aid": AID, "files": shown}
    expected = f"Files in {AID}: 01, 02" if shown else f"No files in application {AID}."
    assert expected in human.output


def _frames(conn: RecordingConn) -> list[str]:
    return [f.hex().upper() for f in conn.frames]


def test_app_create_sends_the_aid_and_the_key_count(monkeypatch):
    conn = _recorder(monkeypatch)
    as_json, human = run_both_modes(
        ["--yes", "mifare", "app", "create", "--aid", AID, "--keys", "5"]
    )
    assert json.loads(as_json.stdout) == {"aid": AID, "created": True, "keys": 5, "key_type": "AES"}
    assert _frames(conn)[0] == "90CA000005" + AID + "0F8500"
    assert f"Created application {AID} (5 AES keys)." in human.output


def test_app_create_refuses_a_key_type_other_than_aes(monkeypatch):
    conn = _recorder(monkeypatch)
    result = run(["--yes", "mifare", "app", "create", "--aid", AID, "--key-type", "des"])
    assert result.exit_code == 2 and "only AES applications are supported" in result.output
    assert conn.frames == []


@pytest.mark.parametrize(
    ("full", "comm_access", "mode"),
    [(False, "0100E0", "free read, key-0 wr"), (True, "030000", "FULL/encrypted, key-0 r+w")],
    ids=["mac", "full"],
)
def test_files_create_standard(monkeypatch, full, comm_access, mode):
    conn = _recorder(monkeypatch)
    args = ["--yes", "mifare", "files", "create-standard", "--aid", AID, "--file-id", "02"]
    args += ["--size", "32", *(["--full"] if full else [])]
    as_json, human = run_both_modes(args)
    assert json.loads(as_json.stdout) == {
        "aid": AID,
        "file": "02",
        "size": 32,
        "full": full,
        "created": True,
    }
    assert _frames(conn)[:2] == [SELECT_APP, "90CD00000702" + comm_access + "200000" + "00"]
    assert f"Created standard file 02 (32 B, {mode})." in human.output


def test_value_create_sends_the_limits_and_the_initial_value(monkeypatch):
    conn = _recorder(monkeypatch)
    args = ["--yes", "mifare", "value", "create", "--aid", AID, "--file-id", "03"]
    as_json, human = run_both_modes([*args, "--initial", "5", "--lower", "-10", "--upper", "100"])
    assert json.loads(as_json.stdout) == {"aid": AID, "file": "03", "initial": 5, "created": True}
    sent = conn.frames[1]
    assert sent[1] == df.CMD_CREATE_VALUE_FILE and sent[5] == 0x03
    body = sent[5 : 5 + sent[4]]
    lower, upper, value = (
        int.from_bytes(body[i : i + 4], "little", signed=True) for i in (4, 8, 12)
    )
    assert (lower, upper, value) == (-10, 100, 5)
    assert "Created value file 03 (initial 5, limits -10..100)." in human.output


@pytest.mark.parametrize(
    ("cyclic", "cmd", "kind"), [(False, 0xC1, "linear"), (True, 0xC0, "cyclic")]
)
def test_record_create(monkeypatch, cyclic, cmd, kind):
    conn = _recorder(monkeypatch)
    args = ["--yes", "mifare", "record", "create", "--aid", AID, "--file-id", "04"]
    args += ["--record-size", "16", "--max-records", "5", *(["--cyclic"] if cyclic else [])]
    as_json, human = run_both_modes(args)
    payload = json.loads(as_json.stdout)
    assert (payload["kind"], payload["record_size"], payload["max_records"]) == (kind, 16, 5)
    sent = conn.frames[1]
    assert sent[1] == cmd and sent[5] == 0x04
    body = sent[5 : 5 + sent[4]]
    assert body[4:7] == (16).to_bytes(3, "little") and body[7:10] == (5).to_bytes(3, "little")
    assert f"Created {kind} record file 04 (5 x 16 B)." in human.output


@pytest.mark.parametrize(
    "args",
    [
        ["app", "create", "--aid", AID],
        ["files", "create-standard", "--aid", AID, "--file-id", "02", "--size", "32"],
        ["value", "create", "--aid", AID, "--file-id", "03"],
        [
            "record",
            "create",
            "--aid",
            AID,
            "--file-id",
            "04",
            "--record-size",
            "8",
            "--max-records",
            "2",
        ],
    ],
    ids=["app", "standard", "value", "record"],
)
def test_declining_a_create_sends_nothing(monkeypatch, args):
    conn = _recorder(monkeypatch)
    result = run(["mifare", *args], input="n\n")
    assert result.exit_code != 0
    assert conn.frames == []


def test_keys_authenticate_reports_the_transaction_identifier(monkeypatch):
    wire_session(
        monkeypatch, ResponseAdapter(FakeEv2Card(bytes(16), RNDB, TI), answers={SELECT_APP: OK})
    )
    args = ["mifare", "keys", "authenticate", "--aid", AID, "--key-no", "1", "--zero-key"]
    as_json, human = run_both_modes(args)
    assert json.loads(as_json.stdout) == {
        "aid": AID,
        "key_no": 1,
        "authenticated": True,
        "ti": TI.hex().upper(),
    }
    assert f"EV2 authentication OK (key 1, TI {TI.hex().upper()})." in human.output


class MacFile:
    """The card side of EV2 MAC-mode commands: checks each command MAC, MACs each answer."""

    def __init__(self, k_enc: bytes, k_mac: bytes, ti: bytes, records: bytes = b"") -> None:
        self.s = ev2.Ev2Session(k_enc=k_enc, k_mac=k_mac, ti=ti)
        self.records = records
        self.received: list[tuple[int, bytes]] = []

    def transmit(self, raw: bytes):
        cmd, body = raw[1], raw[5 : 5 + raw[4]] if len(raw) > 5 else b""
        data, mact = body[:-8], body[-8:]
        if self.s.command_mac(cmd, data) != mact:
            return [], 0x91, 0x1E
        self.received.append((cmd, data))
        self.s.cmd_ctr += 1
        reply = self.records if cmd == df.CMD_READ_RECORDS else b""
        return list(reply + self.s.response_mac(0x00, reply)), 0x91, 0x00


def _mac_card(monkeypatch, records: bytes = b"") -> Ev2Card:
    card = Ev2Card(bytes(16), lambda k_enc, k_mac, ti: MacFile(k_enc, k_mac, ti, records))
    wire_session(monkeypatch, ResponseAdapter(card))
    return card


@pytest.mark.parametrize(
    ("verb", "cmd", "amount"), [("credit", df.CMD_CREDIT, 7), ("debit", df.CMD_DEBIT, 3)]
)
def test_credit_and_debit_are_maced_and_committed(monkeypatch, verb, cmd, amount):
    card = _mac_card(monkeypatch)
    args = ["mifare", "value", verb, "--aid", AID, "--file-id", "03", "--amount", str(amount)]
    as_json, human = run_both_modes([*args, "--zero-key"])
    assert json.loads(as_json.stdout) == {
        "aid": AID,
        "file": "03",
        verb: amount,
        "committed": True,
    }
    sent = card.sessions[0].received
    assert sent == [
        (cmd, b"\x03" + amount.to_bytes(4, "little", signed=True)),
        (df.CMD_COMMIT_TXN, b""),
    ]
    assert f"{verb.capitalize()} {amount} on value file 03 (committed)." in human.output


@pytest.mark.parametrize("source", ["data", "file"])
def test_record_write_appends_and_commits(monkeypatch, tmp_path, source):
    card = _mac_card(monkeypatch)
    record = bytes(range(8))
    path = tmp_path / "rec.bin"
    path.write_bytes(record)
    given = ["--data", record.hex()] if source == "data" else ["--in", str(path)]
    args = ["mifare", "record", "write", "--aid", AID, "--file-id", "04", *given, "--zero-key"]
    as_json, human = run_both_modes(args)
    assert json.loads(as_json.stdout) == {"aid": AID, "file": "04", "written": 8, "committed": True}
    header = df.DesfireTransport.data_header(4, 0, 8)
    assert card.sessions[0].received == [
        (df.CMD_WRITE_RECORD, header + record),
        (df.CMD_COMMIT_TXN, b""),
    ]
    assert "Wrote a 8-byte record to 04 (committed)." in human.output


def test_record_write_needs_exactly_one_source(monkeypatch, tmp_path):
    _mac_card(monkeypatch)
    args = ["mifare", "record", "write", "--aid", AID, "--file-id", "04", "--zero-key"]
    assert "provide exactly one of --in or --data" in run(args).output
    path = tmp_path / "rec.bin"
    path.write_bytes(b"x")
    assert (
        "provide exactly one of --in or --data"
        in run([*args, "--data", "00", "--in", str(path)]).output
    )


def test_record_read_returns_the_records(monkeypatch):
    records = bytes(range(0x10, 0x20))
    card = _mac_card(monkeypatch, records)
    args = [
        "mifare",
        "record",
        "read",
        "--aid",
        AID,
        "--file-id",
        "04",
        "--count",
        "2",
        "--offset",
        "1",
    ]
    as_json, human = run_both_modes([*args, "--zero-key"])
    payload = json.loads(as_json.stdout)
    assert (payload["length"], payload["hex"]) == (16, records.hex().upper())
    assert card.sessions[0].received == [
        (df.CMD_READ_RECORDS, df.DesfireTransport.data_header(4, 1, 2))
    ]
    assert f"records of 04 (16 B): {records.hex().upper()}" in human.output


def test_a_maced_command_the_card_refuses_surfaces_its_status(monkeypatch):
    class BadMacFile(MacFile):
        def transmit(self, raw):
            self.s.cmd_ctr += 5  # out of step: every MAC the host sends now looks wrong
            return super().transmit(raw)

    card = Ev2Card(bytes(16), BadMacFile)
    wire_session(monkeypatch, ResponseAdapter(card))
    args = ["--json", "mifare", "value", "credit", "--aid", AID, "--file-id", "03", "--amount", "1"]
    result = run([*args, "--zero-key"])
    assert result.exit_code == df.DesfireError.exit_code, result.output
    assert "INTEGRITY_ERROR" in result.stdout


FORMAT = ["mifare", "format", "--zero-key", "--i-understand-this-erases-all-applications"]


def test_format_of_an_aes_picc_authenticates_and_sends_format_picc(monkeypatch):
    card = Ev2Card(bytes(16), MacFile)
    conn = ResponseAdapter(card, answers={GET_KEY_SETTINGS: (b"\x0f\x81", 0x91, 0x00)})
    wire_session(monkeypatch, conn)
    as_json, human = run_both_modes(FORMAT)
    assert json.loads(as_json.stdout) == {"formatted": True}
    assert card.sessions[0].received == [(df.CMD_FORMAT_PICC, b"")]
    assert conn.log[0] == "905A00000300000000"  # the PICC level
    assert "PICC formatted." in human.output


def test_format_refuses_a_3k3des_picc_key(monkeypatch):
    _scripted(monkeypatch, {"905A00000300000000": OK, GET_KEY_SETTINGS: (b"\x0f\x41", 0x91, 0x00)})
    result = run(FORMAT)
    assert result.exit_code == 1
    assert "the PICC master key is 3K3DES; this tool handles AES and 2K3DES." in result.output


def test_format_needs_the_flag_without_a_terminal(monkeypatch):
    conn = _recorder(monkeypatch)
    result = run(["mifare", "format", "--zero-key"])
    assert result.exit_code == 1
    assert "needs --i-understand-this-erases-all-applications non-interactively" in result.output
    assert conn.frames == []


def test_format_on_a_terminal_wants_the_phrase(monkeypatch):
    conn = _recorder(monkeypatch)
    fake_tty(monkeypatch, mifare_cmd)
    result = run(["mifare", "format", "--zero-key"], input="format\n")
    assert result.exit_code != 0
    assert "Type FORMAT-PICC to continue" in result.output
    assert conn.frames == []


@pytest.mark.parametrize(
    ("extra", "env", "message"),
    [
        (["--zero-key", "--key-env", "K"], {"K": "00" * 16}, "mutually exclusive"),
        (["--key-env", "K"], {}, "environment variable K is not set"),
        (["--key-env", "K"], {"K": "0011"}, "must be 16 bytes (AES-128 or 2K3DES)"),
        ([], {}, "provide --zero-key (factory default) or --key-env NAME"),
    ],
    ids=["both", "unset", "short", "neither"],
)
def test_format_key_source_errors(monkeypatch, extra, env, message):
    conn = _recorder(monkeypatch)
    monkeypatch.delenv("K", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    result = run(["mifare", "format", "--i-understand-this-erases-all-applications", *extra])
    assert result.exit_code != 0
    assert message in result.output
    assert conn.frames == []


@pytest.mark.parametrize(
    ("extra", "env", "message"),
    [
        (["--zero-key", "--key-env", "K"], {"K": "00" * 16}, "mutually exclusive"),
        (["--key-env", "K"], {"K": "0011"}, "DESFire EV2 keys must be 16 bytes (AES-128)"),
    ],
    ids=["both", "short"],
)
def test_aes_key_source_errors(monkeypatch, extra, env, message):
    conn = _recorder(monkeypatch)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    result = run(["mifare", "keys", "authenticate", "--aid", AID, *extra])
    assert result.exit_code != 0
    assert message in result.output
    assert conn.frames == []
