"""`factory card status` and `factory card fuse`: the card-manager commands, against a
stateful card-manager double. No real card is fused by these tests."""

from __future__ import annotations

import json
import os
import stat
import sys
from types import SimpleNamespace

import pytest
from _cardfakes import run, wire_session

from cryptnox_id_cli.applets import cardmanager as cm
from cryptnox_id_cli.applets.piv import ssd
from cryptnox_id_cli.applets.piv.admin import SCP02
from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.secrets.resolver import DEFAULT_GP_KEY
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.errors import Scp02Error

TEST_KEY = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
SELECT_ISD = "00A4040008A00000015100000000"
GET_E0 = "80CA00E000"
GET_CPLC = "80CA9F7F00"
FCI_ISD = bytes.fromhex("6F108408A000000151000000A5049F6501FF")
E0_KVN1_DES = bytes.fromhex("E012C00401018010C00402018010C00403018010")
E0_TWO_VERSIONS = bytes.fromhex(
    "E024C00401018010C00402018010C00403018010C00401028010C00402028010C00403028010"
)
CPLC = bytes.fromhex(
    "9F7F2A4790D6004700000000004327028644211698000000000000000002507732383634340000000000000000"
)
OK = (0x90, 0x00)
MODULE_AIDS = [m.aid for m in cm.FUSE_MODULES]


# --------------------------------------------------------------- builders --- #
def test_apdu_builders():
    assert cm.delete_aid_apdu(cm.CONFIG_MODULE_AID).to_bytes().hex().upper() == (
        "80E4008010" + "4F0E" + "D276000085304A434F504D4F4406" + "00"
    )
    assert cm.set_card_lifecycle_apdu(cm.INITIALIZED).to_bytes().hex().upper() == "80F08007"
    assert cm.set_card_lifecycle_apdu(cm.SECURED).to_bytes().hex().upper() == "80F0800F"
    assert cm.get_status_apdu(cm.SCOPE_ISD).to_bytes().hex().upper() == "80F28002024F0000"
    assert cm.get_status_apdu(cm.SCOPE_ISD, tlv_format=False).to_bytes()[3] == 0x00
    assert cm.get_status_apdu(cm.SCOPE_ISD, next_occurrence=True).to_bytes()[3] == 0x03


def test_parse_status_tlv_reads_aid_lifecycle_and_modules():
    data = bytes.fromhex(
        "E3114F08A0000001510000009F70010FC5019EE3174F07A00000015153509F7001018408A000000151535041"
    )
    entries = cm.parse_status_tlv(data)
    assert entries[0] == cm.StatusEntry(bytes.fromhex("A000000151000000"), 0x0F, ())
    assert entries[1].aid == bytes.fromhex("A0000001515350")
    assert entries[1].modules == (bytes.fromhex("A000000151535041"),)


def test_parse_status_legacy_per_scope():
    isd = bytes.fromhex("08A000000151000000079E")
    assert cm.parse_status_legacy(isd, cm.SCOPE_ISD) == [
        cm.StatusEntry(bytes.fromhex("A000000151000000"), 0x07, ())
    ]
    files = bytes.fromhex("07A0000001515350010108A000000151535041")
    (entry,) = cm.parse_status_legacy(files, cm.SCOPE_LOAD_FILES_AND_MODULES)
    assert entry.modules == (bytes.fromhex("A000000151535041"),)


def test_read_status_follows_more_data_and_falls_back_to_legacy():
    first = bytes.fromhex("E30B4F05A0000000019F700101")
    second = bytes.fromhex("E30B4F05A0000000029F700101")
    answers = iter([Response(first, 0x63, 0x10), Response(second, 0x90, 0x00)])
    entries = cm.read_status(lambda apdu: next(answers), cm.SCOPE_APPLICATIONS)
    assert [e.aid.hex() for e in entries] == ["a000000001", "a000000002"]

    legacy = iter(
        [Response(b"", 0x6A, 0x86), Response(bytes.fromhex("08A000000151000000079E"), 0x90, 0x00)]
    )
    (isd,) = cm.read_status(lambda apdu: next(legacy), cm.SCOPE_ISD)
    assert isd.lifecycle == cm.INITIALIZED

    assert cm.read_status(lambda apdu: Response(b"", 0x6A, 0x88), cm.SCOPE_APPLICATIONS) == []
    assert cm.read_status(lambda apdu: Response(b"", 0x69, 0x82), cm.SCOPE_APPLICATIONS) is None


# ---------------------------------------------------------------- doubles --- #
class _SeqConn:
    def __init__(self, answers: dict[str, tuple[bytes, int, int]]) -> None:
        self._answers = {k.upper(): v for k, v in answers.items()}

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        data, sw1, sw2 = self._answers.get(bytes(apdu).hex().upper(), (b"", 0x6A, 0x82))
        return list(data), sw1, sw2

    def get_atr(self) -> bytes:
        return b"\x3b\x00"

    def disconnect(self) -> None:
        pass


class _CardManager:
    """A card manager with a lifecycle, loaded modules and a key; every command the fuse
    sends acts on that state, so the post-checks see what a real card would report."""

    def __init__(self) -> None:
        self.key = DEFAULT_GP_KEY
        self.lifecycle = cm.OP_READY
        self.loaded = set(MODULE_AIDS)
        self.refuse: dict[str, int] = {}
        self.opened: list[bytes] = []
        self.sent: list[str] = []
        self.files_seen_at_put_key: list[bool] = []
        self.key_file: str | None = None


STATE = _CardManager()


class _FakeAdmin:
    def __init__(self, session) -> None:
        self.card = session
        self.scp = SimpleNamespace(s_dek=bytes(16))
        self.scp_version = SCP02

    def open(self, keys, *, key_version: int = 0, security_level: int = 0x03) -> None:
        STATE.opened.append(keys.enc)
        if keys.enc != STATE.key:
            raise Scp02Error("Card cryptogram mismatch - the SCP02 keys are wrong for this card.")

    def forget_channel(self) -> None:
        self.scp = None

    def send(self, apdu, *, context=None) -> Response:
        hexed = apdu.to_bytes().hex().upper()
        STATE.sent.append(hexed)
        refused = STATE.refuse.get(
            hexed[:4] + (apdu.data[2:].hex().upper() if apdu.ins == 0xE4 else "")
        )
        if refused:
            return Response(b"", refused >> 8, refused & 0xFF)
        if apdu.ins == 0xF2:
            if apdu.p1 == cm.SCOPE_ISD:
                body = (
                    bytes.fromhex("E3114F08A0000001510000009F7001")
                    + bytes([STATE.lifecycle])
                    + bytes.fromhex("C5019E")
                )
                return Response(body, 0x90, 0x00)
            entries = b"".join(
                bytes([0xE3, len(a) + 6, 0x4F, len(a)]) + a + bytes.fromhex("9F700101")
                for a in sorted(STATE.loaded)
            )
            if not entries:
                return Response(b"", 0x6A, 0x88)
            return Response(entries, 0x90, 0x00)
        if apdu.ins == 0xE4:
            aid = apdu.data[2:]
            if aid in STATE.loaded:
                STATE.loaded.discard(aid)
                return Response(b"\x00", 0x90, 0x00)
            return Response(b"", 0x6A, 0x88)
        if apdu.ins == 0xF0:
            STATE.lifecycle = apdu.p2
            return Response(b"", 0x90, 0x00)
        if apdu.ins == 0xD8:
            STATE.files_seen_at_put_key.append(
                bool(STATE.key_file and os.path.exists(STATE.key_file))
            )
            STATE.key = STATE.new_key
            echoed = ssd.kcv_des(STATE.new_key) * 3
            return Response(bytes([apdu.data[0]]) + echoed, 0x90, 0x00)
        return Response(b"", 0x6D, 0x00)


@pytest.fixture
def card(monkeypatch):
    global STATE
    STATE = _CardManager()
    STATE.new_key = TEST_KEY
    monkeypatch.setattr(piv_cmd, "PivAdmin", _FakeAdmin)
    wire_session(
        monkeypatch,
        _SeqConn({SELECT_ISD: (FCI_ISD, *OK), GET_E0: (E0_KVN1_DES, *OK), GET_CPLC: (CPLC, *OK)}),
    )
    for part in ("ENC", "MAC", "DEK"):
        monkeypatch.setenv(f"CARD_MANAGER_NEW_{part}", TEST_KEY.hex())
        monkeypatch.delenv(f"CARD_MANAGER_{part}", raising=False)
    return STATE


def _changes(state: _CardManager) -> list[str]:
    return [c for c in state.sent if c[2:4] in ("E4", "F0", "D8")]


# ------------------------------------------------------------------- fuse --- #
def test_fuse_runs_the_factory_sequence(card):
    result = run(["--json", "factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [s["step"] for s in payload["steps"]] == [
        "delete egovaccelerators sample module",
        "delete fips sample module",
        "delete piv sample module",
        "delete configuration module",
        "lifecycle INITIALIZED",
        "lifecycle SECURED",
        "lock card manager",
    ]
    assert all(s["result"] in ("deleted", "set", "locked") for s in payload["steps"])
    assert payload["before"]["lifecycle"] == "OP_READY"
    assert payload["after"]["lifecycle"] == "SECURED"
    assert payload["after"]["jcop_modules"] == {m.key: False for m in cm.FUSE_MODULES}
    assert payload["configuration_sealed"] is True
    assert payload["new_key_kcvs"] == [ssd.kcv_des(TEST_KEY).hex().upper()] * 3
    assert payload["card_kcvs_match"] is True
    assert payload["new_keys_authenticate"] is True
    changes = _changes(card)
    assert [c[:4] for c in changes] == ["80E4"] * 4 + ["80F0", "80F0", "80D8"]
    assert [c[4:8] for c in changes[4:6]] == ["8007", "800F"]
    assert card.opened == [DEFAULT_GP_KEY, TEST_KEY]


def test_fuse_skips_what_the_card_has_already_done(card):
    card.lifecycle = cm.SECURED
    card.loaded = set()
    result = run(["--json", "factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [s["result"] for s in payload["steps"]] == ["absent"] * 4 + ["locked"]
    assert not any(c.startswith("80F0") for c in card.sent)


def test_fuse_from_initialized_sets_only_secured(card):
    card.lifecycle = cm.INITIALIZED
    result = run(["--json", "factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code == 0, result.output
    assert [c[4:8] for c in card.sent if c.startswith("80F0")] == ["800F"]


def test_fuse_global_yes_also_skips_the_prompt(card):
    result = run(["--json", "--yes", "factory", "card", "fuse", "--default-keys"])
    assert result.exit_code == 0, result.output


def test_fuse_without_y_refuses_non_interactively_before_any_change(card):
    result = run(["--json", "factory", "card", "fuse", "--default-keys"])
    assert result.exit_code != 0
    assert "pass -y" in result.output
    assert _changes(card) == []
    assert "cannot be undone" in result.stderr


class _TtySys:
    class _Stdin:
        def isatty(self):
            return True

        def __getattr__(self, name):
            return getattr(sys.stdin, name)

    stdin = _Stdin()

    def __getattr__(self, name):
        return getattr(sys, name)


def test_fuse_asks_for_the_phrase_and_a_wrong_answer_changes_nothing(card, monkeypatch):
    monkeypatch.setattr(factory_cmd, "sys", _TtySys())
    result = run(["factory", "card", "fuse", "--default-keys"], input="fuse-card\n")
    assert result.exit_code != 0
    assert "Lifecycle: OP_READY" in result.output
    assert "piv sample module (D276000085304A434F5076): present" in result.output
    assert "cannot be undone" in result.output
    assert "Type FUSE-CARD to continue" in result.output
    assert _changes(card) == []


def test_fuse_proceeds_on_the_phrase(card, monkeypatch):
    monkeypatch.setattr(factory_cmd, "sys", _TtySys())
    result = run(["factory", "card", "fuse", "--default-keys"], input="FUSE-CARD\n")
    assert result.exit_code == 0, result.output
    assert "Fuse sequence complete" in result.output


def test_fuse_randomize_needs_out(card):
    result = run(["factory", "card", "fuse", "--default-keys", "--randomize", "-y"])
    assert result.exit_code != 0
    assert "--randomize needs --out" in result.output
    assert card.opened == []


def test_fuse_randomize_writes_the_key_file_before_the_lock(card, tmp_path, monkeypatch):
    out = tmp_path / "card-keys.json"
    card.key_file = str(out)
    monkeypatch.setattr(factory_cmd.os, "urandom", lambda n: TEST_KEY[:n])
    result = run(
        [
            "--json",
            "factory",
            "card",
            "fuse",
            "--default-keys",
            "--randomize",
            "--out",
            str(out),
            "-y",
        ]
    )
    assert result.exit_code == 0, result.output
    assert card.files_seen_at_put_key == [True]
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    record = json.loads(out.read_text())
    assert record["enc"] == TEST_KEY.hex().upper()
    assert record["kcv"] == json.loads(result.stdout)["new_key_kcvs"]
    assert record["ic_serial"] and record["key_version"] == 1


def test_fuse_never_overwrites_a_key_file(card, tmp_path):
    out = tmp_path / "card-keys.json"
    out.write_text("{}")
    result = run(
        ["factory", "card", "fuse", "--default-keys", "--randomize", "--out", str(out), "-y"]
    )
    assert result.exit_code != 0
    assert "never overwritten" in result.output
    assert out.read_text() == "{}"


def test_fuse_refuses_the_test_key_as_new_key(card, monkeypatch):
    for part in ("ENC", "MAC", "DEK"):
        monkeypatch.setenv(f"CARD_MANAGER_NEW_{part}", DEFAULT_GP_KEY.hex())
    result = run(["factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code != 0
    assert "publicly known test keys" in result.output
    assert card.opened == []


def test_fuse_requires_new_keys(card, monkeypatch):
    monkeypatch.delenv("CARD_MANAGER_NEW_ENC")
    result = run(["factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code != 0
    assert "CARD_MANAGER_NEW_ENC" in result.output


def test_fuse_dry_run_needs_no_current_keys_and_changes_nothing(card):
    result = run(["--json", "factory", "card", "fuse", "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["delete"] == ["egovaccelerators", "fips", "piv", "configuration"]
    assert card.opened == [] and card.sent == []


def test_fuse_stops_at_a_refusal_and_names_what_was_done(card):
    card.refuse["80E4" + cm.CONFIG_MODULE_AID.hex().upper()] = 0x6985
    result = run(["factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code != 0
    assert "DELETE configuration module refused (SW=6985)" in result.output
    assert "delete egovaccelerators sample module (deleted)" in result.output
    assert not any(c[2:4] in ("F0", "D8") for c in card.sent)


def test_fuse_refuses_a_locked_card(card):
    card.lifecycle = cm.CARD_LOCKED
    result = run(["factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code != 0
    assert "CARD_LOCKED" in result.output
    assert _changes(card) == []


def test_fuse_refuses_a_card_manager_with_two_key_versions(card, monkeypatch):
    wire_session(
        monkeypatch,
        _SeqConn(
            {SELECT_ISD: (FCI_ISD, *OK), GET_E0: (E0_TWO_VERSIONS, *OK), GET_CPLC: (CPLC, *OK)}
        ),
    )
    result = run(["factory", "card", "fuse", "--default-keys", "-y"])
    assert result.exit_code != 0
    assert "refusing to choose" in result.output
    assert card.opened == []


# ----------------------------------------------------------------- status --- #
def test_status_reports_lifecycle_modules_and_the_sealed_configuration(card):
    result = run(["--json", "factory", "card", "status", "--default-keys"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["lifecycle"] == "OP_READY"
    assert payload["jcop_modules"]["configuration"] is True
    assert payload["configuration_sealed"] is False
    assert "fused" not in payload
    assert _changes(card) == []


def test_status_after_a_fuse_reports_secured_and_sealed(card, monkeypatch):
    run(["--json", "factory", "card", "fuse", "--default-keys", "-y"])
    for part in ("ENC", "MAC", "DEK"):
        monkeypatch.setenv(f"CARD_MANAGER_{part}", TEST_KEY.hex())
    result = run(["--json", "factory", "card", "status"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["lifecycle"] == "SECURED"
    assert payload["configuration_sealed"] is True
