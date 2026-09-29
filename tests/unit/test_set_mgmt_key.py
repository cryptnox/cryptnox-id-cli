"""`factory piv preperso set-mgmt-key`: what it writes, and what it refuses to write.

Loading a card's administration key changes who can administer the card, so the
command's value is mostly in its refusals: it never creates a missing key object, and
it never overwrites a value that is already there without ``--replace``. The applet
does not overwrite silently either (it answers 6985), but the CLI must not rely on
that to decide whether an operator meant it.
"""

from __future__ import annotations

import contextlib
import json

import pytest
from click.testing import CliRunner

from cryptnox_id_cli.applets.piv import mgmt_auth as ma
from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.util import tlv

KEY256 = bytes(range(32))
WITNESS = bytes.fromhex("A7E57B882467107902739D50387B3651")


class FakeSession:
    """Answers SELECT and the 9B witness request; records everything sent."""

    reader_name = "Fake Contact Reader 00 00"

    def __init__(self, *, witness_sw: int, mechanism: int = 0x0C) -> None:
        self.witness_sw = witness_sw
        self.mechanism = mechanism
        self.sent: list[str] = []

    @property
    def atr(self) -> bytes:
        return bytes.fromhex("3BFA1300008131FE454A434F5033")

    def transmit(self, apdu, *, context: str | None = None) -> Response:
        self.sent.append(apdu.to_bytes().hex().upper())
        if apdu.ins == 0xA4:
            return Response(b"", 0x90, 0x00)
        if apdu.ins == 0x87:
            if apdu.p1 != self.mechanism:
                return Response(b"", 0x6A, 0x86)
            if self.witness_sw != 0x9000:
                return Response(b"", self.witness_sw >> 8, self.witness_sw & 0xFF)
            body = tlv.build_constructed(
                ma.TAG_DYNAMIC_AUTH,
                tlv.build(ma.TAG_WITNESS, ma.aes_ecb_encrypt(KEY256, WITNESS)),
            )
            return Response(body, 0x90, 0x00)
        return Response(b"", 0x6A, 0x82)


class FakeAdmin:
    def __init__(self, session: FakeSession, write_sw: int = 0x9000) -> None:
        self.card = session
        self.write_sw = write_sw
        self.events: list[str] = []
        self.writes: list[str] = []

    def select(self) -> None:
        self.events.append("select")

    def initialize_update_probe(self, key_version: int = 0) -> dict[str, object]:
        return {"supported": True, "scp_version": 0x03}

    def open(self, keys) -> None:
        self.events.append("open")

    def send(self, apdu, *, context: str | None = None) -> Response:
        self.writes.append(apdu.to_bytes().hex().upper())
        self.events.append(f"send:{apdu.ins:02X}")
        return Response(b"", self.write_sw >> 8, self.write_sw & 0xFF)


def _run(monkeypatch, session, adm, args, *, env_key: str | None = KEY256.hex()):
    @contextlib.contextmanager
    def fake_session(self):
        yield session

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(factory_cmd, "PivAdmin", lambda s: adm)
    for var in ("PIV_SCP03_ENC", "PIV_SCP03_MAC", "PIV_SCP03_DEK"):
        monkeypatch.setenv(var, "40" * 16)
    monkeypatch.delenv("CARD_PIV_MGMT_KEY", raising=False)
    if env_key is None:
        monkeypatch.delenv("PIV_MGMT_KEY", raising=False)
    else:
        monkeypatch.setenv("PIV_MGMT_KEY", env_key)
    return CliRunner().invoke(root, args)


BASE = ["--json", "factory", "piv", "preperso", "set-mgmt-key"]


def test_an_empty_object_is_loaded_with_one_write(monkeypatch):
    session = FakeSession(witness_sw=0x6983)
    adm = FakeAdmin(session)
    result = _run(monkeypatch, session, adm, BASE)
    assert result.exit_code == 0, result.output
    assert adm.writes == ["00240C9B228020" + KEY256.hex().upper()]
    payload = json.loads(result.stdout)
    assert payload["action"] == "set"
    assert payload["mechanism"] == "AES-256"
    assert payload["source"] == "$PIV_MGMT_KEY"


@pytest.mark.parametrize("witness_sw", [0x9000, 0x6985])
def test_a_value_already_set_is_never_replaced_without_the_flag(monkeypatch, witness_sw):
    # 6985 too: the applet checks "has a value" before it checks the attributes, so
    # anything but 6983 proves a value is there.
    session = FakeSession(witness_sw=witness_sw)
    adm = FakeAdmin(session)
    result = _run(monkeypatch, session, adm, BASE)
    assert result.exit_code == 7
    assert json.loads(result.stdout)["stage"] == "set_value"
    assert adm.writes == [], "nothing may be written before the operator asks for it"


def test_replace_clears_first_then_sets_each_in_its_own_session(monkeypatch):
    session = FakeSession(witness_sw=0x9000)
    adm = FakeAdmin(session)
    result = _run(monkeypatch, session, adm, [*BASE, "--replace"])
    assert result.exit_code == 0, result.output
    assert adm.writes == [
        "00240C9B029F00",
        "00240C9B228020" + KEY256.hex().upper(),
    ]
    # One probe SELECT, then a fresh channel for the CLEAR and another for the SET.
    assert adm.events == [
        "select",
        "select",
        "open",
        "send:24",
        "select",
        "open",
        "send:24",
    ]
    assert json.loads(result.stdout)["action"] == "replaced"
    assert "invalidates every credential" in result.stderr


def test_a_missing_key_object_is_not_created(monkeypatch):
    session = FakeSession(witness_sw=0x9000, mechanism=0x99)  # matches no candidate
    adm = FakeAdmin(session)
    result = _run(monkeypatch, session, adm, BASE)
    assert result.exit_code == 7
    assert json.loads(result.stdout)["stage"] == "missing"
    assert adm.writes == []


def test_a_value_of_the_wrong_length_for_the_card_is_refused_before_writing(monkeypatch):
    session = FakeSession(witness_sw=0x6983, mechanism=0x08)
    adm = FakeAdmin(session)
    result = _run(monkeypatch, session, adm, BASE)  # 32-byte value, AES-128 object
    assert result.exit_code == 7
    assert json.loads(result.stdout)["stage"] == "key_length"
    assert adm.writes == []


def test_an_inaccessible_interface_is_named_as_such(monkeypatch):
    session = FakeSession(witness_sw=0x6982)
    adm = FakeAdmin(session)
    result = _run(monkeypatch, session, adm, BASE)
    assert result.exit_code == 7
    assert json.loads(result.stdout)["stage"] == "access"
    assert adm.writes == []


def test_a_refused_write_reports_the_cards_own_reason(monkeypatch):
    session = FakeSession(witness_sw=0x6983)
    adm = FakeAdmin(session, write_sw=0x6A88)
    result = _run(monkeypatch, session, adm, BASE)
    assert result.exit_code == 7
    assert "no 9B key object" in json.loads(result.stdout)["message"]


def test_no_value_supplied_is_an_input_error_not_a_card_error(monkeypatch):
    session = FakeSession(witness_sw=0x6983)
    adm = FakeAdmin(session)
    result = _run(monkeypatch, session, adm, BASE, env_key=None)
    assert result.exit_code == 3
    assert "--default-keys" in json.loads(result.stdout)["message"]


def test_dry_run_refuses_before_a_session_opens(monkeypatch):
    def no_session(self):
        raise AssertionError("--dry-run opened a card session")

    monkeypatch.setattr(AppContext, "open_session", no_session)
    result = CliRunner().invoke(root, ["--dry-run", *BASE[1:], "--default-keys"])
    assert result.exit_code != 0
    assert "cannot preview its card operations" in result.output


# ------------------------------------------------------------------- status ---
def test_status_reports_whether_9b_holds_a_value(monkeypatch):
    session = FakeSession(witness_sw=0x6983)
    adm = FakeAdmin(session)

    @contextlib.contextmanager
    def fake_session(self):
        yield session

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(factory_cmd, "PivAdmin", lambda s: adm)

    class _State:
        piv = factory_cmd.PivState.PRE_PERSONALIZED

    monkeypatch.setattr(
        factory_cmd, "StateDetector", lambda *a, **kw: type("D", (), {"detect": lambda s: _State})()
    )
    result = CliRunner().invoke(root, ["--json", "factory", "piv", "preperso", "status"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["management_key"] == {
        "present": True,
        "mechanism": "AES-256",
        "value_set": False,
        "sw": "6983",
    }
