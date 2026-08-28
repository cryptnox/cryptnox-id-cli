"""Safety-review follow-ups on the perso admin-channel writes and object reads.

Safety review 2026-08-21:

* Finding (low): ``piv perso set-pin``/``set-puk`` and ``write-object``/
  ``write-standard-objects`` are admin-channel scripting primitives - no confirm
  gate by policy - but each must state what it overwrites (set-pin/set-puk
  replace the current value without needing it; the object writes overwrite the
  container's current content).
* Finding (medium): PIN-protected cardholder objects (printed, fingerprints,
  facial) must not land in the "secrets redacted" APDU transcript; a plain
  object's bytes still appear there. Stdout keeps showing the content - the
  user asked for it.
"""

from __future__ import annotations

import contextlib

from click.testing import CliRunner

from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.transport.apdu import Response

OK = Response(b"", 0x90, 0x00)


@contextlib.contextmanager
def _fake_session(self):
    yield object()


def _run(args, **kw):
    return CliRunner().invoke(root, args, **kw)


# ------------------------------------------------- admin-channel warnings --- #
def test_set_pin_warns_it_replaces_without_current_value(monkeypatch):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(piv_cmd, "_set_verifier", lambda adm, keys, ref, padded, label: OK)
    result = _run(
        ["piv", "perso", "set-pin", "--default-keys"], env={"CRYPTNOX_PIV_NEW_PIN": "123456"}
    )
    assert result.exit_code == 0, result.output
    # Warns, but never prompts: this is a scripting primitive.
    assert "replaces the current PIN without needing its value" in result.output


def test_set_puk_warns_it_replaces_without_current_value(monkeypatch):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(piv_cmd, "_set_verifier", lambda adm, keys, ref, padded, label: OK)
    result = _run(
        ["piv", "perso", "set-puk", "--default-keys"], env={"CRYPTNOX_PIV_NEW_PUK": "12345678"}
    )
    assert result.exit_code == 0, result.output
    assert "replaces the current PUK without needing its value" in result.output


class _FakeAdmin:
    def __init__(self, session):
        pass

    def select(self):
        pass

    def open(self, keys):
        pass

    def send(self, apdu, context=None):
        return OK


def test_write_object_warns_it_overwrites_container(monkeypatch, tmp_path):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(piv_cmd, "PivAdmin", _FakeAdmin)
    blob = tmp_path / "chuid.bin"
    blob.write_bytes(b"\x01\x02")
    result = _run(
        [
            "piv",
            "perso",
            "write-object",
            "--object",
            "chuid",
            "--file",
            str(blob),
            "--default-keys",
        ]
    )
    assert result.exit_code == 0, result.output
    assert "overwrites the chuid container's current content" in result.output


def test_write_standard_objects_warns_it_overwrites_containers(monkeypatch):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(
        piv_cmd,
        "_write_standard",
        lambda adm, keys, names: [{"object": n, "ok": True, "sw": "9000"} for n in names],
    )
    result = _run(["piv", "perso", "write-standard-objects", "--default-keys"])
    assert result.exit_code == 0, result.output
    assert "overwrites the current content of the chuid and ccc containers" in result.output


def test_default_keys_help_says_publicly_known():
    result = _run(["piv", "perso", "set-pin", "--help"])
    assert result.exit_code == 0
    assert "publicly known" in result.output


# ----------------------------------------- transcript redaction on reads --- #
class _FakeConn:
    """Minimal RawConnection: VERIFY succeeds, GET DATA returns a canned object."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def transmit(self, apdu):
        ins = apdu[1]
        if ins == 0x20:  # VERIFY
            return [], 0x90, 0x00
        if ins == 0xCB:  # GET DATA - 53-wrapped object content
            body = bytes([0x53, len(self._payload)]) + self._payload
            return list(body), 0x90, 0x00
        return [], 0x90, 0x00

    def get_atr(self):
        return b"\x3b\x00"

    def disconnect(self):
        pass


def _wire_card(monkeypatch, payload: bytes):
    """Route the CLI at a real CardSession (redactor + transcript) over a fake card."""
    monkeypatch.setattr(
        AppContext, "open_session", lambda self: self.make_session(_FakeConn(payload))
    )
    monkeypatch.setattr(piv_cmd, "_select", PivApplet)


# Distinctive bytes that must not appear in the transcript when PIN-protected.
PAYLOAD = bytes.fromhex("A5DEADBEEF015AC0FE")


def test_pin_protected_object_is_masked_in_transcript(monkeypatch, tmp_path):
    _wire_card(monkeypatch, PAYLOAD)
    log = tmp_path / "apdu.log"
    result = _run(
        ["--apdu-log", str(log), "piv", "objects", "read", "--object", "printed"],
        env={"CRYPTNOX_PIV_PIN": "123456"},
    )
    assert result.exit_code == 0, result.output
    transcript = log.read_text()
    assert PAYLOAD.hex().upper() not in transcript, "PIN-gated content leaked into the transcript"
    assert f"<REDACTED:{len(PAYLOAD)}B>" in transcript
    # Stdout still shows the content - the user asked for it.
    assert PAYLOAD.hex().upper() in result.output


def test_plain_object_stays_visible_in_transcript(monkeypatch, tmp_path):
    _wire_card(monkeypatch, PAYLOAD)
    log = tmp_path / "apdu.log"
    result = _run(["--apdu-log", str(log), "piv", "objects", "read", "--object", "chuid"])
    assert result.exit_code == 0, result.output
    transcript = log.read_text()
    assert PAYLOAD.hex().upper() in transcript
    assert "<REDACTED:" not in transcript
    assert PAYLOAD.hex().upper() in result.output
