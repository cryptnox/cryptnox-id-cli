# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The Windows UAC relaunch of ``fido`` commands, run on Linux.

On Windows a ``fido`` command relaunches itself through a UAC prompt and the child
writes its result to ``--elevated-result-out`` for the parent to show. The child's
console closes when it exits, so an error the child only printed there is lost.
"""

from __future__ import annotations

import json
import os

import pytest
from _cardfakes import QueueConn, fake_tty, run, wire_session
from test_fido_pinproto import FakeFidoCard

from cryptnox_id_cli.cli.commands import fido as fido_cmd
from cryptnox_id_cli.transport import elevation

CHILD_ERROR = {"error": "applet_not_found", "message": "FIDO2 applet not found on this card."}
CHILD_RESULT = {"selected": True, "version": "FIDO_2_1"}


def test_the_child_writes_its_error_to_the_result_file(tmp_path, monkeypatch):
    wire_session(monkeypatch, QueueConn([(b"", 0x6A, 0x82)]))  # SELECT: no FIDO applet
    out = tmp_path / "result.json"
    result = run(["--json", "--elevated-result-out", str(out), "fido", "ping"])
    assert result.exit_code != 0
    assert json.loads(result.stdout) == CHILD_ERROR
    assert json.loads(out.read_text()) == CHILD_ERROR


def test_the_child_still_writes_its_result_to_the_result_file(tmp_path, monkeypatch):
    wire_session(monkeypatch, QueueConn([(b"U2F_V2", 0x90, 0x00)]))
    out = tmp_path / "result.json"
    result = run(["--json", "--elevated-result-out", str(out), "fido", "ping"])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text()) == {"selected": True, "version": "U2F_V2"}


def _windows(monkeypatch, *, code=None, write=None, elevated=False, card=None):
    """A Windows terminal; the relaunched child writes ``write`` and exits ``code``."""
    calls: list[list[str]] = []
    monkeypatch.setattr(elevation, "is_windows", lambda: True)
    monkeypatch.setattr(elevation, "is_elevated", lambda: elevated)
    monkeypatch.setattr(fido_cmd, "is_windows", lambda: True)

    def relaunch(args):
        calls.append(list(args))
        if write is not None:
            with open(args[args.index("--elevated-result-out") + 1], "w", encoding="utf-8") as fh:
                fh.write(write)
        return code

    monkeypatch.setattr(fido_cmd, "relaunch_elevated", relaunch)
    wire_session(monkeypatch, card or QueueConn([]))  # by default the parent must not touch it
    return calls


def test_the_parent_shows_the_child_error_in_json(monkeypatch):
    calls = _windows(monkeypatch, code=1, write=json.dumps(CHILD_ERROR))
    result = run(["--json", "--yes", "fido", "ping"])
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout) == CHILD_ERROR
    assert not os.path.exists(calls[0][2])


def test_the_parent_shows_the_child_error_as_an_error(monkeypatch):
    _windows(monkeypatch, code=1, write=json.dumps(CHILD_ERROR))
    result = run(["--yes", "fido", "ping"])
    assert result.exit_code == 1, result.output
    assert "error: FIDO2 applet not found on this card." in result.output
    assert "Administrator" in result.output
    assert "result (ran as Administrator)" not in result.output


def test_the_parent_still_shows_a_child_result(monkeypatch):
    _windows(monkeypatch, code=0, write=json.dumps(CHILD_RESULT))
    result = run(["--yes", "fido", "ping"])
    assert result.exit_code == 0, result.output
    assert "result (ran as Administrator)" in result.output
    assert "FIDO_2_1" in result.output


@pytest.mark.parametrize("write", [None, "  \n"], ids=["no-file", "blank-file"])
def test_a_child_that_left_no_result_says_where_its_output_went(monkeypatch, write):
    _windows(monkeypatch, code=3, write=write)
    result = run(["--yes", "fido", "ping"])
    assert result.exit_code == 1, result.output
    assert "elevated FIDO2 command failed (exit 3)" in result.output
    assert "left no result" in result.output


def test_the_parent_relaunches_with_a_result_file_and_shows_the_json(monkeypatch):
    calls = _windows(monkeypatch, code=0, write=json.dumps(CHILD_RESULT))
    result = run(["--json", "--yes", "fido", "ping"])
    assert result.exit_code == 0, result.output
    assert calls[0][:2] == ["--json", "--elevated-result-out"]
    assert not os.path.exists(calls[0][2])
    assert json.loads(result.stdout) == CHILD_RESULT
    assert "NOT elevated" in result.output


def test_a_declined_uac_prompt_falls_back_to_the_windows_guidance(monkeypatch):
    _windows(monkeypatch, code=None)
    result = run(["--json", "--yes", "fido", "ping"])
    assert result.exit_code == 4, result.output
    assert "WebAuthn" in result.stdout


def test_a_child_that_succeeded_silently_exits_0(monkeypatch):
    calls = _windows(monkeypatch, code=0)
    result = run(["--json", "--yes", "fido", "ping"])
    assert result.exit_code == 0, result.output
    assert not os.path.exists(calls[0][2])


def test_json_without_yes_does_not_offer_a_relaunch(monkeypatch):
    calls = _windows(monkeypatch, code=0, card=FakeFidoCard())
    result = run(["--json", "fido", "ping"])
    assert calls == []
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["version"] == "FIDO_2_1"
    assert "NOT elevated" in result.output


@pytest.mark.parametrize(("answer", "relaunched"), [("y\n", True), ("n\n", False)])
def test_a_terminal_user_is_asked_before_the_uac_prompt(monkeypatch, answer, relaunched):
    card = FakeFidoCard()
    calls = _windows(monkeypatch, code=0, write=json.dumps(CHILD_RESULT), card=card)
    fake_tty(monkeypatch, fido_cmd)
    result = run(["fido", "ping"], input=answer)
    assert result.exit_code == 0, result.output
    assert "Re-run this command as Administrator now?" in result.output
    assert bool(calls) is relaunched
    assert (card.sent == []) is relaunched


def test_an_elevated_terminal_gets_a_note_and_runs_directly(monkeypatch):
    calls = _windows(monkeypatch, elevated=True, card=FakeFidoCard())
    result = run(["fido", "ping"])
    assert result.exit_code == 0, result.output
    assert calls == []
    assert "This terminal is elevated." in result.stdout
    assert "FIDO2 applet selected." in result.stdout
