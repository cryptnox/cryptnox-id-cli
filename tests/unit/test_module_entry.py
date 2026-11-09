"""``python -m cryptnox_id_cli`` reaches the CLI."""

import runpy
import sys

import pytest


def test_module_entry_point_invokes_the_cli(monkeypatch, capsys):
    # runpy, not a subprocess: the __main__ guard only counts as covered when it runs
    # in this interpreter.
    monkeypatch.setattr(sys, "argv", ["cryptnox-id", "--help"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("cryptnox_id_cli", run_name="__main__")
    assert exc.value.code == 0
    assert "Manage the Cryptnox multi-applet smartcard" in capsys.readouterr().out
