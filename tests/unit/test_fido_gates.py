"""Consent gates on `fido config` policy writes.

Safety review 2026-08-21 (medium findings): `min-pin-length` skipped its
confirmation entirely under --json or piped stdin (a one-way change with no consent
at all), and `toggle-always-uv` mutated a device-wide policy with no warning or
confirmation. Both must fail closed: interactive confirm, or --yes; `min-pin-length`
refuses non-interactive use without --yes instead of silently proceeding.

Also pinned here: the fido group help must not describe the group as read-only
while it contains reset and other writes.
"""

from __future__ import annotations

import sys

from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import fido as fido_cmd
from cryptnox_id_cli.cli.main import main as root


def _wire(monkeypatch, payload: dict):
    """Fake the card layer: no elevation talk, and record whether it was reached."""
    calls = {"card": False}
    monkeypatch.setattr(fido_cmd, "_ensure_fido_access", lambda app: None)

    def fake_with_fido(app, action):
        calls["card"] = True
        return payload

    monkeypatch.setattr(fido_cmd, "_with_fido", fake_with_fido)
    return calls


class _FakeSys:
    """The real ``sys``, but ``stdin.isatty()`` reports a terminal. Reads still go
    through whatever stdin CliRunner injected at call time."""

    class _Stdin:
        def isatty(self):
            return True

        def __getattr__(self, name):
            return getattr(sys.stdin, name)

    stdin = _Stdin()

    def __getattr__(self, name):
        return getattr(sys, name)


def _fake_tty(monkeypatch):
    monkeypatch.setattr(fido_cmd, "sys", _FakeSys())


def _run(args, **kw):
    return CliRunner().invoke(root, args, **kw)


TOGGLE = ["fido", "config", "toggle-always-uv"]
TOGGLE_PAYLOAD = {"always_uv_before": False, "always_uv_after": True}

MIN_PIN = ["fido", "config", "min-pin-length", "--length", "6"]
MIN_PIN_PAYLOAD = {
    "min_pin_length_before": 4,
    "min_pin_length_after": 6,
    "force_change_pin": False,
}


# --- toggle-always-uv: device-wide policy needs warn + confirm ---


def test_toggle_declined_confirmation_leaves_card_untouched(monkeypatch):
    calls = _wire(monkeypatch, TOGGLE_PAYLOAD)
    result = _run(TOGGLE, input="n\n")
    assert result.exit_code != 0
    assert calls["card"] is False, "alwaysUv toggled despite declined confirmation"
    assert "DEVICE-WIDE" in result.output


def test_toggle_non_interactive_fails_closed(monkeypatch):
    # No TTY, no --yes: click.confirm aborts -> the policy must not change.
    calls = _wire(monkeypatch, TOGGLE_PAYLOAD)
    result = _run(TOGGLE)
    assert result.exit_code != 0
    assert calls["card"] is False


def test_toggle_proceeds_with_yes(monkeypatch):
    calls = _wire(monkeypatch, TOGGLE_PAYLOAD)
    result = _run(["--yes", *TOGGLE])
    assert result.exit_code == 0, result.output
    assert calls["card"] is True
    assert "DEVICE-WIDE" in result.output  # consent given, consequence still stated


def test_toggle_proceeds_on_interactive_yes(monkeypatch):
    calls = _wire(monkeypatch, TOGGLE_PAYLOAD)
    result = _run(TOGGLE, input="y\n")
    assert result.exit_code == 0, result.output
    assert calls["card"] is True


# --- min-pin-length: one-way, so non-interactive use must name --yes, not vanish ---


def test_min_pin_piped_stdin_refuses_and_names_yes(monkeypatch):
    calls = _wire(monkeypatch, MIN_PIN_PAYLOAD)
    result = _run(MIN_PIN)  # CliRunner stdin is not a tty
    assert result.exit_code != 0
    assert calls["card"] is False, "one-way write proceeded with no consent"
    assert "--yes" in result.output
    assert "INCREASES" in result.output  # the one-way warning is always shown


def test_min_pin_json_refuses_without_yes(monkeypatch):
    calls = _wire(monkeypatch, MIN_PIN_PAYLOAD)
    _fake_tty(monkeypatch)  # even on a tty, --json means no prompt: refuse
    result = _run(["--json", *MIN_PIN])
    assert result.exit_code != 0
    assert calls["card"] is False
    assert "--yes" in result.output


def test_min_pin_yes_proceeds_with_piped_stdin(monkeypatch):
    calls = _wire(monkeypatch, MIN_PIN_PAYLOAD)
    result = _run(["--yes", *MIN_PIN])
    assert result.exit_code == 0, result.output
    assert calls["card"] is True


def test_min_pin_yes_proceeds_under_json(monkeypatch):
    calls = _wire(monkeypatch, MIN_PIN_PAYLOAD)
    result = _run(["--json", "--yes", *MIN_PIN])
    assert result.exit_code == 0, result.output
    assert calls["card"] is True


def test_min_pin_interactive_confirm_proceeds(monkeypatch):
    calls = _wire(monkeypatch, MIN_PIN_PAYLOAD)
    _fake_tty(monkeypatch)
    result = _run(MIN_PIN, input="y\n")
    assert result.exit_code == 0, result.output
    assert calls["card"] is True


def test_min_pin_interactive_decline_aborts(monkeypatch):
    calls = _wire(monkeypatch, MIN_PIN_PAYLOAD)
    _fake_tty(monkeypatch)
    result = _run(MIN_PIN, input="n\n")
    assert result.exit_code != 0
    assert calls["card"] is False


# --- group help: no read-only claim over a group that resets and writes ---


def test_fido_group_help_does_not_claim_read_only():
    result = _run(["fido", "--help"])
    text = " ".join(result.output.split())
    assert "read-only" not in text
    assert "irreversibly erases" in text.lower()
