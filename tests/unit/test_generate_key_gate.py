"""`piv perso generate-key` must not silently destroy a certified key.

Safety review 2026-08-21, finding 2 (high): the bare command regenerated the slot key
with no warning even when a certificate referenced it (quickstart already refused).
Rule mirrored from quickstart: a present certificate marks the slot as in use ->
confirm (or --yes); an empty certificate container -> proceed as before.
"""

from __future__ import annotations

import contextlib

from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root


def _wire(monkeypatch, *, cert_present: bool):
    """Fake the card: a session that yields, a cert probe, and a key generator."""
    calls = {"generated": False}

    @contextlib.contextmanager
    def fake_session(self):
        yield object()

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(piv_cmd, "_select", lambda session: object())
    monkeypatch.setattr(
        piv_cmd, "_read_cert_der", lambda piv, name: b"\x30\x03" if cert_present else None
    )

    def fake_generate(adm, keys, ref, mech, *, label):
        calls["generated"] = True
        return ec.generate_private_key(ec.SECP256R1()).public_key()

    monkeypatch.setattr(piv_cmd, "_generate_key_on_card", fake_generate)
    return calls


def _run(args, **kw):
    return CliRunner().invoke(root, args, **kw)


ARGS = ["piv", "perso", "generate-key", "--slot", "9C", "--default-keys"]


def test_certified_slot_refuses_without_consent(monkeypatch):
    calls = _wire(monkeypatch, cert_present=True)
    result = _run(ARGS, input="n\n")
    assert result.exit_code != 0
    assert calls["generated"] is False, "key was regenerated despite declined confirmation"
    assert "DESTROYS" in result.output


def test_certified_slot_non_interactive_fails_closed(monkeypatch):
    # No TTY, no --yes: click.confirm aborts -> the key must survive.
    calls = _wire(monkeypatch, cert_present=True)
    result = _run(ARGS)
    assert result.exit_code != 0
    assert calls["generated"] is False


def test_certified_slot_proceeds_with_yes(monkeypatch):
    calls = _wire(monkeypatch, cert_present=True)
    result = _run(["--yes", *ARGS])
    assert result.exit_code == 0, result.output
    assert calls["generated"] is True
    assert "DESTROYS" in result.output  # consent given, but the consequence is still stated


def test_certified_slot_proceeds_on_interactive_yes(monkeypatch):
    calls = _wire(monkeypatch, cert_present=True)
    result = _run(ARGS, input="y\n")
    assert result.exit_code == 0, result.output
    assert calls["generated"] is True


def test_empty_slot_needs_no_confirmation(monkeypatch):
    calls = _wire(monkeypatch, cert_present=False)
    result = _run(ARGS)
    assert result.exit_code == 0, result.output
    assert calls["generated"] is True
    assert "DESTROYS" not in result.output
