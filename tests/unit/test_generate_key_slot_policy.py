# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""`piv perso generate-key` applies the host-side slot policy before it opens the card."""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.cli.commands.piv import primitives as piv_cmd
from cryptnox_id_cli.cli.commands.piv.perso import keys as piv_perso
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root


def _wire(monkeypatch):
    """Fake a card that has no key object for the requested (slot, algorithm)."""
    calls = {"opened": False, "created": False, "generated": False}

    class FakeSession:
        def transmit(self, apdu, context=None):
            return SimpleNamespace(sw=0x6A86)

    @contextlib.contextmanager
    def fake_session(self):
        calls["opened"] = True
        yield FakeSession()

    def fake_create(*args, **kwargs):
        calls["created"] = True

    def fake_generate(app, adm, keys, ref, mech, *, label, default_keys=False):
        calls["generated"] = True
        public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        return piv_cmd.GeneratedKey(public_key, "admin-channel", None)

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(piv_perso, "_select", lambda session: object())
    monkeypatch.setattr(piv_perso, "_read_cert_der", lambda piv, name: None)
    monkeypatch.setattr(piv_perso, "_create_key_object", fake_create)
    monkeypatch.setattr(piv_perso, "_generate_key_on_card", fake_generate)
    return calls


def _generate(slot):
    args = ["piv", "perso", "generate-key", "--slot", slot, "--default-keys", "--create-key-object"]
    return CliRunner().invoke(root, args)


@pytest.mark.parametrize(
    ("slot", "reason"),
    [
        ("9B", "admin key"),
        ("04", "secure messaging"),
        ("80", "not a PIV asymmetric key slot"),
    ],
)
def test_non_key_slot_is_refused_before_the_card_is_opened(monkeypatch, slot, reason):
    calls = _wire(monkeypatch)
    result = _generate(slot)
    assert result.exit_code == 2, result.output
    assert reason in result.output
    assert calls == {"opened": False, "created": False, "generated": False}


def test_retired_slot_still_gets_a_key_object_and_a_key(monkeypatch):
    calls = _wire(monkeypatch)
    result = _generate("82")
    assert result.exit_code == 0, result.output
    assert calls == {"opened": True, "created": True, "generated": True}
