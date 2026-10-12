"""`preperso status` must report finalize under the same rule `finalize` applies."""

import contextlib
import json

import pytest
from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.state.model import PivState

SELECTABLE = [PivState.PRE_PERSONALIZED, PivState.PARTIALLY_PERSONALIZED, PivState.PERSONALIZED]


def _status(monkeypatch, piv_state, *, secured=None, json_out=True):
    @contextlib.contextmanager
    def fake_session(self):
        yield object()

    class _State:
        piv = piv_state
        piv_secured = secured

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(factory_cmd, "describe_security_domain", lambda session: None)
    monkeypatch.setattr(factory_cmd, "_probe_mgmt_key", lambda session: None)
    monkeypatch.setattr(
        factory_cmd, "StateDetector", lambda *a, **kw: type("D", (), {"detect": lambda s: _State})()
    )
    args = ["factory", "piv", "preperso", "status"]
    result = CliRunner().invoke(root, (["--json"] if json_out else []) + args)
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout) if json_out else result.output


@pytest.mark.parametrize("state", SELECTABLE)
def test_finalize_allowed_on_any_selectable_unsecured_card(monkeypatch, state):
    payload = _status(monkeypatch, state, secured=False)
    assert payload["finalize_allowed"] is True
    assert payload["load_config_allowed"] is (state == PivState.PRE_PERSONALIZED)


@pytest.mark.parametrize("state", SELECTABLE)
def test_unreadable_secured_flag_does_not_block_finalize(monkeypatch, state):
    payload = _status(monkeypatch, state)
    assert payload["secured"] is None
    assert payload["finalize_allowed"] is True


@pytest.mark.parametrize("state", [PivState.NOT_PRESENT, PivState.UNKNOWN])
def test_finalize_not_allowed_when_the_applet_is_not_selectable(monkeypatch, state):
    payload = _status(monkeypatch, state)
    assert payload["finalize_allowed"] is False
    assert payload["load_config_allowed"] is False


def test_nothing_allowed_once_secured(monkeypatch):
    payload = _status(monkeypatch, PivState.PRE_PERSONALIZED, secured=True)
    assert payload["secured"] is True
    assert payload["finalize_allowed"] is False
    assert payload["load_config_allowed"] is False
    out = _status(monkeypatch, PivState.PRE_PERSONALIZED, secured=True, json_out=False)
    assert "Finalized (SECURED): yes" in out
    assert "already finalized" in out
    assert "structure is finalized" in out


def test_human_output_no_longer_says_finalize_is_not_allowed_with_structure(monkeypatch):
    out = _status(monkeypatch, PivState.PARTIALLY_PERSONALIZED, secured=False, json_out=False)
    assert "Finalize: allowed" in out
    assert "finalize is NOT allowed" not in out
    assert "structure present" in out
    assert "Finalized (SECURED): no" in out
