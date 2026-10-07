"""`preperso status` must report finalize under the same rule `finalize` applies."""

import contextlib
import json

import pytest
from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.state.model import PivState


class _NoChannel:
    def __init__(self, session):
        pass

    def initialize_update_probe(self):
        return {"supported": False}


def _status(monkeypatch, piv_state):
    @contextlib.contextmanager
    def fake_session(self):
        yield object()

    class _State:
        piv = piv_state

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(factory_cmd, "PivAdmin", _NoChannel)
    monkeypatch.setattr(factory_cmd, "_probe_mgmt_key", lambda session: None)
    monkeypatch.setattr(
        factory_cmd, "StateDetector", lambda *a, **kw: type("D", (), {"detect": lambda s: _State})()
    )
    result = CliRunner().invoke(root, ["--json", "factory", "piv", "preperso", "status"])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "state",
    [PivState.PRE_PERSONALIZED, PivState.PARTIALLY_PERSONALIZED, PivState.PERSONALIZED],
)
def test_finalize_allowed_on_any_selectable_unsecured_card(monkeypatch, state):
    payload = _status(monkeypatch, state)
    assert payload["finalize_allowed"] is True
    assert payload["load_config_allowed"] is (state == PivState.PRE_PERSONALIZED)


@pytest.mark.parametrize("state", [PivState.SECURED, PivState.NOT_PRESENT, PivState.UNKNOWN])
def test_finalize_not_allowed_when_finalize_itself_refuses(monkeypatch, state):
    payload = _status(monkeypatch, state)
    assert payload["finalize_allowed"] is False
    assert payload["load_config_allowed"] is False


def test_human_output_no_longer_says_finalize_is_not_allowed_with_structure(monkeypatch):
    @contextlib.contextmanager
    def fake_session(self):
        yield object()

    class _State:
        piv = PivState.PARTIALLY_PERSONALIZED

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(factory_cmd, "PivAdmin", _NoChannel)
    monkeypatch.setattr(factory_cmd, "_probe_mgmt_key", lambda session: None)
    monkeypatch.setattr(
        factory_cmd, "StateDetector", lambda *a, **kw: type("D", (), {"detect": lambda s: _State})()
    )
    result = CliRunner().invoke(root, ["factory", "piv", "preperso", "status"])
    assert result.exit_code == 0, result.output
    assert "Finalize: allowed" in result.output
    assert "finalize is NOT allowed" not in result.output
    assert "structure present" in result.output
