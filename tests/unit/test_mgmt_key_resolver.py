"""Where the PIV management key (9B) value may come from, and where it may not.

Same rule as the admin-channel keys: a flag for the published development value, an
environment variable for a real one, never the command line and never a prompt (the
fallback that needs it has to work non-interactively). The value's length is what
picks the mechanism, so a wrong length must be refused here rather than turning into
a confusing card refusal later.
"""

from __future__ import annotations

import pytest

from cryptnox_id_cli.secrets.redaction import Redactor
from cryptnox_id_cli.secrets.resolver import DEFAULT_GP_KEY, SecretInputError, resolve_mgmt_key


@pytest.fixture(autouse=True)
def _no_inherited_env(monkeypatch):
    monkeypatch.delenv("PIV_MGMT_KEY", raising=False)
    monkeypatch.delenv("CARD_PIV_MGMT_KEY", raising=False)


def test_default_keys_serves_both_published_shapes():
    redactor = Redactor()
    material = resolve_mgmt_key(redactor, default_keys=True)
    assert material.source == "--default-keys"
    assert material.keys == {0x08: DEFAULT_GP_KEY, 0x0C: DEFAULT_GP_KEY * 2}
    for value in material.keys.values():
        assert redactor.mask(value.hex().upper()) != value.hex().upper()


@pytest.mark.parametrize(("size", "mechanism"), [(16, 0x08), (24, 0x0A), (32, 0x0C)])
def test_the_value_length_picks_the_mechanism(monkeypatch, size, mechanism):
    value = bytes(range(size))
    monkeypatch.setenv("PIV_MGMT_KEY", value.hex())
    material = resolve_mgmt_key(Redactor())
    assert material.source == "$PIV_MGMT_KEY"
    assert material.keys == {mechanism: value}


def test_the_value_is_registered_for_redaction(monkeypatch):
    value = bytes(range(32))
    monkeypatch.setenv("PIV_MGMT_KEY", value.hex())
    redactor = Redactor()
    resolve_mgmt_key(redactor)
    assert value.hex().upper() not in redactor.mask(value.hex().upper())


@pytest.mark.parametrize(
    "text", ["40:41:42:43:44:45:46:47:48:49:4A:4B:4C:4D:4E:4F", "0x" + "41" * 16]
)
def test_hex_input_tolerates_the_usual_separators(monkeypatch, text):
    monkeypatch.setenv("PIV_MGMT_KEY", text)
    assert len(resolve_mgmt_key(Redactor()).keys[0x08]) == 16


def test_a_value_of_an_impossible_length_is_refused(monkeypatch):
    monkeypatch.setenv("PIV_MGMT_KEY", "00" * 15)
    with pytest.raises(SecretInputError, match="15 bytes; the PIV management key must be"):
        resolve_mgmt_key(Redactor())


def test_the_alias_is_honoured_only_when_the_primary_is_unset(monkeypatch):
    monkeypatch.setenv("CARD_PIV_MGMT_KEY", "AA" * 32)
    assert resolve_mgmt_key(Redactor()).source == "$CARD_PIV_MGMT_KEY"
    monkeypatch.setenv("PIV_MGMT_KEY", "BB" * 32)
    material = resolve_mgmt_key(Redactor())
    assert material.source == "$PIV_MGMT_KEY"
    assert material.keys[0x0C] == b"\xbb" * 32


def test_default_keys_wins_over_the_environment(monkeypatch):
    monkeypatch.setenv("PIV_MGMT_KEY", "AA" * 32)
    assert resolve_mgmt_key(Redactor(), default_keys=True).source == "--default-keys"


def test_nothing_supplied_names_both_ways_to_supply_it():
    with pytest.raises(SecretInputError) as excinfo:
        resolve_mgmt_key(Redactor())
    assert "$PIV_MGMT_KEY" in str(excinfo.value)
    assert "--default-keys" in str(excinfo.value)


def test_the_caller_may_say_why_the_value_is_needed():
    with pytest.raises(SecretInputError, match="because the card truncated the template"):
        resolve_mgmt_key(Redactor(), missing_message="because the card truncated the template")
