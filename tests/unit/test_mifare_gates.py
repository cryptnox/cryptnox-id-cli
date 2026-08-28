"""mifare data-destroying gates and default-key disclosure.

Safety review 2026-08-21: `mifare record clear` and `mifare write` ran ungated while
the sibling file-system commands warn + confirm (medium); `mifare sdm setup` silently
authenticated with the all-zero factory default key (medium); `mifare sdm read`
printed a flat MAC verdict computed against the factory default keys (medium); later
--zero-key help strings dropped the factory-default qualifier and the module
docstring claimed read-only (low).

`value credit/debit` and `record write` stay ungated on purpose: they are
transactional data-plane operations, not file-system destruction.
"""

from __future__ import annotations

import click
from click.testing import CliRunner

from cryptnox_id_cli.applets.mifare import desfire as df
from cryptnox_id_cli.cli.commands import mifare as mifare_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root


class _FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeDtx:
    """Just enough DesfireTransport surface for the gated commands; never a real card."""

    def __init__(self, session):
        pass

    def select_application(self, aid):
        pass

    @staticmethod
    def data_header(file_no, offset, length):
        return bytes([file_no]) + offset.to_bytes(3, "little") + length.to_bytes(3, "little")

    def create_std_data_file(self, file_no, size, comm=0, access=0, sdm=False):
        pass

    def raw_command(self, cmd, data=b"", context=""):
        return df.STATUS_OK, b""

    def read_data_plain(self, file_no, offset, length):  # overridden by the sdm-read tests
        return b""


def _wire(monkeypatch):
    """Fake the card: session, transport, EV2 auth, and the MACed command channel."""
    calls = {"macked": [], "auth": None}

    monkeypatch.setattr(AppContext, "open_session", lambda self: _FakeSession())
    monkeypatch.setattr(mifare_cmd, "DesfireTransport", _FakeDtx)

    def fake_auth(dtx, key_no, key):
        calls["auth"] = (key_no, key)
        return object()

    monkeypatch.setattr(mifare_cmd, "authenticate_ev2_first", fake_auth)

    def fake_macked(dtx, ev2, cmd, data=b"", **kwargs):
        calls["macked"].append(kwargs.get("context", ""))
        return b""

    monkeypatch.setattr(mifare_cmd, "command_macked", fake_macked)
    monkeypatch.setattr(
        mifare_cmd,
        "change_file_settings",
        lambda *a, **k: calls["macked"].append("ChangeFileSettings SDM"),
    )
    return calls


def _run(args, **kw):
    return CliRunner().invoke(root, args, **kw)


WRITE_ARGS = [
    "mifare",
    "write",
    "--aid",
    "010203",
    "--file-id",
    "01",
    "--data",
    "AABB",
    "--zero-key",
]
CLEAR_ARGS = ["mifare", "record", "clear", "--aid", "010203", "--file-id", "01", "--zero-key"]
SDM_SETUP_ARGS = ["mifare", "sdm", "setup", "--aid", "010203", "--file-id", "02"]


# -- mifare write ----------------------------------------------------------- #


def test_write_declined_confirmation_aborts(monkeypatch):
    calls = _wire(monkeypatch)
    result = _run(WRITE_ARGS, input="n\n")
    assert result.exit_code != 0
    assert calls["macked"] == [], "data was written despite declined confirmation"
    assert "overwrites data" in result.output


def test_write_non_interactive_fails_closed(monkeypatch):
    # No TTY, no --yes: click.confirm aborts -> the file content must survive.
    calls = _wire(monkeypatch)
    result = _run(WRITE_ARGS)
    assert result.exit_code != 0
    assert calls["macked"] == []


def test_write_proceeds_with_yes(monkeypatch):
    calls = _wire(monkeypatch)
    result = _run(["--yes", *WRITE_ARGS])
    assert result.exit_code == 0, result.output
    assert "WriteData" in calls["macked"]
    assert "overwrites data" in result.output  # consent given, consequence still stated


# -- mifare record clear ---------------------------------------------------- #


def test_record_clear_declined_confirmation_aborts(monkeypatch):
    calls = _wire(monkeypatch)
    result = _run(CLEAR_ARGS, input="n\n")
    assert result.exit_code != 0
    assert calls["macked"] == [], "records were cleared despite declined confirmation"
    assert "permanently erases ALL records" in result.output


def test_record_clear_non_interactive_fails_closed(monkeypatch):
    calls = _wire(monkeypatch)
    result = _run(CLEAR_ARGS)
    assert result.exit_code != 0
    assert calls["macked"] == []


def test_record_clear_proceeds_with_yes(monkeypatch):
    calls = _wire(monkeypatch)
    result = _run(["--yes", *CLEAR_ARGS])
    assert result.exit_code == 0, result.output
    assert "ClearRecordFile" in calls["macked"]
    assert "CommitTransaction" in calls["macked"]


# -- mifare sdm setup ------------------------------------------------------- #


def test_sdm_setup_requires_an_explicit_key_choice(monkeypatch):
    # No more silent all-zero authentication: the key source must be named.
    calls = _wire(monkeypatch)
    result = _run(["--yes", *SDM_SETUP_ARGS])
    assert result.exit_code != 0
    assert calls["auth"] is None, "authenticated without an explicit key choice"
    assert "--zero-key" in result.output


def test_sdm_setup_zero_key_authenticates_with_the_factory_default(monkeypatch):
    calls = _wire(monkeypatch)
    result = _run(["--yes", *SDM_SETUP_ARGS, "--zero-key"])
    assert result.exit_code == 0, result.output
    assert calls["auth"] == (0, bytes(16))
    assert "ChangeFileSettings SDM" in calls["macked"]


def test_sdm_setup_key_env_uses_that_key(monkeypatch):
    calls = _wire(monkeypatch)
    monkeypatch.setenv("SDM_APP_KEY0", "00112233445566778899AABBCCDDEEFF")
    result = _run(["--yes", *SDM_SETUP_ARGS, "--key-env", "SDM_APP_KEY0"])
    assert result.exit_code == 0, result.output
    assert calls["auth"] == (0, bytes.fromhex("00112233445566778899AABBCCDDEEFF"))


# -- mifare sdm read -------------------------------------------------------- #


def _wire_sdm_read(monkeypatch, *, mac_matches: bool):
    _wire(monkeypatch)
    text = "https://x.example/t?picc=" + "00" * 16 + "&c=" + "11" * 8
    monkeypatch.setattr(_FakeDtx, "read_data_plain", lambda self, f, o, n: text.encode())
    monkeypatch.setattr(
        mifare_cmd, "sdm_decrypt_picc", lambda key, data: (bytes.fromhex("04AABBCCDDEE11"), 7)
    )
    monkeypatch.setattr(
        mifare_cmd,
        "sdm_file_read_mac",
        lambda key, uid, ctr, inp: bytes.fromhex("11" * 8) if mac_matches else bytes(8),
    )


def test_sdm_read_failure_names_the_factory_default_key(monkeypatch):
    # A rotated-keys tag must not be flatly labelled MAC-invalid.
    _wire_sdm_read(monkeypatch, mac_matches=False)
    result = _run(["mifare", "sdm", "read", "--aid", "010203", "--file-id", "02"])
    assert result.exit_code == 0, result.output
    assert "did not verify with the all-zero factory default keys" in result.output
    assert "genuine" in result.output
    assert "SDMMAC valid: no" not in result.output


def test_sdm_read_success_names_the_key_it_verified_with(monkeypatch):
    _wire_sdm_read(monkeypatch, mac_matches=True)
    result = _run(["mifare", "sdm", "read", "--aid", "010203", "--file-id", "02"])
    assert result.exit_code == 0, result.output
    assert "verified" in result.output
    assert "all-zero factory default keys" in result.output


# -- help-text and docstring disclosure ------------------------------------- #


def _iter_commands(group: click.Group):
    for cmd in group.commands.values():
        yield cmd
        if isinstance(cmd, click.Group):
            yield from _iter_commands(cmd)


def test_every_zero_key_option_names_the_publicly_known_factory_default():
    seen = 0
    for cmd in _iter_commands(mifare_cmd.command):
        for param in cmd.params:
            if any(opt in ("--zero-key", "--auth-zero-key") for opt in param.opts):
                seen += 1
                assert "publicly known factory default" in (param.help or ""), (
                    f"{cmd.name} {param.opts}: help must say the all-zero key is the "
                    "publicly known factory default"
                )
    assert seen >= 10, "expected the mifare tree to carry many --zero-key options"


def test_module_docstring_no_longer_claims_read_only():
    assert "read-only" not in (mifare_cmd.__doc__ or "")
