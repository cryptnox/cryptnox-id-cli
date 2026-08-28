"""Guards surfaced by the pre-ship review: error-funnel membership + option conflicts."""

import contextlib

import click
import pytest

from cryptnox_id_cli.cli.commands.mifare import _resolve_aes_key
from cryptnox_id_cli.secrets import resolver as resolver_mod
from cryptnox_id_cli.secrets.redaction import Redactor
from cryptnox_id_cli.secrets.resolver import SecretInputError, resolve_scp03_keys
from cryptnox_id_cli.transport.errors import CryptnoxError


def test_secret_input_error_routes_through_funnel():
    # Must be a CryptnoxError so the CLI prints a friendly message / JSON error, not a traceback.
    assert issubclass(SecretInputError, CryptnoxError)
    assert SecretInputError("nope").exit_code == 3


class _Redactor:
    def register(self, _):  # pragma: no cover - trivial
        pass


class _App:
    redactor = _Redactor()


def test_resolve_aes_key_rejects_conflicting_options():
    with pytest.raises(click.UsageError):
        _resolve_aes_key(_App(), zero_key=True, key_env="SOME_KEY")


def test_resolve_aes_key_zero_key():
    assert _resolve_aes_key(_App(), zero_key=True, key_env=None) == bytes(16)


def test_resolve_aes_key_requires_a_source():
    with pytest.raises(click.UsageError):
        _resolve_aes_key(_App(), zero_key=False, key_env=None)


def _invoke_transcript(path):
    """`apdu transcript --file <path>` in dry-run: parses the file, never touches a card."""
    from click.testing import CliRunner

    from cryptnox_id_cli.cli.commands import apdu as apdu_cmd
    from cryptnox_id_cli.cli.context import AppContext

    return CliRunner().invoke(
        apdu_cmd.command,
        ["transcript", "--file", str(path)],
        obj=AppContext(json=True, dry_run=True),
    )


def test_apdu_transcript_accepts_a_utf8_bom(tmp_path):
    """PowerShell 5.1's `Set-Content -Encoding utf8` writes a BOM by default, and
    json.loads rejects it. Found on Windows 2026-08-11; read as utf-8-sig."""
    path = tmp_path / "transcript.json"
    path.write_text('["00A4040000"]', encoding="utf-8-sig")  # utf-8-sig == write a BOM
    assert path.read_bytes().startswith(b"\xef\xbb\xbf"), "test file must actually carry a BOM"

    result = _invoke_transcript(path)
    assert result.exit_code == 0, result.output
    assert "00A4040000" in result.output


def test_apdu_transcript_still_accepts_plain_utf8(tmp_path):
    """The utf-8-sig read must not regress the ordinary no-BOM case, which is what
    every non-Windows tool writes."""
    path = tmp_path / "transcript.json"
    path.write_text('["00A4040000"]', encoding="utf-8")
    assert not path.read_bytes().startswith(b"\xef\xbb\xbf"), "control file must carry no BOM"

    result = _invoke_transcript(path)
    assert result.exit_code == 0, result.output
    assert "00A4040000" in result.output


# --- SCP03 key-resolution wording (safety review 2026-08-21) -------------------

_SCP03_ENV = ("PIV_SCP03_ENC", "PIV_SCP03_MAC", "PIV_SCP03_DEK")


def test_scp03_key_error_does_not_assert_the_card_uses_default_keys(monkeypatch):
    """The no-keys error must present the default keys as one possibility (cards
    still on the publicly known test keys), never as a fact about this card."""
    for var in _SCP03_ENV:
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(SecretInputError) as exc:
        resolve_scp03_keys(Redactor())
    msg = str(exc.value)
    assert "this card uses" not in msg
    assert "--default-keys" in msg
    assert "publicly known" in msg
    for var in _SCP03_ENV:
        assert var in msg


def test_resolver_docstring_admits_the_cli_path_exists():
    """resolver.py claimed secrets come 'never [from] the CLI' while --pin/--puk/
    --password options exist; the docstring must describe the real precedence."""
    doc = resolver_mod.__doc__ or ""
    assert "never the CLI" not in doc
    assert "shell history" in doc


# --- apdu output applies the transcript's response redaction -------------------

_SHARED_SECRET = "CAFEBABE" * 8  # a derived ECDH secret is never pre-registered


def _invoke_apdu(monkeypatch, args, resp_data_hex):
    """Run an apdu subcommand against a fake session returning the given response."""
    from click.testing import CliRunner

    from cryptnox_id_cli.cli.commands import apdu as apdu_cmd
    from cryptnox_id_cli.cli.context import AppContext
    from cryptnox_id_cli.transport.apdu import Response

    @contextlib.contextmanager
    def fake_session(self):
        class _Session:
            def transmit(self, _apdu):
                return Response(bytes.fromhex(resp_data_hex), 0x90, 0x00)

        yield _Session()

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    return CliRunner().invoke(apdu_cmd.command, args, obj=AppContext(json=True))


def test_apdu_send_redacts_general_authenticate_response(monkeypatch):
    """apdu send of a GENERAL AUTHENTICATE (INS 0x87) must mask the response body
    in stdout/JSON exactly as the transcript layer does - the response can carry
    key material (e.g. an ECDH shared secret) that was never registered."""
    result = _invoke_apdu(monkeypatch, ["send", "--hex", "0087119D0401020304"], _SHARED_SECRET)
    assert result.exit_code == 0, result.output
    assert _SHARED_SECRET not in result.output
    assert "REDACTED" in result.output


def test_apdu_send_leaves_non_sensitive_response_visible(monkeypatch):
    result = _invoke_apdu(monkeypatch, ["send", "--hex", "80CA9F7F00"], "ABCD")
    assert result.exit_code == 0, result.output
    assert "ABCD" in result.output


def test_apdu_transcript_redacts_general_authenticate_response(monkeypatch, tmp_path):
    path = tmp_path / "transcript.json"
    path.write_text('["0087119D0401020304"]', encoding="utf-8")
    result = _invoke_apdu(monkeypatch, ["transcript", "--file", str(path)], _SHARED_SECRET)
    assert result.exit_code == 0, result.output
    assert _SHARED_SECRET not in result.output
    assert "REDACTED" in result.output
