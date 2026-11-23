"""APDU 6Cxx retry, input errors, quickstart outputs and small output fixes."""

from __future__ import annotations

import os
import stat

import pytest
from _cardfakes import accept_any_pin, run

from cryptnox_id_cli.cli.commands import info as info_cmd
from cryptnox_id_cli.transport.errors import CryptnoxError, InputError
from cryptnox_id_cli.transport.pcsc import CardSession, _with_le
from cryptnox_id_cli.util.hexutil import from_hex


class Conn:
    """Answers 6C05 to the first command, then echoes success; records frames."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []

    def transmit(self, apdu: list[int]):
        self.frames.append(bytes(apdu))
        if len(self.frames) == 1:
            return [], 0x6C, 0x05
        return [1, 2, 3, 4, 5], 0x90, 0x00

    def get_atr(self) -> bytes:
        return b"\x3b\x00"

    def disconnect(self) -> None:
        pass


@pytest.mark.parametrize(
    ("command", "retry"),
    [
        ("00CA9F7F", "00CA9F7F05"),  # case 1
        ("00CA9F7F00", "00CA9F7F05"),  # case 2
        ("00DB3FFF04AABBCCDD", "00DB3FFF04AABBCCDD05"),  # case 3: the data stays intact
        ("00DB3FFF04AABBCCDD00", "00DB3FFF04AABBCCDD05"),  # case 4
    ],
)
def test_6cxx_retry_sets_le_and_keeps_the_data(command, retry):
    conn = Conn()
    resp = CardSession(conn).transmit(bytes.fromhex(command))
    assert conn.frames[1].hex().upper() == retry
    assert resp.ok


def test_6cxx_retry_leaves_an_extended_apdu_alone():
    assert _with_le(bytes.fromhex("00DB3FFF000004AABBCCDD"), 5) is None


@pytest.mark.parametrize("value", ["ABC", "ZZ11"])
def test_bad_hex_is_an_input_error_that_hides_the_value(value):
    with pytest.raises(InputError) as exc:
        from_hex(value)
    assert value not in str(exc.value)
    assert isinstance(exc.value, ValueError) and isinstance(exc.value, CryptnoxError)


def test_a_bad_slot_is_a_usage_error_not_a_traceback():
    result = run(["piv", "certs", "inspect", "--slot", "ZZ"])
    assert result.exit_code == 2
    assert "not a hex key reference" in result.output
    assert "Traceback" not in result.output


def test_a_bad_mifare_key_env_names_no_value(monkeypatch):
    monkeypatch.setenv("BAD_KEY", "00112233445566778899AABBCCDDEEFG")
    result = run(["mifare", "keys", "authenticate", "--aid", "CC0102", "--key-env", "BAD_KEY"])
    assert result.exit_code == 2
    assert "EEFG" not in result.output and "Traceback" not in result.output


def test_load_spki_takes_der_and_refuses_junk(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from cryptnox_id_cli.cli.commands import piv as piv_cmd

    public = ec.generate_private_key(ec.SECP256R1()).public_key()
    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "k.der"
    path.write_bytes(der)
    assert piv_cmd._load_spki(str(path)) == der
    junk = tmp_path / "junk"
    junk.write_bytes(b"not a key")
    with pytest.raises(InputError, match="PEM or DER"):
        piv_cmd._load_spki(str(junk))


@pytest.mark.parametrize(
    ("raw", "serial"),
    [
        ("9F7F2A" + "00" * 12 + "07848720" + "00" * 26, "07848720"),
        ("9F7F812A" + "00" * 12 + "07848720" + "00" * 26, "07848720"),
    ],
)
def test_cplc_serial_with_short_and_long_form_length(raw, serial):
    body = info_cmd._cplc_body(bytes.fromhex(raw))
    assert body[12:16].hex().upper() == serial


def test_objects_read_out_is_private(tmp_path):
    from cryptnox_id_cli.cli.commands import piv as piv_cmd

    path = tmp_path / "obj.bin"
    piv_cmd._write_private(str(path), b"data")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert path.read_bytes() == b"data"


def test_the_public_zero_key_is_not_redacted(monkeypatch):
    from cryptnox_id_cli.cli.commands import mifare as mifare_cmd
    from cryptnox_id_cli.cli.context import AppContext

    app = AppContext()
    mifare_cmd._resolve_aes_key(app, True, None)
    assert "<REDACTED" not in app.redactor.mask("00" * 16)
    monkeypatch.setenv("K", "11" * 16)
    mifare_cmd._resolve_aes_key(app, False, "K")
    assert "<REDACTED" in app.redactor.mask("11" * 16)


def _done_slot_facts():
    from cryptnox_id_cli.cli.commands import piv as piv_cmd

    return piv_cmd.CardFacts(
        pin_configured=True,
        puk_configured=True,
        structure_present=True,
        key_object_present=True,
        cert_present=True,
        chuid_present=True,
        ccc_present=True,
        key_object_can_sign=True,
    )


def _wire_quickstart(monkeypatch, cert_der: bytes | None = None):
    import contextlib

    from cryptnox_id_cli.cli.commands import piv as piv_cmd
    from cryptnox_id_cli.cli.context import AppContext

    @contextlib.contextmanager
    def no_card(self):
        yield object()

    monkeypatch.setattr(AppContext, "open_session", no_card)
    monkeypatch.setattr(
        piv_cmd, "_collect_quickstart_facts", lambda s, ref, mech: (_done_slot_facts(), "x")
    )
    monkeypatch.setattr(piv_cmd, "_select", lambda s: object())
    accept_any_pin(monkeypatch)
    monkeypatch.setattr(piv_cmd, "_read_cert_der", lambda piv, name: cert_der)
    monkeypatch.setattr(
        piv_cmd, "_sign_with_session", lambda session, ref, mech, pin, build: b"\x00" * 64
    )
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")


@pytest.mark.parametrize("dry_run", [True, False])
def test_quickstart_refuses_csr_out_when_the_slot_keeps_its_certificate(
    monkeypatch, tmp_path, dry_run
):
    _wire_quickstart(monkeypatch)
    csr = tmp_path / "x.csr"
    args = ["--yes", "piv", "quickstart", "--slot", "9C", "--cert-mode", "csr"]
    args += ["--csr-out", str(csr), "--default-keys"] + (["--dry-run"] if dry_run else [])
    result = run(args)
    assert result.exit_code != 0
    assert "generate-csr --slot 9C" in " ".join(result.output.split())
    assert not csr.exists()


def test_quickstart_public_out_comes_from_the_kept_certificate(monkeypatch, tmp_path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kept")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    _wire_quickstart(monkeypatch, cert.public_bytes(serialization.Encoding.DER))
    out = tmp_path / "pub.pem"
    result = run(
        ["--yes", "piv", "quickstart", "--slot", "9C", "--public-out", str(out), "--default-keys"]
    )
    assert result.exit_code == 0, result.output
    written = serialization.load_pem_public_key(out.read_bytes())
    assert written.public_numbers() == key.public_key().public_numbers()
