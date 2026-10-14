"""`piv perso import-cert` checks: `--csr` compares public keys before any card
contact, `--verify-pin` has the slot sign a challenge and verifies it with the
certificate's key. Neither flag leaves the old behaviour (write whatever is given)."""

from __future__ import annotations

import contextlib
import datetime
import json

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.util import tlv


def _self_signed(key, name: str) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def _csr(key, name: str) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


@pytest.fixture(scope="module")
def rsa_keys():
    return rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)


@pytest.fixture
def files(tmp_path, rsa_keys):
    slot_key, other_key = rsa_keys
    cert = tmp_path / "cert.pem"
    cert.write_bytes(_self_signed(slot_key, "slot").public_bytes(serialization.Encoding.PEM))
    csr_same = tmp_path / "same.csr.pem"
    csr_same.write_bytes(_csr(slot_key, "slot"))
    csr_other = tmp_path / "other.csr.pem"
    csr_other.write_bytes(_csr(other_key, "other"))
    return {"cert": str(cert), "csr_same": str(csr_same), "csr_other": str(csr_other)}


class _Session:
    """Answers VERIFY PIN and one GENERAL AUTHENTICATE with a signature made by ``key``
    (raw RSA over the host's EMSA block, or ECDSA over the digest), or a status word."""

    def __init__(self, key=None, sw: int = 0x9000) -> None:
        self.key = key
        self.sw = sw
        self.signed = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def _sign(self, apdu) -> Response:
        self.signed += 1
        if self.sw != 0x9000:
            return Response(b"", self.sw >> 8, self.sw & 0xFF)
        challenge = tlv.find(tlv.parse(apdu.data), 0x81).value
        if isinstance(self.key, rsa.RSAPrivateKey):
            numbers = self.key.private_numbers()
            n = numbers.public_numbers.n
            signature = pow(int.from_bytes(challenge, "big"), numbers.d, n).to_bytes(256, "big")
        else:
            signature = self.key.sign(challenge, ec.ECDSA(Prehashed(hashes.SHA256())))
        body = tlv.build_constructed(0x7C, tlv.build(0x82, signature))
        return Response(body, 0x90, 0x00)

    def transmit(self, apdu, context=None) -> Response:
        return self._sign(apdu)

    def transmit_chained(self, apdu, context=None) -> Response:
        return self._sign(apdu)


class _Piv:
    def verify_pin(self, pin: bytes) -> Response:
        return Response(b"", 0x90, 0x00)


def _wire(monkeypatch, session: _Session, *, imported: list) -> None:
    @contextlib.contextmanager
    def open_session(self):
        yield session

    monkeypatch.setattr(AppContext, "open_session", open_session)
    monkeypatch.setattr(piv_cmd, "_select", lambda s: _Piv())
    monkeypatch.setattr(
        piv_cmd,
        "_import_cert_der",
        lambda adm, keys, ref, der, *, label: (imported.append(der), Response(b"", 0x90, 0x00))[1],
    )
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")


def _run(args):
    return CliRunner().invoke(root, ["--json", "piv", "perso", "import-cert", *args])


def test_csr_mismatch_refuses_before_any_card_contact(monkeypatch, files):
    def no_session(self):
        raise AssertionError("a mismatched certificate reached the card")

    monkeypatch.setattr(AppContext, "open_session", no_session)
    result = _run(
        ["--slot", "9A", "--cert", files["cert"], "--csr", files["csr_other"], "--default-keys"]
    )
    assert result.exit_code != 0
    assert "not the one in" in result.output


def test_csr_match_imports_and_reports_the_check(monkeypatch, files):
    imported: list = []
    _wire(monkeypatch, _Session(), imported=imported)
    result = _run(
        ["--slot", "9A", "--cert", files["cert"], "--csr", files["csr_same"], "--default-keys"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["checked"] == ["csr"]
    assert len(imported) == 1


def test_verify_pin_accepts_a_signature_by_the_slot_key(monkeypatch, files, rsa_keys):
    imported: list = []
    session = _Session(rsa_keys[0])
    _wire(monkeypatch, session, imported=imported)
    result = _run(["--slot", "9A", "--cert", files["cert"], "--verify-pin", "--default-keys"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["checked"] == ["signature"]
    assert session.signed == 1 and len(imported) == 1


def test_verify_pin_refuses_a_signature_by_another_key(monkeypatch, files, rsa_keys):
    imported: list = []
    _wire(monkeypatch, _Session(rsa_keys[1]), imported=imported)
    result = _run(["--slot", "9A", "--cert", files["cert"], "--verify-pin", "--default-keys"])
    assert result.exit_code != 0
    assert "does not verify" in result.output
    assert imported == []


def test_verify_pin_explains_a_slot_that_cannot_sign(monkeypatch, files):
    imported: list = []
    _wire(monkeypatch, _Session(sw=0x6985), imported=imported)
    result = _run(["--slot", "9D", "--cert", files["cert"], "--verify-pin", "--default-keys"])
    assert result.exit_code != 0
    assert "--csr instead" in result.output
    assert imported == []


def test_verify_pin_works_for_an_ec_certificate(monkeypatch, tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = tmp_path / "ec.pem"
    cert.write_bytes(_self_signed(key, "ec").public_bytes(serialization.Encoding.PEM))
    imported: list = []
    session = _Session(key)
    _wire(monkeypatch, session, imported=imported)
    result = _run(["--slot", "9C", "--cert", str(cert), "--verify-pin", "--default-keys"])
    assert result.exit_code == 0, result.output
    assert session.signed == 1 and len(imported) == 1


def test_without_flags_the_import_is_unchecked_and_says_so(monkeypatch, files):
    imported: list = []
    _wire(monkeypatch, _Session(), imported=imported)
    result = CliRunner().invoke(
        root,
        ["piv", "perso", "import-cert", "--slot", "9A", "--cert", files["cert"], "--default-keys"],
    )
    assert result.exit_code == 0, result.output
    assert "not checked" in result.output
    assert len(imported) == 1


def test_mechanism_follows_the_certificate_key():
    assert (
        piv_cmd._mechanism_for_public_key(rsa.generate_private_key(65537, 2048).public_key())
        == (perso_mod.ALGORITHMS["RSA2048"])
    )
    assert (
        piv_cmd._mechanism_for_public_key(ec.generate_private_key(ec.SECP384R1()).public_key())
        == (perso_mod.ALGORITHMS["ECCP384"])
    )
    with pytest.raises(CryptnoxError):
        piv_cmd._mechanism_for_public_key(ec.generate_private_key(ec.SECP521R1()).public_key())
