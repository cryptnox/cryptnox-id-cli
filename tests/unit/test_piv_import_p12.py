# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso import-p12``: the key, then the certificate, then an on-card signature."""

from __future__ import annotations

import datetime
import json

import pytest
from _cardfakes import ResponseAdapter, run, run_both_modes, wire_session
from _piv_card import PivResponder, UnwrappingScp03Card
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

SELECT_PIV = "00A404000BA00000030800001000010000"
NOW = datetime.datetime.now(datetime.timezone.utc)
KEY = ec.generate_private_key(ec.SECP256R1())


def _cert(cn, key, *, ca=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=9))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


LEAF = _cert("Probe Holder", KEY)
CA = _cert("Probe CA", ec.generate_private_key(ec.SECP256R1()), ca=True)


def _p12(tmp_path, *, cert=LEAF, cas=(CA,), password=None):
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    path = tmp_path / "cred.p12"
    path.write_bytes(pkcs12.serialize_key_and_certificates(b"c", KEY, cert, list(cas), enc))
    path.chmod(0o600)
    return str(path)


@pytest.fixture
def card(monkeypatch, acs_transcript):
    apt = bytes.fromhex(acs_transcript["exchanges"][SELECT_PIV].split("|")[0])
    piv = PivResponder(apt, pin=b"123456", key=KEY)
    scp = UnwrappingScp03Card(on_secured=piv.secured, on_plain=piv.plain)
    wire_session(monkeypatch, ResponseAdapter(scp), reader_name="Fake Reader 00 00")
    return piv, scp


def _args(path, *extra):
    return ["piv", "perso", "import-p12", "--slot", "9C", "--p12", path, "--default-keys", *extra]


def test_key_then_certificate_then_signature(card, tmp_path):
    _, scp = card
    as_json, human = run_both_modes(_args(_p12(tmp_path), "--pin", "123456"))
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["certificate"]["subject"] == "CN=Probe Holder"
    assert payload["extra_certs_ignored"] == 1
    assert payload["smoke_test"] == {"signed": True, "verified": True}
    put = b"".join(body for ins, _, _, body in scp.secured[:5] if ins == 0xDB)
    assert put.startswith(b"\x5c\x03\x5f\xc1\x0a")
    assert LEAF.public_bytes(serialization.Encoding.DER) in put
    text = " ".join(human.output.split())
    assert "Imported ECC-P256 credential into slot 9C" in text
    assert "1 chain certificate(s) ignored." in text and "verified against the key" in text


@pytest.mark.parametrize(
    ("sign_sw", "expect"),
    [(None, "Smoke test skipped."), ((0x69, 0x85), "this slot's role cannot sign")],
    ids=["skipped", "role-cannot-sign"],
)
def test_smoke_variants_without_chain_certs(card, tmp_path, sign_sw, expect):
    card[0].sign_sw = sign_sw
    extra = ["--no-smoke-test"] if sign_sw is None else ["--pin", "123456"]
    as_json, human = run_both_modes(_args(_p12(tmp_path, cas=()), *extra))
    assert json.loads(as_json.stdout)["extra_certs_ignored"] == 0
    assert expect in " ".join(human.output.split()) and "ignored" not in human.output


def test_dry_run_lists_key_elements_and_the_certificate(tmp_path):
    as_json, human = run_both_modes(_args(_p12(tmp_path), "--dry-run"))
    payload = json.loads(as_json.stdout)
    assert payload["dry_run"] is True and len(payload["elements"]) == 3
    assert payload["extra_certs_ignored"] == 1
    text = " ".join(human.output.split())
    assert "certificate (CN=Probe Holder): chained PUT DATA" in text
    assert "1 chain certificate(s) ignored" in text


def test_mismatched_pair_is_refused(tmp_path, monkeypatch):
    """cryptography will not serialize a mismatched pair, so the parser stands in for one."""
    from cryptnox_id_cli.applets.piv import keyimport

    other = _cert("Other", ec.generate_private_key(ec.SECP256R1()))
    monkeypatch.setattr(
        keyimport,
        "load_pkcs12",
        lambda raw, pw: (KEY, other.public_bytes(serialization.Encoding.DER), []),
    )
    result = run(_args(_p12(tmp_path), "--dry-run"))
    assert result.exit_code != 0 and "does not match its private key" in result.output


@pytest.mark.parametrize(
    ("flag", "env", "ok", "text"),
    [
        ("wrong", None, False, "could not open the PKCS#12 file"),
        (None, "pw", True, ""),
        (None, "wrong", False, "wrong password or corrupt data"),
    ],
    ids=["wrong-flag", "env", "wrong-env"],
)
def test_password_sources(tmp_path, monkeypatch, flag, env, ok, text):
    if env:
        monkeypatch.setenv("CRYPTNOX_PIV_P12_PASSWORD", env)
    extra = ["--password", flag] if flag else []
    result = run(_args(_p12(tmp_path, password=b"pw"), "--dry-run", *extra))
    assert (result.exit_code == 0) is ok, result.output
    assert text in result.output


def test_slot_without_certificate_container(tmp_path):
    result = run(["piv", "perso", "import-p12", "--slot", "82", "--p12", _p12(tmp_path)])
    assert result.exit_code == 2 and "has no certificate container" in result.output


def test_certificate_refused_after_the_key_landed(card, tmp_path):
    card[0].secured_sw[0xDB] = (0x6A, 0x84)
    result = run(_args(_p12(tmp_path), "--no-smoke-test"))
    assert result.exit_code != 0 and "IMPORT cert 9C" in result.output
    assert [s[0] for s in card[1].secured][:3] == [0x24, 0x24, 0x24]


BRACKETED = _cert("Holder a[/x]b", KEY)


def test_dry_run_names_a_bracketed_subject_as_written(tmp_path):
    result = run(_args(_p12(tmp_path, cert=BRACKETED), "--dry-run"))
    assert result.exit_code == 0, result.output
    assert "certificate (CN=Holder a[/x]b): chained PUT DATA" in " ".join(result.output.split())


def test_import_names_a_bracketed_subject_as_written(card, tmp_path):
    result = run(_args(_p12(tmp_path, cert=BRACKETED), "--no-smoke-test"))
    assert result.exit_code == 0, result.output
    assert "Certificate: CN=Holder a[/x]b (expires" in " ".join(result.output.split())
