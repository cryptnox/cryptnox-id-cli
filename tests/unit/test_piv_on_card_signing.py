# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso generate-csr``, ``self-sign-cert`` and ``smoke-test``, signed by the
responder's slot key, and the ``generate-chuid``, ``generate-ccc`` and
``generate-discovery`` outputs."""

from __future__ import annotations

import datetime
import json

import pytest
from _cardfakes import ResponseAdapter, run, run_both_modes, wire_session
from _piv_card import PivResponder, UnwrappingScp03Card
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.crypto import piv_objects
from cryptnox_id_cli.util import tlv

SELECT_PIV = "00A404000BA00000030800001000010000"


@pytest.fixture
def signer(monkeypatch, acs_transcript, tmp_path):
    """A card whose 9C key signs, its public key on disk, and the PIN in the environment."""

    def _make(curve=ec.SECP256R1(), **kw):
        apt = bytes.fromhex(acs_transcript["exchanges"][SELECT_PIV].split("|")[0])
        piv = PivResponder(apt, key=ec.generate_private_key(curve), **kw)
        conn = ResponseAdapter(UnwrappingScp03Card(on_plain=piv.plain))
        wire_session(monkeypatch, conn)
        monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
        pub = tmp_path / "pub.pem"
        pub.write_bytes(
            piv.key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        return piv, conn, str(pub)

    return _make


def _signing_args(command, pub, *extra):
    return ["piv", "perso", command, "--slot", "9C", "--subject", "CN=Test User", *extra,
            "--public-key", pub]  # fmt: skip


@pytest.mark.parametrize(
    ("curve", "algorithm", "hash_alg"),
    [(ec.SECP256R1(), "ECCP256", hashes.SHA256), (ec.SECP384R1(), "ECCP384", hashes.SHA384)],
    ids=["p256", "p384"],
)
def test_generate_csr_is_signed_by_the_slot_key(signer, tmp_path, curve, algorithm, hash_alg):
    piv, conn, pub = signer(curve)
    out = tmp_path / "req.pem"
    args = _signing_args("generate-csr", pub, "--algorithm", algorithm, "--out", str(out))
    as_json, human = run_both_modes(args)
    assert as_json.exit_code == 0, as_json.output
    assert json.loads(as_json.stdout) == {
        "slot": "9C",
        "subject": "CN=Test User",
        "out": str(out),
        "csr_pem": None,
    }
    csr = x509.load_pem_x509_csr(out.read_bytes())
    assert csr.is_signature_valid
    assert isinstance(csr.signature_hash_algorithm, hash_alg)
    assert csr.subject.rfc4514_string() == "CN=Test User"
    assert csr.public_key() == piv.key.public_key()
    assert any(c.startswith("00200080") for c in conn.log)
    assert f"CSR written to {out}" in " ".join(human.output.split())


def test_generate_csr_without_out_prints_the_pem(signer):
    _, _, pub = signer()
    as_json, human = run_both_modes(_signing_args("generate-csr", pub))
    pem = json.loads(as_json.stdout)["csr_pem"]
    assert x509.load_pem_x509_csr(pem.encode()).is_signature_valid
    assert "-----BEGIN CERTIFICATE REQUEST-----" in human.output


def test_self_signed_certificate_is_signed_by_the_slot_key(signer, tmp_path):
    piv, _, pub = signer()
    out = tmp_path / "cert.pem"
    args = _signing_args("self-sign-cert", pub, "--days", "30", "--out", str(out))
    as_json, human = run_both_modes(args)
    assert as_json.exit_code == 0, as_json.output
    assert json.loads(as_json.stdout)["cert_pem"] is None
    cert = x509.load_pem_x509_certificate(out.read_bytes())
    piv.key.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )
    assert cert.issuer == cert.subject
    assert cert.serial_number & 1
    validity = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert validity == datetime.timedelta(days=30)
    assert "development/testing only" in as_json.stderr
    assert f"Self-signed cert written to {out}" in " ".join(human.output.split())


def test_self_signed_certificate_without_out_prints_the_pem(signer):
    _, _, pub = signer()
    as_json, human = run_both_modes(_signing_args("self-sign-cert", pub))
    pem = json.loads(as_json.stdout)["cert_pem"]
    assert x509.load_pem_x509_certificate(pem.encode()).subject.rfc4514_string() == "CN=Test User"
    assert "-----BEGIN CERTIFICATE-----" in human.output


@pytest.mark.parametrize("command", ["generate-csr", "self-sign-cert"])
def test_an_unsupported_algorithm_is_refused_before_the_card(signer, command):
    _, conn, pub = signer()
    result = run(_signing_args(command, pub, "--algorithm", "ED25519"))
    assert result.exit_code == 2
    assert "not supported by this applet" in result.output
    assert conn.log == []


def test_a_wrong_pin_stops_before_the_signature(signer, monkeypatch):
    _, conn, pub = signer()
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "654321")
    result = run(_signing_args("generate-csr", pub))
    assert result.exit_code != 0
    assert not any(c[2:4] == "87" for c in conn.log)


@pytest.mark.parametrize(
    ("curve", "algorithm", "length"),
    [(ec.SECP256R1(), "ECCP256", 32), (ec.SECP384R1(), "ECCP384", 48)],
    ids=["p256", "p384"],
)
def test_smoke_test_signs_a_digest_of_the_mechanisms_size(signer, curve, algorithm, length):
    _, conn, _ = signer(curve)
    args = ["piv", "perso", "smoke-test", "--slot", "9C", "--algorithm", algorithm]
    as_json, human = run_both_modes(args)
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["pin_verified"] and payload["signed"] and payload["signature_len"] > 0
    sign = bytes.fromhex(next(c for c in conn.log if c[2:4] == "87"))
    assert len(tlv.find(tlv.parse(sign[5 : 5 + sign[4]]), 0x81).value) == length
    assert "Smoke test OK: PIN verified and slot 9C produced a" in " ".join(human.output.split())


@pytest.mark.parametrize(
    ("command", "name", "build"),
    [
        ("generate-chuid", "chuid", None),
        ("generate-ccc", "ccc", None),
        ("generate-discovery", "discovery", piv_objects.generate_discovery),
    ],
)
def test_generated_objects_go_to_stdout_or_a_file(tmp_path, command, name, build):
    as_json, human = run_both_modes(["piv", "perso", command])
    payload = json.loads(as_json.stdout)
    assert payload["object"] == name and payload["out"] is None
    data = bytes.fromhex(payload["hex"])
    assert payload["length"] == len(data)
    if build is not None:  # the other two carry fresh random identifiers
        assert data == build()
    assert f"{name} ({len(data)} bytes):" in human.output

    out = tmp_path / f"{name}.bin"
    as_json, human = run_both_modes(["piv", "perso", command, "--out", str(out)])
    payload = json.loads(as_json.stdout)
    assert payload["hex"] is None and payload["length"] == len(out.read_bytes())
    assert f"{name} ({payload['length']} bytes) -> {out}" in " ".join(human.output.split())
