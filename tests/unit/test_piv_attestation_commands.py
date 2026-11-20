# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv export-attestation`` and ``verify-attestation`` through the open_session seam."""

from __future__ import annotations

import datetime
import json

import pytest
from _cardfakes import run, run_both_modes, wire_session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.applets.piv.objects import wrap_certificate
from cryptnox_id_cli.util import tlv

SELECT_PIV = "00A404000BA00000030800001000010000"
GET_ATTESTATION = "00CB3FFF055C035FC12000"
NOW = datetime.datetime.now(datetime.timezone.utc)


def _cert(cn, key, issuer_cn, issuer_key, *, ca):
    name = lambda v: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, v)])  # noqa: E731
    return (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(name(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def pki(tmp_path, monkeypatch):
    """A probe root + intermediate added to the trust store, and a leaf they issue."""
    root_key, inter_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Probe Root", root_key, "Probe Root", root_key, ca=True)
    inter = _cert("Probe Intermediate", inter_key, "Probe Root", root_key, ca=True)
    leaf = _cert("PIV Attestation 9C", leaf_key, "Probe Intermediate", inter_key, ca=False)
    anchors = tmp_path / "anchors"
    anchors.mkdir()
    (anchors / "probe.pem").write_bytes(
        b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (root, inter))
    )
    monkeypatch.setenv("CRYPTNOX_TRUST_DIR", str(anchors))
    return {"leaf": leaf, "inter": inter, "root": root, "leaf_key": leaf_key}


@pytest.fixture
def card(monkeypatch, mock_connection, acs_transcript):
    def _wire(leaf_der=None):
        exchanges = {SELECT_PIV: acs_transcript["exchanges"][SELECT_PIV]}
        if leaf_der is not None:
            obj = tlv.build(0x53, wrap_certificate(leaf_der))
            exchanges[GET_ATTESTATION] = obj.hex() + "|9000"
        conn = mock_connection(acs_transcript["atr"], exchanges, [])
        wire_session(monkeypatch, conn, reader_name="R")

    return _wire


def _csr(tmp_path, key, *, der=False):
    req = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr")]))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / ("req.der" if der else "req.pem")
    path.write_bytes(
        req.public_bytes(serialization.Encoding.DER if der else serialization.Encoding.PEM)
    )
    return str(path)


def test_verify_attestation_chain_to_the_pinned_root(pki, card):
    card(_der(pki["leaf"]))
    as_json, human = run_both_modes(["piv", "verify-attestation"])
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["verified"] is True and payload["csr_match"] is None
    assert payload["chain"] == ["CN=PIV Attestation 9C", "CN=Probe Intermediate", "CN=Probe Root"]
    assert "verified" in human.output and "NOT" not in human.output
    assert "CN=PIV Attestation 9C -> CN=Probe Intermediate -> CN=Probe Root" in human.output


@pytest.mark.parametrize("der", [False, True], ids=["pem-csr", "der-csr"])
@pytest.mark.parametrize("same_key", [True, False], ids=["match", "mismatch"])
def test_verify_attestation_checks_the_csr_key(pki, card, tmp_path, der, same_key):
    card(_der(pki["leaf"]))
    key = pki["leaf_key"] if same_key else ec.generate_private_key(ec.SECP256R1())
    csr = _csr(tmp_path, key, der=der)
    as_json, human = run_both_modes(["piv", "verify-attestation", "--csr", csr])
    payload = json.loads(as_json.stdout)
    assert payload["csr_match"] is same_key
    assert payload["verified"] is same_key
    assert f"CSR key match: {'yes' if same_key else 'no'}" in human.output
    if not same_key:
        assert "NOT verified" in human.output
        assert "does not match the CSR" in human.output


def test_verify_attestation_unanchored_leaf_lists_the_reasons(card):
    stranger = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert("PIV Attestation 9C", stranger, "Nobody", stranger, ca=False)
    card(_der(leaf))
    as_json, human = run_both_modes(["piv", "verify-attestation"])
    payload = json.loads(as_json.stdout)
    assert payload["verified"] is False and payload["reasons"]
    assert "NOT verified" in human.output
    assert payload["reasons"][0] in human.output


@pytest.mark.parametrize("command", ["verify-attestation", "export-attestation"])
def test_absent_attestation_is_reported_not_raised(card, command):
    card()
    as_json, human = run_both_modes(["piv", command])
    assert as_json.exit_code == 0 and human.exit_code == 0
    assert json.loads(as_json.stdout) == {"present": False, "slot": "9C"}
    assert "No attestation certificate in slot 9C" in human.output


@pytest.mark.parametrize("command", ["verify-attestation", "export-attestation"])
def test_only_slot_9c_carries_an_attestation(command):
    result = run(["piv", command, "--slot", "9A"])
    assert result.exit_code == 2
    assert "carries no attestation certificate" in result.output


def test_export_attestation_pem_bundles_the_intermediate_not_the_root(pki, card):
    card(_der(pki["leaf"]))
    as_json, human = run_both_modes(["piv", "export-attestation"])
    payload = json.loads(as_json.stdout)
    assert payload == {
        "present": True,
        "slot": "9C",
        "format": "PEM",
        "out": None,
        "intermediates_bundled": 1,
    }
    printed = x509.load_pem_x509_certificates(human.output.encode())
    assert [_der(c) for c in printed] == [_der(pki["leaf"]), _der(pki["inter"])]


def test_export_attestation_pem_to_file(pki, card, tmp_path):
    card(_der(pki["leaf"]))
    out = tmp_path / "chain.pem"
    as_json, human = run_both_modes(["piv", "export-attestation", "--out", str(out)])
    assert json.loads(as_json.stdout)["out"] == str(out)
    assert "Wrote PEM attestation to" in human.output and "(+1 intermediate)" in human.output
    assert len(x509.load_pem_x509_certificates(out.read_bytes())) == 2


def test_export_attestation_der_leaf_only(pki, card, tmp_path):
    card(_der(pki["leaf"]))
    out = tmp_path / "leaf.der"
    as_json, human = run_both_modes(["piv", "export-attestation", "--der", "--out", str(out)])
    assert json.loads(as_json.stdout)["intermediates_bundled"] == 0
    assert out.read_bytes() == _der(pki["leaf"])
    assert "Wrote DER attestation to" in human.output and "intermediate" not in human.output
    to_stdout = run(["piv", "export-attestation", "--der"])
    assert (
        _der(pki["leaf"]).hex().upper()
        in to_stdout.output.replace("\n", "").replace(" ", "").upper()
    )


def test_verify_attestation_prints_bracketed_names_as_written(card, monkeypatch, tmp_path):
    root_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    root = _cert("Root [b]R[/b]", root_key, "Root [b]R[/b]", root_key, ca=True)
    leaf = _cert("Leaf a[/x]b", leaf_key, "Root [b]R[/b]", root_key, ca=False)
    anchors = tmp_path / "anchors"
    anchors.mkdir()
    (anchors / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("CRYPTNOX_TRUST_DIR", str(anchors))
    card(_der(leaf))
    result = run(["piv", "verify-attestation"])
    assert result.exit_code == 0, result.output
    assert "subject: CN=Leaf a[/x]b" in result.output
    assert "chain:   CN=Leaf a[/x]b -> CN=Root [b]R[/b]" in result.output


def test_verify_attestation_prints_a_reason_naming_a_bracketed_leaf_as_written(card):
    stranger = ec.generate_private_key(ec.SECP256R1())
    card(_der(_cert("Leaf a[/x]b", stranger, "Nobody", stranger, ca=False)))
    result = run(["piv", "verify-attestation"])
    assert result.exit_code == 0, result.output
    assert "- not anchored: no pinned root issues 'CN=Leaf a[/x]b'" in result.output


def test_export_attestation_names_a_path_with_brackets_as_written(pki, card, tmp_path):
    card(_der(pki["leaf"]))
    folder = tmp_path / "old [draft]"
    folder.mkdir()
    out = folder / "chain.pem"
    result = run(["piv", "export-attestation", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert f"Wrote PEM attestation to {out}" in " ".join(result.output.split())
