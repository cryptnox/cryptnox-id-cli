"""CSR / self-signed cert assembly around an external signer (verified with cryptography)."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from cryptnox_id_cli.crypto import csr


def _spki(priv) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _software_signer(priv):
    # Emulates the card: DER ECDSA over the already-computed digest.
    def sign(digest: bytes) -> bytes:
        return priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    return sign


def test_build_csr_ec_signature_valid():
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = csr.build_csr("CN=Test User,O=Cryptnox,C=CH", _spki(priv), 0x11, _software_signer(priv))
    req = x509.load_pem_x509_csr(pem)
    assert req.is_signature_valid
    assert "CN=Test User" in req.subject.rfc4514_string()


def test_self_signed_ec_signature_valid():
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = csr.build_self_signed(
        "CN=Test User",
        _spki(priv),
        0x11,
        _software_signer(priv),
        serial=0x1234,
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
    )
    cert = x509.load_pem_x509_certificate(pem)
    # Raises on invalid signature.
    cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))


def test_self_signed_far_future_year_not_wrapped():
    # not_after >= 2050 must use GeneralizedTime; UTCTime would wrap 2060 -> 1960.
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = csr.build_self_signed(
        "CN=Future",
        _spki(priv),
        0x11,
        _software_signer(priv),
        serial=0x1234,
        not_before="2049-06-01T00:00:00+00:00",
        not_after="2060-06-01T00:00:00+00:00",
    )
    cert = x509.load_pem_x509_certificate(pem)
    assert cert.not_valid_after_utc.year == 2060


def test_parse_subject_rejects_garbage():
    with pytest.raises(ValueError):
        csr.parse_subject("not-a-dn")


def test_ensure_der_ecdsa_from_raw():
    raw = bytes(range(1, 33)) + bytes(range(33, 65))  # 64-byte raw r||s
    der = csr.ensure_der_ecdsa(raw, 32)
    r, s = decode_dss_signature(der)
    assert r == int.from_bytes(raw[:32], "big")
    assert s == int.from_bytes(raw[32:], "big")
    # An already-DER signature passes through unchanged.
    assert csr.ensure_der_ecdsa(der, 32) == der
