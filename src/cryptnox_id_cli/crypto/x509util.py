"""Minimal X.509 inspection for PIV certificate objects (read-only)."""

from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def to_pem(der: bytes) -> bytes:
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)


def _key_description(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}"
    return type(pub).__name__


def describe_certificate(der: bytes) -> dict[str, object]:
    """Return a JSON-able summary of a DER certificate."""
    cert = x509.load_der_x509_certificate(der)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key": _key_description(cert),
        "sha256_fingerprint": hashlib.sha256(der).hexdigest().upper(),
    }
