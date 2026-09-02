"""Build CSRs and self-signed certs around an external (on-card) signer.

The PIV private key never leaves the card, so we assemble the ASN.1 with
``asn1crypto`` and sign the TBS bytes via a callback that runs GENERAL
AUTHENTICATE on the card.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from asn1crypto import algos, csr, keys, pem, x509
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# A signer takes the digest to sign and returns the signature bytes.
Signer = Callable[[bytes], bytes]

# mechanism id -> (hash func, signature-algorithm name, EC coord length or None for RSA)
_ALG = {
    0x11: (hashlib.sha256, "sha256_ecdsa", 32),
    0x14: (hashlib.sha384, "sha384_ecdsa", 48),
    0x07: (hashlib.sha256, "sha256_rsa", None),
    0x05: (hashlib.sha256, "sha256_rsa", None),
    0x16: (hashlib.sha256, "sha256_rsa", None),
}

_RDN = {
    "CN": "common_name",
    "O": "organization_name",
    "OU": "organizational_unit_name",
    "C": "country_name",
    "L": "locality_name",
    "ST": "state_or_province_name",
    "E": "email_address",
}


def parse_subject(subject: str) -> x509.Name:
    """Parse a one-line DN like 'CN=John Doe,O=Cryptnox,C=CH' into a Name."""
    parts: dict[str, str] = {}
    for rdn in subject.split(","):
        key, sep, value = rdn.partition("=")
        key = key.strip().upper()
        if not sep or key not in _RDN:
            raise ValueError(f"unsupported subject component {rdn.strip()!r}")
        parts[_RDN[key]] = value.strip()
    if not parts:
        raise ValueError("empty subject")
    return x509.Name.build(parts)


def ensure_der_ecdsa(signature: bytes, coord_len: int) -> bytes:
    """Return a DER ECDSA signature; convert from raw r||s if needed."""
    if len(signature) == 2 * coord_len:  # raw r||s
        r = int.from_bytes(signature[:coord_len], "big")
        s = int.from_bytes(signature[coord_len:], "big")
        return encode_dss_signature(r, s)
    return signature  # already DER


def _finalize_sig(mechanism: int, raw: bytes, coord_len: int | None) -> bytes:
    if coord_len is not None:  # EC
        return ensure_der_ecdsa(raw, coord_len)
    return raw  # RSA: card returns the PKCS#1 signature as-is


def build_csr(subject: str, public_key_der: bytes, mechanism: int, signer: Signer) -> bytes:
    """Build a PEM PKCS#10 CSR, signing the request info on-card via ``signer``."""
    hash_fn, sig_alg, coord = _ALG[mechanism]
    info = csr.CertificationRequestInfo(
        {
            "version": "v1",
            "subject": parse_subject(subject),
            "subject_pk_info": keys.PublicKeyInfo.load(public_key_der),
            "attributes": [],
        }
    )
    signature = _finalize_sig(mechanism, signer(hash_fn(info.dump()).digest()), coord)
    request = csr.CertificationRequest(
        {
            "certification_request_info": info,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": sig_alg}),
            "signature": signature,
        }
    )
    return pem.armor("CERTIFICATE REQUEST", request.dump())


def build_self_signed(
    subject: str,
    public_key_der: bytes,
    mechanism: int,
    signer: Signer,
    *,
    serial: int,
    not_before: str,
    not_after: str,
) -> bytes:
    """Build a PEM self-signed X.509 cert (dev/test), signed on-card.

    ``not_before``/``not_after`` are ISO datetimes (passed in to avoid using the
    clock here); ``serial`` is a positive integer.
    """
    hash_fn, sig_alg, coord = _ALG[mechanism]
    name = parse_subject(subject)
    alg = algos.SignedDigestAlgorithm({"algorithm": sig_alg})
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": serial,
            "signature": alg,
            "issuer": name,
            "validity": {
                "not_before": _time(not_before),
                "not_after": _time(not_after),
            },
            "subject": name,
            "subject_public_key_info": keys.PublicKeyInfo.load(public_key_der),
        }
    )
    signature = _finalize_sig(mechanism, signer(hash_fn(tbs.dump()).digest()), coord)
    cert = x509.Certificate(
        {"tbs_certificate": tbs, "signature_algorithm": alg, "signature_value": signature}
    )
    return pem.armor("CERTIFICATE", cert.dump())


def _time(iso: str) -> x509.Time:
    """Encode an ISO datetime as the RFC 5280-correct ASN.1 time: UTCTime for years
    < 2050, GeneralizedTime for 2050+ (UTCTime's 2-digit year wraps otherwise)."""
    from datetime import datetime

    dt = datetime.fromisoformat(iso)
    field = "utc_time" if dt.year < 2050 else "general_time"
    return x509.Time({field: dt})
