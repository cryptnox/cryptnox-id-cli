# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Certificate key descriptions and the hex rendering helper."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.crypto import x509util
from cryptnox_id_cli.util.hexutil import to_hex


def _cert_der(key, *, algorithm) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "k")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, algorithm)
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize(
    ("key", "algorithm", "description"),
    [
        (rsa.generate_private_key(65537, 2048), hashes.SHA256(), "RSA-2048"),
        (ec.generate_private_key(ec.SECP384R1()), hashes.SHA384(), "EC-secp384r1"),
        (ed25519.Ed25519PrivateKey.generate(), None, "Ed25519PublicKey"),
    ],
    ids=["rsa", "ec", "other"],
)
def test_certificate_key_description(key, algorithm, description):
    assert (
        x509util.describe_certificate(_cert_der(key, algorithm=algorithm))["public_key"]
        == description
    )


@pytest.mark.parametrize(("sep", "text"), [("", "00A4FF"), (" ", "00 A4 FF"), (":", "00:A4:FF")])
def test_to_hex_with_and_without_a_separator(sep, text):
    assert to_hex(b"\x00\xa4\xff", sep=sep) == text
