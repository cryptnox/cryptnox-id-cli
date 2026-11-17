# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv certs list`` and ``inspect`` print certificate names exactly as the card holds them.

A subject or issuer is free text from the card, and square brackets in it would be read as
console markup: ``[/x]`` raises an error, ``[b]...[/b]`` disappears into bold.
"""

from __future__ import annotations

import datetime
import json

import pytest
from _cardfakes import run, run_both_modes, wire_session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_piv_certs_list import APT, SELECT_PIV, _get_data, _object

BROKEN_TAG = "CN=a[/x]b"
BOLD_ISSUER = "CN=[b]I[/b]"
BOLD_SUBJECT = "CN=[b]S[/b]"


def _cert(subject: str, issuer: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())

    def name(rfc4514: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, rfc4514[3:])])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(key.public_key())
        .serial_number(9)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def card(monkeypatch, mock_connection):
    exchanges = {
        SELECT_PIV: APT + "|9000",
        _get_data("5FC105"): _object(_cert(BROKEN_TAG, BOLD_ISSUER)),  # 9A
        _get_data("5FC10A"): _object(_cert(BOLD_SUBJECT, BOLD_SUBJECT)),  # 9C
    }
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []))


def test_json_carries_the_names_unchanged(card):
    as_json, _ = run_both_modes(["piv", "certs", "list"])
    by_slot = {c["slot"]: c["certificate"] for c in json.loads(as_json.stdout)["certificates"][:2]}
    assert by_slot["9A"]["subject"] == BROKEN_TAG
    assert by_slot["9A"]["issuer"] == BOLD_ISSUER
    assert by_slot["9C"]["subject"] == BOLD_SUBJECT


@pytest.mark.xfail(strict=True, reason="the subject is printed as console markup")
def test_list_prints_each_subject_as_written(card):
    result = run(["piv", "certs", "list"])
    assert result.exit_code == 0, result.output
    rows = {line.split()[1]: line for line in result.output.splitlines() if "-cert" in line}
    assert BROKEN_TAG in rows["9A"]
    assert BOLD_SUBJECT in rows["9C"]


@pytest.mark.xfail(strict=True, reason="the subject and issuer are printed as console markup")
@pytest.mark.parametrize(
    ("slot", "subject", "issuer"),
    [("9A", BROKEN_TAG, BOLD_ISSUER), ("9C", BOLD_SUBJECT, BOLD_SUBJECT)],
    ids=["closing-tag", "bold"],
)
def test_inspect_prints_subject_and_issuer_as_written(card, slot, subject, issuer):
    result = run(["piv", "certs", "inspect", "--slot", slot])
    assert result.exit_code == 0, result.output
    assert f"subject: {subject}" in result.output
    assert f"issuer: {issuer}" in result.output
