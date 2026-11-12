# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv certs list`` against a card holding one readable and one unreadable certificate."""

from __future__ import annotations

import datetime
import json

import pytest
from _cardfakes import run_both_modes, wire_session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.applets.piv.objects import wrap_certificate
from cryptnox_id_cli.util import tlv

SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
_KEY = ec.generate_private_key(ec.SECP256R1())
_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Slot 9C Signer")])
CERT = (
    x509.CertificateBuilder()
    .subject_name(_NAME)
    .issuer_name(_NAME)
    .public_key(_KEY.public_key())
    .serial_number(7)
    .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
    .not_valid_after(datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc))
    .sign(_KEY, hashes.SHA256())
)
DER = CERT.public_bytes(serialization.Encoding.DER)


def _get_data(oid_hex: str) -> str:
    oid = bytes.fromhex(oid_hex)
    return f"00CB3FFF{len(oid) + 2:02X}5C{len(oid):02X}{oid_hex}00"


def _object(der: bytes) -> str:
    return tlv.build(0x53, wrap_certificate(der)).hex() + "|9000"


@pytest.fixture
def card(monkeypatch, mock_connection):
    exchanges = {
        SELECT_PIV: APT + "|9000",
        _get_data("5FC105"): _object(b"\x30\x03junk"),  # 9A
        _get_data("5FC10A"): _object(DER),  # 9C
    }
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []))


def test_json_lists_each_slot_with_its_certificate_or_parse_error(card):
    as_json, _ = run_both_modes(["piv", "certs", "list"])
    assert as_json.exit_code == 0, as_json.output
    by_slot = {c["slot"]: c for c in json.loads(as_json.stdout)["certificates"]}
    assert by_slot["9A"]["present"] is True
    assert by_slot["9A"]["error"].startswith("parse failed: ")
    assert "certificate" not in by_slot["9A"]
    assert by_slot["9C"]["certificate"]["subject"] == "CN=Slot 9C Signer"
    assert by_slot["9D"]["present"] is False
    assert by_slot["9E"]["present"] is False


def test_human_shows_the_readable_certificate_and_the_empty_slots(card):
    _, human = run_both_modes(["piv", "certs", "list"])
    assert human.exit_code == 0, human.output
    rows = {line.split()[1]: line for line in human.output.splitlines() if "-cert" in line}
    assert "CN=Slot 9C Signer" in rows["9C"]
    assert "2031-01-01" in rows["9C"]
    for slot in ("9D", "9E"):
        assert [cell.strip() for cell in rows[slot].split("│")[3:6]] == ["no", "-", "-"]


def test_human_flags_the_unreadable_certificate_and_prints_why(card):
    _, human = run_both_modes(["piv", "certs", "list"])
    assert human.exit_code == 0, human.output
    row = next(line for line in human.output.splitlines() if "9A" in line)
    assert "unreadable" in row
    assert "9A: parse failed: " in human.output
