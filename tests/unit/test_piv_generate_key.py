# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso generate-key`` over the SCP03 double, with the PIV responder generating
the key, so the public key the command reports is the one the card holds."""

from __future__ import annotations

import hashlib
import json

import pytest
from _cardfakes import ResponseAdapter, run, wire_session
from _piv_card import PivResponder, UnwrappingScp03Card
from cryptography.hazmat.primitives import serialization

SELECT_PIV = "00A404000BA00000030800001000010000"
GENERATE = (0x47, 0x00, 0x9C)


@pytest.fixture
def card(monkeypatch, acs_transcript):
    apt = bytes.fromhex(acs_transcript["exchanges"][SELECT_PIV].split("|")[0])
    piv = PivResponder(apt)
    scp = UnwrappingScp03Card(on_secured=piv.secured, on_plain=piv.plain)
    conn = ResponseAdapter(scp)
    wire_session(monkeypatch, conn)
    return piv, scp, conn


def _gen(*extra):
    return ["piv", "perso", "generate-key", "--slot", "9C", "--default-keys", *extra]


def _der(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_generate_writes_the_cards_public_key(card, tmp_path):
    piv, scp, _ = card
    out = tmp_path / "pub.pem"
    result = run(["--json", *_gen("--out", str(out))])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    pub = serialization.load_pem_public_key(out.read_bytes())
    der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert der == _der(piv.key)
    assert payload["public_key_sha256"] == hashlib.sha256(der).hexdigest().upper()
    assert payload["public_key_pem"] is None and payload["generate_path"] == "admin-channel"
    assert [s[:3] for s in scp.secured].count(GENERATE) == 1

    human = run(_gen("--out", str(out)))
    text = " ".join(human.output.split())
    assert "Generated ECCP256 key in slot 9C (on-card)." in text
    assert f"Public key PEM -> {out}" in text


def test_an_unsupported_algorithm_is_refused_before_the_card(card):
    _, _, conn = card
    result = run(_gen("--algorithm", "ED25519"))
    assert result.exit_code == 2
    assert "not supported by this applet" in result.output
    assert conn.log == []


@pytest.mark.parametrize(
    ("probe_sw", "created"), [((0x6A, 0x86), True), ((0x69, 0x82), False)], ids=["absent", "there"]
)
def test_create_key_object_only_when_the_probe_finds_none(card, probe_sw, created):
    piv, scp, _ = card
    piv.probe_sw = probe_sw
    result = run(["--json", "--yes", *_gen("--create-key-object")])
    assert result.exit_code == 0, result.output
    secured = [s[:2] for s in scp.secured]
    assert ((0xDB, 0x3F) in secured) is created
    assert secured[-1] == GENERATE[:2]
    assert ("creating the key object (PUT DATA ADMIN)" in result.output) is created


def test_rsa_generate_refused_with_6f00_names_the_cause(card):
    piv, _, _ = card
    piv.secured_sw[0x47] = (0x6F, 0x00)
    result = run(_gen("--algorithm", "RSA2048"))
    assert result.exit_code != 0
    assert "GENERATE key 9C failed (SW=6F00):" in " ".join(result.output.split())
