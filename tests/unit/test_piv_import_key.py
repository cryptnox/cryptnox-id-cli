# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso import-key``: the plan, the key file, and the import over the secure channel."""

from __future__ import annotations

import json
import os

import pytest
from _cardfakes import ResponseAdapter, run, run_both_modes, wire_session
from _piv_card import PivResponder, UnwrappingScp03Card
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from test_scp03 import GP_KEY, FakeScp03Card

from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv.objects import get_data_extended_apdu
from cryptnox_id_cli.transport.scp03 import Scp03Keys

SELECT_PIV = "00A404000BA00000030800001000010000"
PROBE_9C = keyimport.probe_apdu(0x9C, 0x11).to_bytes().hex().upper()
STATUS = get_data_extended_apdu(0x4753).to_bytes().hex().upper()
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def _key_file(tmp_path, key, *, password=None, private=True):
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    path = tmp_path / "key.pem"
    # CodeQL flags a chmod to a readable mode; a 022 umask gives the file 0644 instead.
    old_umask = os.umask(0o022)
    try:
        path.write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
        )
    finally:
        os.umask(old_umask)
    if private:
        os.chmod(path, 0o600)
    return str(path)


@pytest.fixture
def apt(acs_transcript):
    return bytes.fromhex(acs_transcript["exchanges"][SELECT_PIV].split("|")[0])


@pytest.fixture
def scp03_card(monkeypatch, apt):
    """The SCP03 double alone: it answers every secured command 6D00."""

    def _wire(probe_sw):
        conn = ResponseAdapter(
            FakeScp03Card(Scp03Keys.same(GP_KEY), bytes.fromhex("1122334455667788")),
            answers={
                SELECT_PIV: (apt, 0x90, 0x00),
                PROBE_9C: ([], *probe_sw),
                STATUS: ([], 0x69, 0x86),
            },
        )
        wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
        return conn

    return _wire


@pytest.fixture
def card(monkeypatch, apt):
    """The SCP03 double with a PIV applet behind it that takes the key and signs with it."""
    piv = PivResponder(apt, pin=b"123456", key=EC_KEY)
    scp = UnwrappingScp03Card(on_secured=piv.secured, on_plain=piv.plain)
    conn = ResponseAdapter(scp)
    wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
    return piv, scp, conn


def _import(tmp_path, *extra, key=EC_KEY, slot="9C"):
    path = _key_file(tmp_path, key)
    return ["piv", "perso", "import-key", "--slot", slot, "--key", path, "--default-keys", *extra]


@pytest.mark.parametrize(
    ("key", "slot", "algorithm", "elements", "chained"),
    [
        (ec.generate_private_key(ec.SECP256R1()), "9C", "ECC-P256", 3, 0),
        (rsa.generate_private_key(65537, 2048), "9A", "RSA-2048", 8, 1),
    ],
    ids=["ec", "rsa"],
)
def test_dry_run_plans_one_session_per_element(tmp_path, key, slot, algorithm, elements, chained):
    path = _key_file(tmp_path, key)
    args = ["piv", "perso", "import-key", "--slot", slot, "--key", path, "--dry-run"]
    as_json, human = run_both_modes(args)
    payload = json.loads(as_json.stdout)
    assert payload["algorithm"] == algorithm and payload["scp03_sessions"] == elements
    assert sum(s["chained"] for s in payload["elements"]) == chained
    assert payload["rsa_form"] == ("crt" if algorithm.startswith("RSA") else None)
    assert f"DRY RUN - import {algorithm} into slot {slot}" in human.output
    assert "Nothing was sent to the card." in human.output


def test_encrypted_key_takes_the_password_from_the_environment(tmp_path, monkeypatch):
    path = _key_file(tmp_path, ec.generate_private_key(ec.SECP256R1()), password=b"pw")
    args = ["piv", "perso", "import-key", "--slot", "9C", "--key", path, "--dry-run"]
    monkeypatch.setenv("CRYPTNOX_PIV_KEY_PASSWORD", "pw")
    result = run(["--json", *args])
    assert result.exit_code == 0, result.output
    monkeypatch.setenv("CRYPTNOX_PIV_KEY_PASSWORD", "wrong")
    result = run(args)
    assert result.exit_code != 0 and "could not decrypt the private key" in result.output


def test_unreadable_key_file_is_refused(tmp_path):
    path = tmp_path / "key.pem"
    path.write_bytes(b"not a key")
    result = run(["piv", "perso", "import-key", "--slot", "9C", "--key", str(path), "--dry-run"])
    assert result.exit_code != 0 and "could not load the private key" in result.output


def test_world_readable_key_file_warns(tmp_path):
    path = _key_file(tmp_path, ec.generate_private_key(ec.SECP256R1()), private=False)
    result = run(["piv", "perso", "import-key", "--slot", "9C", "--key", path, "--dry-run"])
    assert "group/world-readable; consider chmod 600" in result.output


def test_missing_key_object_without_create_flag_is_refused(tmp_path, scp03_card):
    conn = scp03_card((0x6A, 0x86))
    key = ec.generate_private_key(ec.SECP256R1())
    result = run(_import(tmp_path, "--no-smoke-test", key=key))
    assert result.exit_code != 0
    assert "slot 9C has no ECC-P256 key object" in result.output
    assert not any(c.startswith("8050") for c in conn.log)


def test_a_smoke_test_pin_that_does_not_fit_is_refused_before_the_import(tmp_path, scp03_card):
    conn = scp03_card((0x6A, 0x86))
    result = run(_import(tmp_path, "--pin", "12", key=ec.generate_private_key(ec.SECP256R1())))
    assert result.exit_code == 2
    assert "Nothing was sent to the card." in result.output
    assert conn.log == []


def test_refused_element_stops_the_import(tmp_path, scp03_card):
    conn = scp03_card((0x69, 0x82))
    key = ec.generate_private_key(ec.SECP256R1())
    result = run(_import(tmp_path, "--no-smoke-test", key=key))
    assert result.exit_code != 0
    assert "key is left uninitialised" in result.output
    assert "IMPORT 9C [CLEAR (9F)]" in result.output
    assert [c[:4] for c in conn.log if c[:2] in ("80", "84", "04")] == ["8050", "8482", "0424"]


def test_create_key_object_refused_on_the_secured_channel(tmp_path, scp03_card):
    conn = scp03_card((0x6A, 0x86))
    key = ec.generate_private_key(ec.SECP256R1())
    result = run(["--yes", *_import(tmp_path, "--create-key-object", "--no-smoke-test", key=key)])
    assert result.exit_code != 0
    assert "creating the key object (PUT DATA ADMIN)" in result.output
    assert "CREATE KEY 9C" in result.output
    assert STATUS in conn.log


def test_ec_import_one_session_per_element_then_signs(card, tmp_path):
    _, scp, conn = card
    pub = tmp_path / "pub.pem"
    as_json, human = run_both_modes(_import(tmp_path, "--pin", "123456", "--public-out", str(pub)))
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert [e["ok"] for e in payload["elements"]] == [True] * 3
    assert payload["smoke_test"] == {"signed": True, "verified": True}
    point = EC_KEY.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    scalar = EC_KEY.private_numbers().private_value.to_bytes(32, "big")
    assert scp.secured[:3] == [
        (0x24, 0x11, 0x9C, b"\x9f\x00"),
        (0x24, 0x11, 0x9C, b"\x86\x41" + point),
        (0x24, 0x11, 0x9C, b"\x87\x20" + scalar),
    ]
    assert sum(c.startswith("8050") for c in conn.log) == 6  # fresh channel per element, x2 runs
    assert pub.read_bytes() == EC_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert "Imported ECC-P256 key into slot 9C (3 elements)" in human.output
    assert f"Public key PEM -> {pub}" in human.output
    assert "signed on-card, verified against the key" in human.output


def test_smoke_test_skipped(card, tmp_path):
    as_json, human = run_both_modes(_import(tmp_path, "--no-smoke-test"))
    assert json.loads(as_json.stdout)["smoke_test"] is None
    assert "Smoke test skipped." in human.output
    assert not any(c.startswith("0087") and len(c) > 30 for c in card[2].log)


def test_slot_role_that_cannot_sign_is_a_note(card, tmp_path):
    card[0].sign_sw = (0x69, 0x85)
    as_json, human = run_both_modes(_import(tmp_path, "--pin", "123456"))
    note = "import OK; this slot's role cannot sign on this applet"
    assert json.loads(as_json.stdout)["smoke_test"] == {"signed": False, "note": note}
    assert f"Smoke test: {note}" in " ".join(human.output.split())


def test_signature_from_another_key_is_caught(card, tmp_path):
    card[0].key = ec.generate_private_key(ec.SECP256R1())
    result = run(_import(tmp_path, "--pin", "123456"))
    assert result.exit_code != 0
    assert "does not verify against the imported key" in result.output


@pytest.mark.parametrize(
    ("where", "sw", "text"),
    [
        ("sign", (0x6A, 0x80), "GENERAL AUTHENTICATE (smoke)"),
        ("pin", None, "63C2"),
        ("element", (0x6A, 0x80), "IMPORT 9C [CLEAR (9F)] - the card rejected this element"),
        ("element", (0x6F, 0x00), "the chip refuses this key size"),
    ],
    ids=["sign-refused", "wrong-pin", "element-refused", "key-size-refused"],
)
def test_failures_name_the_step(card, tmp_path, where, sw, text):
    piv = card[0]
    if where == "sign":
        piv.sign_sw = sw
    elif where == "element":
        piv.secured_sw[0x24] = sw
    result = run(_import(tmp_path, "--pin", "999999" if where == "pin" else "123456"))
    assert result.exit_code != 0
    assert text in " ".join(result.output.split())


def test_rsa_modulus_goes_chained_over_the_secured_channel(card, tmp_path):
    key = rsa.generate_private_key(65537, 2048)
    _, scp, _ = card
    result = run(["--json", *_import(tmp_path, "--no-smoke-test", key=key, slot="9A")])
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)["elements"]) == 8
    blocks = [body for ins, p1, p2, body in scp.secured if (ins, p1, p2) == (0x24, 0x07, 0x9A)]
    assert len(blocks) == 9  # the 260-byte N element travels as two chained blocks
    n = key.public_key().public_numbers().n.to_bytes(256, "big")
    assert blocks[1] + blocks[2] == b"\x81\x82\x01\x00" + n


def test_missing_key_object_is_created_first(card, tmp_path):
    piv, scp, _ = card
    piv.probe_sw = (0x6A, 0x86)
    args = _import(tmp_path, "--create-key-object", "--no-smoke-test")
    result = run(["--yes", "--json", *args])
    assert result.exit_code == 0, result.output
    assert "creating the key object (PUT DATA ADMIN)" in result.output
    assert [s[0] for s in scp.secured] == [0xDB, 0x24, 0x24, 0x24]


def test_public_out_names_a_path_with_brackets_as_written(card, tmp_path):
    folder = tmp_path / "old [draft]"
    folder.mkdir()
    pub = folder / "pub.pem"
    result = run(_import(tmp_path, "--no-smoke-test", "--public-out", str(pub)))
    assert result.exit_code == 0, result.output
    assert pub.exists()
    assert f"Public key PEM -> {pub}" in " ".join(result.output.split())
