# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv info``, ``certs export`` and ``inspect``, ``discover``, ``slots`` and ``objects``."""

from __future__ import annotations

import json

import pytest
from _cardfakes import run, run_both_modes, self_signed_der, wire_session
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cryptnox_id_cli.applets.piv.objects import wrap_certificate
from cryptnox_id_cli.cli.commands.piv import primitives as piv_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.util import tlv

SELECT_PIV = "00A404000BA00000030800001000010000"
PIV_AID = bytes.fromhex("A000000308000010000100")
DER = self_signed_der("Probe Signer")
CHUID = b"\x30\x19chuid-bytes"
DISCOVERY = tlv.build_constructed(0x7E, tlv.build(0x4F, PIV_AID), tlv.build(0x5F2F, b"\x40\x00"))


def _get(oid_hex: str) -> str:
    oid = bytes.fromhex(oid_hex)
    return f"00CB3FFF{len(oid) + 2:02X}5C{len(oid):02X}{oid_hex}00"


def _ok(value: bytes) -> str:
    return value.hex() + "|9000"


def apt(label: bytes = b"OpenFIPS201", url: bytes = b"http://example.test/sp800-73.pdf") -> str:
    """A PIV Application Property Template answer to SELECT."""
    body = (
        tlv.build(0x4F, PIV_AID)
        + tlv.build(0x79, tlv.build(0x4F, PIV_AID[:5]))
        + tlv.build(0x50, label)
        + tlv.build(0x5F50, url)
    )
    return _ok(tlv.build(0x61, body))


@pytest.fixture
def card(monkeypatch, mock_connection, acs_transcript):
    def _wire(select=None, *, discovery=True):
        exchanges = {
            SELECT_PIV: select or acs_transcript["exchanges"][SELECT_PIV],
            _get("5FC10A"): _ok(tlv.build(0x53, wrap_certificate(DER))),  # 9C
            _get("5FC102"): _ok(tlv.build(0x53, CHUID)),
        }
        if discovery:
            exchanges[_get("7E")] = _ok(DISCOVERY)
        conn = mock_connection(acs_transcript["atr"], exchanges, [])
        wire_session(monkeypatch, conn, reader_name="R")

    return _wire


@pytest.mark.parametrize(("der", "fmt"), [(False, "PEM"), (True, "DER")])
def test_certs_export(card, tmp_path, der, fmt):
    card()
    out = tmp_path / "c"
    args = ["piv", "certs", "export", "--slot", "9C", "--out", str(out)]
    as_json, human = run_both_modes([*args, *(["--der"] if der else [])])
    assert json.loads(as_json.stdout) == {
        "present": True,
        "slot": "9C",
        "out": str(out),
        "format": fmt,
    }
    pem = x509.load_der_x509_certificate(DER).public_bytes(serialization.Encoding.PEM)
    assert out.read_bytes() == (DER if der else pem)
    assert f"Wrote {fmt} certificate to" in human.output


@pytest.mark.parametrize("command", ["export", "inspect"])
def test_certs_absent_and_bad_slot(card, tmp_path, command):
    card()
    extra = ["--out", str(tmp_path / "c")] if command == "export" else []
    as_json, human = run_both_modes(["piv", "certs", command, "--slot", "9D", *extra])
    assert json.loads(as_json.stdout) == {"present": False, "slot": "9D"}
    assert "No certificate in slot 9D" in human.output
    assert run(["piv", "certs", command, "--slot", "9B", *extra]).exit_code == 2


def test_certs_inspect(card):
    card()
    as_json, human = run_both_modes(["piv", "certs", "inspect", "--slot", "9C"])
    assert json.loads(as_json.stdout)["certificate"]["subject"] == "CN=Probe Signer"
    assert "subject: CN=Probe Signer" in human.output


def test_discover_reads_the_pin_policy(card):
    card()
    as_json, human = run_both_modes(["piv", "discover"])
    assert json.loads(as_json.stdout) == {
        "present": True,
        "aid": "A000000308000010000100",
        "pin_policy": "4000",
    }
    assert "PIN usage policy: 4000" in human.output


def test_discover_absent(card):
    card(discovery=False)
    as_json, human = run_both_modes(["piv", "discover"])
    assert json.loads(as_json.stdout) == {"present": False}
    assert "Discovery object: not present" in human.output


def test_slots_and_info(card):
    card()
    as_json, human = run_both_modes(["piv", "slots"])
    cert = {s["ref"]: s["certificate"] for s in json.loads(as_json.stdout)["slots"]}
    assert cert["9C"] is True and cert["9D"] is False and cert["9B"] is None
    assert "9C" in human.output
    as_json, human = run_both_modes(["piv", "info"])
    payload = json.loads(as_json.stdout)
    assert (payload["aid"], payload["label"]) == ("A000000308000010000100", "OpenFIPS201")
    assert "Label: OpenFIPS201" in human.output
    assert "Supported algorithms:" in human.output


def test_objects_list_and_read(card, tmp_path):
    card()
    as_json, human = run_both_modes(["piv", "objects", "list"])
    present = {o["name"]: o["present"] for o in json.loads(as_json.stdout)["objects"]}
    assert present["chuid"] is True and present["ccc"] is False
    assert "chuid" in human.output
    as_json, human = run_both_modes(["piv", "objects", "read", "--object", "chuid"])
    assert json.loads(as_json.stdout)["hex"] == CHUID.hex().upper()
    out = tmp_path / "chuid.bin"
    as_json, human = run_both_modes(
        ["piv", "objects", "read", "--object", "chuid", "--out", str(out)]
    )
    assert out.read_bytes() == CHUID and "Wrote 13 bytes" in human.output
    assert run(["piv", "objects", "read", "--object", "nope"]).exit_code == 2
    as_json, human = run_both_modes(["piv", "objects", "read", "--object", "ccc"])
    assert json.loads(as_json.stdout) == {"name": "ccc", "present": False}
    assert "Object ccc: not present" in human.output


@pytest.mark.parametrize(
    ("label", "url"),
    [(b"Open[/x]FIPS", b"http://x.test/a"), (b"Open[b]FIPS[/b]", b"http://x.test/[b]a[/b]")],
    ids=["closing-tag", "bold"],
)
def test_info_prints_the_applet_label_and_url_as_written(card, label, url):
    card(select=apt(label, url))
    result = run(["piv", "info"])
    assert result.exit_code == 0, result.output
    assert f"Label: {label.decode()}" in result.output
    assert f"URL:   {url.decode()}" in result.output


def test_dry_run_refuses_a_pin_protected_object_before_the_pin(monkeypatch, mock_connection):
    """A wrong PIN spends a try, so --dry-run must not verify it to read the object."""
    exchanges = {
        SELECT_PIV: "|9000",
        "0020008008313233343536FFFF": "|9000",
        _get("5FC109"): _ok(tlv.build(0x53, b"printed")),
    }
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []))
    calls: list[str] = []
    open_session = AppContext.open_session
    monkeypatch.setattr(
        AppContext,
        "open_session",
        lambda self: calls.append("open_session") or open_session(self),
    )
    resolve = piv_cmd.resolve_secret
    monkeypatch.setattr(
        piv_cmd,
        "resolve_secret",
        lambda **kw: calls.append("resolve_secret") or resolve(**kw),
    )
    args = ["--dry-run", "piv", "objects", "read", "--object", "printed"]
    result = run(args, env={"CRYPTNOX_PIV_PIN": "123456"})
    assert calls == []
    assert result.exit_code == 1, result.output
    assert "--dry-run: reading 'printed' verifies the PIV PIN" in result.output
    assert "nothing was sent to the card" in result.output


def test_dry_run_still_reads_a_public_object(card):
    card()
    result = run(["--dry-run", "piv", "objects", "read", "--object", "chuid"])
    assert result.exit_code == 0, result.output
    assert CHUID.hex().upper() in result.output
