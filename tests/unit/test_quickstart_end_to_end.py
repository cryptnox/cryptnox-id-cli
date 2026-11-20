# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv quickstart`` end to end, with nothing in ``piv.py`` patched.

Most tests run behind ``_piv_card``, where secured commands reach a PIV applet; a few use
the SCP03 double alone, which answers every secured command 6D00.
"""

from __future__ import annotations

import json

import pytest
from _cardfakes import ResponseAdapter, run, run_both_modes, wire_session
from _piv_card import PivResponder, UnwrappingScp03Card
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from test_scp03 import GP_KEY, FakeScp03Card

from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv import objects as piv_obj
from cryptnox_id_cli.transport.scp03 import Scp03Keys

SELECT_PIV = "00A404000BA00000030800001000010000"
PROBE = keyimport.probe_apdu(0x9C, 0x11).to_bytes().hex().upper()
VERIFY_123456 = "0020008008313233343536FFFF"
GET_CHUID = "00CB3FFF055C035FC10200"


def _get_data(oid: bytes) -> str:
    return f"00CB3FFF{len(oid) + 2:02X}5C{len(oid):02X}{oid.hex().upper()}00"


#: A pre-personalized card answers a GET DATA for every container 6A82.
NO_OBJECTS = {_get_data(o.oid): ([], 0x6A, 0x82) for o in piv_obj.PIV_OBJECTS}


@pytest.fixture
def apt(acs_transcript):
    return bytes.fromhex(acs_transcript["exchanges"][SELECT_PIV].split("|")[0])


SET_PIN, SET_PUK, GENERATE, PUT = (
    (0x24, 0xFF, 0x80),
    (0x24, 0xFF, 0x81),
    (0x47, 0x00, 0x9C),
    (0xDB, 0x3F, 0xFF),
)


@pytest.fixture
def card(monkeypatch, apt):
    monkeypatch.setenv("CRYPTNOX_PIV_NEW_PIN", "123456")
    monkeypatch.setenv("CRYPTNOX_PIV_NEW_PUK", "12345678")
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    piv = PivResponder(apt, pin=b"123456")
    scp = UnwrappingScp03Card(on_secured=piv.secured, on_plain=piv.plain)
    wire_session(monkeypatch, ResponseAdapter(scp), reader_name="Fake Reader 00 00")
    return piv, scp


def _qs(*extra):
    return ["--yes", "piv", "quickstart", "--default-keys", *extra]


def _steps(stdout):
    return {s["step"]: s for s in json.loads(stdout)["steps"]}


def test_pre_personalized_card_to_a_self_signed_certificate(card, tmp_path):
    piv, scp = card
    cert_out, pub_out = tmp_path / "c.pem", tmp_path / "p.pem"
    as_json, human = run_both_modes(_qs("--cert-out", str(cert_out), "--public-out", str(pub_out)))
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert [(s["step"], s["status"]) for s in payload["steps"]] == [
        ("preperso-load-config", "skipped"),
        ("create-key-object", "skipped"),
        ("set-pin", "ok"),
        ("set-puk", "ok"),
        ("generate-key", "ok"),
        ("certificate", "ok"),
        ("write-chuid", "ok"),
        ("write-ccc", "ok"),
        ("smoke-test", "ok"),
    ]
    assert payload["outputs"] == {
        "public_key": str(pub_out),
        "certificate": str(cert_out),
        "csr": None,
    }
    assert "withholds its key listing" in as_json.output
    secured = [s[:3] for s in scp.secured]
    assert secured[:7] == [SET_PIN, SET_PUK, GENERATE, PUT, PUT, PUT, PUT]  # cert takes 2 blocks
    assert scp.secured[0][3] == b"123456\xff\xff" and scp.secured[1][3] == b"12345678"
    cert = x509.load_pem_x509_certificate(cert_out.read_bytes())
    public = serialization.load_pem_public_key(pub_out.read_bytes())
    public.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    text = " ".join(human.output.split())
    assert "Verify with standard PIV tooling" in text
    assert 'yubico-piv-tool -r "Fake Reader 00 00" -a read-certificate -s 9c -o 9c.crt.pem' in text


def test_csr_mode_writes_a_request_signed_on_card(card, tmp_path):
    csr_out = tmp_path / "req.pem"
    as_json, human = run_both_modes(_qs("--cert-mode", "csr", "--csr-out", str(csr_out)))
    assert as_json.exit_code == 0, as_json.output
    assert _steps(as_json.stdout)["certificate"]["detail"]["mode"] == "csr"
    assert x509.load_pem_x509_csr(csr_out.read_bytes()).is_signature_valid
    assert "invalidates" in human.output  # the table wraps the note across lines


def test_set_pin_is_verified_not_overwritten(card):
    piv, scp = card
    piv.status = {0x80: (0x63, 0xC3), 0x81: (0x63, 0xC3)}
    piv.key = ec.generate_private_key(ec.SECP256R1())
    piv.sign_sw = (0x69, 0x85)
    as_json, human = run_both_modes(_qs("--cert-mode", "none"))
    steps = _steps(as_json.stdout)
    assert steps["set-pin"] == {
        "step": "set-pin",
        "status": "skipped",
        "reason": "PIN already set (verified)",
    }
    assert steps["certificate"]["reason"] == "--cert-mode none"
    assert steps["smoke-test"]["detail"]["note"] == "slot role cannot sign on this applet"
    assert SET_PIN not in [s[:3] for s in scp.secured]
    assert "slot role cannot sign on this applet" in human.output


def test_empty_verifier_flips_pin_and_puk_back_on(card):
    piv, _ = card
    piv.status = {0x80: (0x63, 0xC3), 0x81: (0x63, 0xC3)}
    piv.pin = None
    result = run(["--json", *_qs("--cert-mode", "none")])
    assert result.exit_code == 0, result.output
    steps = _steps(result.stdout)
    assert steps["set-pin"]["status"] == steps["set-puk"]["status"] == "ok"
    assert "verifier exists but holds no value" in result.output


@pytest.mark.parametrize(
    ("refuse", "failed_step"),
    [({0x24: (0x69, 0x82)}, "set-pin"), ({0x47: (0x6A, 0x80)}, "generate-key")],
)
def test_first_failure_stops_the_run(card, refuse, failed_step):
    card[0].secured_sw.update(refuse)
    as_json, human = run_both_modes(_qs())
    assert as_json.exit_code == 6 and human.exit_code == 6
    payload = json.loads(as_json.stdout)
    assert (
        payload["steps"][-1]["step"] == failed_step and payload["steps"][-1]["status"] == "failed"
    )
    assert payload["next"] == []
    assert "quickstart stopped at the first failure" in " ".join(human.output.split())


def test_include_preperso_lays_down_the_structure(card):
    piv, scp = card
    piv.probe_sw = (0x6A, 0x86)
    result = run(["--json", *_qs("--include-preperso")])
    assert result.exit_code == 0, result.output
    steps = _steps(result.stdout)
    assert steps["preperso-load-config"]["detail"] == {"profile": "cryptnox-default"}
    assert steps["create-key-object"]["status"] == "skipped"
    assert "lays down the applet structure" in result.output
    assert scp.secured[0][:2] == (0xDB, 0x3F) and scp.secured[0][2] != 0xFF


@pytest.mark.parametrize(
    ("status", "advice"),
    [
        ({0x80: (0x6A, 0x88), 0x81: (0x6A, 0x88)}, "and no PIV structure yet"),
        ({0x80: (0x63, 0xC3), 0x81: (0x63, 0xC3)}, "only ms-logon's 9A creates one"),
    ],
)
def test_rsa_without_a_key_object_explains_the_way_out(card, status, advice):
    card[0].probe_sw, card[0].status = (0x6A, 0x86), status
    result = run(_qs("--algorithm", "RSA2048"))
    assert result.exit_code == 2
    assert advice in " ".join(result.output.split())


@pytest.fixture
def plain_scp03_card(monkeypatch, apt):
    """The SCP03 double alone: every secured command is answered 6D00."""
    monkeypatch.setenv("CRYPTNOX_PIV_NEW_PIN", "123456")
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    monkeypatch.setenv("CRYPTNOX_PIV_NEW_PUK", "12345678")

    def _wire(pin_sw=(0x6A, 0x88), verify_sw=(0x90, 0x00), answers=None):
        conn = ResponseAdapter(
            FakeScp03Card(Scp03Keys.same(GP_KEY), bytes.fromhex("1122334455667788")),
            answers={
                **NO_OBJECTS,
                SELECT_PIV: (apt, 0x90, 0x00),
                "00200080": ([], *pin_sw),
                "00200081": ([], *pin_sw),
                PROBE: ([], 0x69, 0x82),
                VERIFY_123456: ([], *verify_sw),
                **(answers or {}),
            },
        )
        wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
        return conn

    return _wire


def test_dry_run_plans_without_writing(plain_scp03_card):
    conn = plain_scp03_card()
    as_json, human = run_both_modes(["piv", "quickstart", "--dry-run"])
    planned = {s["step"]: s["status"] for s in json.loads(as_json.stdout)["steps"]}
    assert planned["set-pin"] == "would-run" and planned["preperso-load-config"] == "skip"
    assert "DRY RUN - card state: PivPrePersonalized" in human.output
    assert not any(c.startswith("8050") for c in conn.log)


def test_first_secured_write_refused_stops_with_exit_6(plain_scp03_card):
    conn = plain_scp03_card()
    as_json, human = run_both_modes(["--yes", "piv", "quickstart", "--default-keys"])
    assert as_json.exit_code == 6 and human.exit_code == 6
    steps = json.loads(as_json.stdout)["steps"]
    assert steps[-1]["step"] == "set-pin" and "6D00" in steps[-1]["reason"]
    assert "quickstart stopped at the first failure" in " ".join(human.output.split())
    assert any(c.startswith("0424FF80") for c in conn.log)


@pytest.mark.parametrize(
    ("verify_sw", "code", "text"),
    [
        ((0x63, 0xC2), 1, "does not match (2 tries left)"),
        ((0x6A, 0x88), 6, "verifier exists but holds no value"),
        ((0x90, 0x00), 6, "generate-key"),
    ],
)
def test_pin_pre_flight(plain_scp03_card, verify_sw, code, text):
    plain_scp03_card(pin_sw=(0x63, 0xC3), verify_sw=verify_sw)
    result = run(["--yes", "piv", "quickstart", "--default-keys", "--cert-mode", "none"])
    assert result.exit_code == code
    assert text in " ".join(result.output.split())


def test_declining_the_confirmation_sends_nothing(plain_scp03_card):
    conn = plain_scp03_card()
    result = run(["piv", "quickstart", "--default-keys"], input="n\n")
    assert result.exit_code == 1
    assert not any(c.startswith("8050") for c in conn.log)


@pytest.mark.xfail(strict=True, reason="a failed read is reported as absent")
def test_an_unreadable_chuid_stops_the_run_before_any_write(plain_scp03_card):
    conn = plain_scp03_card(answers={GET_CHUID: ([], 0x6F, 0x00)})
    result = run(["--yes", "piv", "quickstart", "--default-keys"])
    assert result.exit_code == 1, result.output
    assert "could not read the card's CHUID" in " ".join(result.output.split())
    assert not any(c.startswith("8050") for c in conn.log)


NO_VALUE, SET_3 = (0x6A, 0x88), (0x63, 0xC3)


@pytest.mark.parametrize(
    ("setup", "extra", "failed_step", "context"),
    [
        (
            {"probe_sw": (0x6A, 0x86), "secured_sw": {0xDB: (0x6A, 0x80)}},
            ["--include-preperso"],
            "preperso-load-config",
            "preperso [",
        ),
        (
            {"status": {0x80: SET_3, 0x81: NO_VALUE}, "secured_sw": {0x24: (0x69, 0x82)}},
            [],
            "set-puk",
            "SET PUK",
        ),
        ({"secured_sw": {0xDB: (0x6A, 0x84)}}, [], "certificate", "IMPORT cert"),
        (
            {"secured_sw": {0xDB: (0x6A, 0x84)}},
            ["--cert-mode", "none"],
            "write-chuid",
            "PUT DATA chuid",
        ),
        ({"sign_sw": (0x6A, 0x80)}, ["--cert-mode", "none"], "smoke-test", "6A80"),
    ],
    ids=["preperso", "set-puk", "cert-import", "chuid", "smoke-test"],
)
def test_a_refused_later_step_stops_the_run(card, setup, extra, failed_step, context):
    piv, _ = card
    for name, value in setup.items():
        setattr(piv, name, value)
    result = run(["--json", *_qs(*extra)])
    assert result.exit_code == 6, result.output
    last = json.loads(result.stdout)["steps"][-1]
    assert (last["step"], last["status"]) == (failed_step, "failed")
    assert context in last["reason"]


def test_include_preperso_adds_only_the_missing_key_object(card):
    piv, scp = card
    piv.status, piv.probe_sw = {0x80: SET_3, 0x81: SET_3}, (0x6A, 0x86)
    result = run(["--json", *_qs("--include-preperso", "--cert-mode", "none")])
    assert result.exit_code == 0, result.output
    steps = _steps(result.stdout)
    assert steps["preperso-load-config"]["status"] == "skipped"
    assert steps["create-key-object"] == {
        "step": "create-key-object",
        "status": "ok",
        "detail": {"slot": "9C", "algorithm": "ECCP256"},
    }
    assert scp.secured[0][:2] == (0xDB, 0x3F) and scp.secured[0][2] != 0xFF


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--algorithm", "ED25519"], "not supported by this applet"),
        (["--slot", "9D"], "certificate modes sign on-card and need a SIGN-capable slot"),
        (
            ["--cert-mode", "none", "--cert-out", "c.pem"],
            "--cert-out applies to --cert-mode self-signed",
        ),
    ],
    ids=["algorithm", "slot", "cert-out"],
)
def test_bad_options_are_refused_before_the_card(plain_scp03_card, extra, message):
    conn = plain_scp03_card()
    result = run(_qs(*extra))
    assert result.exit_code == 2
    assert message in " ".join(result.output.split())
    assert conn.log == []
