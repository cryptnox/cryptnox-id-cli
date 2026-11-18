# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``fido`` read commands, PIN commands, the credential self-test and the credential list."""

from __future__ import annotations

import hashlib
import hmac
import json

import cbor2
import pytest
from _cardfakes import CtapRouter, ResponseAdapter, fake_tty, run, run_both_modes, wire_session
from test_fido_credential import FakeCredCard
from test_fido_credmgmt import FakeCredMgmtCard
from test_fido_pinproto import FakeFidoCard

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.cli.commands import fido as fido_cmd

SELECT_FIDO = "00A4040008A0000006472F000100"
GET_INFO = "80100000010400"
GET_RETRIES = "801000000606A20101020100"
CRYPTNOX_AAGUID = bytes.fromhex("1d1b4e3376a147fb97a014b10d0933f1")

FULL_INFO = {
    c.INFO_VERSIONS: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
    c.INFO_EXTENSIONS: ["credProtect", "hmac-secret"],
    c.INFO_AAGUID: CRYPTNOX_AAGUID,
    c.INFO_OPTIONS: {"rk": True, "clientPin": True, "authnrCfg": True, "alwaysUv": False},
    c.INFO_MAX_MSG_SIZE: 1200,
    c.INFO_PIN_UV_AUTH_PROTOCOLS: [1, 2],
    c.INFO_TRANSPORTS: ["nfc"],
    c.INFO_ALGORITHMS: [{"alg": -7, "type": "public-key"}],
    c.INFO_MIN_PIN_LENGTH: 6,
    c.INFO_FIRMWARE_VERSION: 7,
}
# Not a Cryptnox AAGUID, no options or algorithms, empty lists: every fallback row.
BARE_INFO = {c.INFO_VERSIONS: [], c.INFO_AAGUID: bytes(16)}


@pytest.fixture
def info_card(monkeypatch, mock_connection):
    def _wire(info, version=b"FIDO_2_1"):
        exchanges = {
            SELECT_FIDO: version.hex() + "|9000",
            GET_INFO: "00" + cbor2.dumps(info).hex() + "|9000",
        }
        wire_session(monkeypatch, mock_connection("3B00", exchanges, []))

    return _wire


@pytest.mark.parametrize("cmd", ["info", "get-info"])
def test_info_reports_every_property(info_card, cmd):
    info_card(FULL_INFO)
    as_json, human = run_both_modes(["fido", cmd])
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["select_version"] == "FIDO_2_1"
    assert payload["cryptnox_aaguid"] is True
    assert payload["algorithms"] == [{"alg": -7, "type": "public-key"}]
    assert human.exit_code == 0, human.output
    for text in ("U2F_V2, FIDO_2_0, FIDO_2_1", "Cryptnox AAGUID", "option clientPin", "-7"):
        assert text in human.stdout
    assert "Firmware" in human.stdout and "7" in human.stdout


@pytest.mark.parametrize(
    ("info", "cryptnox_row"),
    [(BARE_INFO, "no"), ({c.INFO_VERSIONS: ["FIDO_2_0"]}, "-")],
    ids=["foreign-aaguid", "no-aaguid"],
)
def test_info_falls_back_on_missing_fields(info_card, info, cryptnox_row):
    info_card(info)
    as_json, human = run_both_modes(["fido", "info"])
    assert json.loads(as_json.stdout)["options"] is None
    assert human.exit_code == 0, human.output
    row = next(line for line in human.stdout.splitlines() if "Cryptnox AAGUID" in line)
    assert row.split()[-2] == cryptnox_row
    assert "option " not in human.stdout and "Algorithms" not in human.stdout


@pytest.mark.parametrize(("ep", "shown"), [(None, "not supported"), (True, "True")])
def test_config_show_reports_policy(info_card, ep, shown):
    info = dict(FULL_INFO)
    if ep is not None:
        info[c.INFO_OPTIONS] = {**FULL_INFO[c.INFO_OPTIONS], "ep": ep}
    info_card(info)
    as_json, human = run_both_modes(["fido", "config", "show"])
    payload = json.loads(as_json.stdout)
    assert payload["authenticator_config_supported"] is True
    assert payload["set_min_pin_length_supported"] is False
    assert payload["min_pin_length"] == 6
    assert payload["enterprise_attestation"] == ep
    row = next(line for line in human.stdout.splitlines() if "enterprise attestation" in line)
    assert shown in row
    assert "bio enrollment and large-blob are not implemented" in human.stdout


def _status_card(monkeypatch, client_pin, retries_reply):
    options = {"rk": True} if client_pin is None else {"clientPin": client_pin}
    info = "00" + cbor2.dumps({c.INFO_VERSIONS: ["FIDO_2_1"], c.INFO_OPTIONS: options}).hex()
    conn = ResponseAdapter(
        FakeFidoCard(),
        answers={
            GET_INFO: (bytes.fromhex(info), 0x90, 0x00),
            GET_RETRIES: (b"\x00" + cbor2.dumps(retries_reply), 0x90, 0x00),
        },
    )
    wire_session(monkeypatch, conn)
    return conn


@pytest.mark.parametrize(
    ("client_pin", "reply", "expect", "lines", "absent"),
    [
        (None, {}, (False, None, None, None), ["not supported"], ["FIDO PIN:"]),
        (
            True,
            {3: 8, 4: False},
            (True, True, 8, False),
            ["FIDO PIN: set", "remaining: 8"],
            ["power cycle"],
        ),
        (True, {3: 0, 4: True}, (True, True, 0, True), ["remaining: 0", "power cycle"], []),
        (False, {}, (True, False, None, None), ["FIDO PIN: not set"], ["remaining"]),
    ],
    ids=["no-client-pin", "set", "blocked-until-power-cycle", "not-set"],
)
def test_pin_status(monkeypatch, client_pin, reply, expect, lines, absent):
    conn = _status_card(monkeypatch, client_pin, reply)
    as_json, human = run_both_modes(["fido", "pin", "status"])
    payload = json.loads(as_json.stdout)
    keys = ("pin_supported", "pin_set", "retries_remaining", "power_cycle_required")
    assert tuple(payload[k] for k in keys) == expect
    assert (GET_RETRIES in conn.log) is (client_pin is not None)
    for text in lines:
        assert text in human.stdout
    for text in absent:
        assert text not in human.stdout


@pytest.mark.parametrize("json_mode", [True, False])
@pytest.mark.parametrize("protocol", [1, 2])
def test_pin_set_reaches_the_card(monkeypatch, json_mode, protocol):
    card = FakeFidoCard(protocol=protocol)
    wire_session(monkeypatch, card)
    monkeypatch.setenv("NEW_FIDO_PIN", "246810")
    args = ["fido", "pin", "set", "--pin-env", "NEW_FIDO_PIN", "--protocol", str(protocol)]
    result = run(["--json", *args] if json_mode else args)
    assert result.exit_code == 0, result.output
    assert card.pin == b"246810"
    if json_mode:
        assert json.loads(result.stdout) == {"pin_set": True, "protocol": protocol}
    else:
        assert "FIDO PIN set." in result.stdout
    assert "246810" not in result.output


@pytest.mark.parametrize("json_mode", [True, False])
def test_pin_change_reaches_the_card(monkeypatch, json_mode):
    card = FakeFidoCard()
    card.pin = b"1234"
    wire_session(monkeypatch, card)
    monkeypatch.setenv("CUR", "1234")
    monkeypatch.setenv("NEW", "567890")
    args = ["fido", "pin", "change", "--current-pin-env", "CUR", "--new-pin-env", "NEW"]
    result = run(["--json", *args] if json_mode else args)
    assert result.exit_code == 0, result.output
    assert card.pin == b"567890"
    assert ("pin_changed" if json_mode else "FIDO PIN changed.") in result.stdout


def test_pin_change_wrong_current_pin_is_reported(monkeypatch):
    card = FakeFidoCard()
    card.pin = b"1234"
    wire_session(monkeypatch, card)
    monkeypatch.setenv("CUR", "9999")
    monkeypatch.setenv("NEW", "567890")
    args = ["--json", "fido", "pin", "change", "--current-pin-env", "CUR", "--new-pin-env", "NEW"]
    result = run(args)
    assert result.exit_code != 0
    assert "PIN is invalid" in result.stdout
    assert card.pin == b"1234"


@pytest.mark.parametrize("json_mode", [True, False])
@pytest.mark.parametrize("pin_env", [None, "UNSET_FIDO_PIN"], ids=["no-option", "unset-var"])
def test_pin_set_without_a_pin_source_refuses(monkeypatch, json_mode, pin_env):
    card = FakeFidoCard()
    wire_session(monkeypatch, card)
    monkeypatch.delenv("UNSET_FIDO_PIN", raising=False)
    args = ["fido", "pin", "set"] + (["--pin-env", pin_env] if pin_env else [])
    result = run(["--json", *args] if json_mode else args)
    assert result.exit_code != 0
    assert f"set ${pin_env or 'a PIN env var'}" in result.output
    assert card.sent == []


def test_pin_set_prompts_on_a_terminal(monkeypatch):
    card = FakeFidoCard()
    wire_session(monkeypatch, card)
    fake_tty(monkeypatch, fido_cmd)
    result = run(["fido", "pin", "set"], input="135791\n135791\n")
    assert result.exit_code == 0, result.output
    assert card.pin == b"135791"


def _pin_cred_card(pin: bytes, protocol: int = 1, card=None) -> CtapRouter:
    pin_card = FakeFidoCard(protocol=protocol)
    pin_card.pin = pin
    return CtapRouter(pin_card, card or FakeCredCard())


def _requests(sent, cmd):
    return [cbor2.loads(raw[6 : 5 + raw[4]]) for raw in sent if raw[1] == 0x10 and raw[5] == cmd]


def test_self_test_round_trip_verifies(monkeypatch):
    card = FakeCredCard()
    wire_session(monkeypatch, card)
    as_json, human = run_both_modes(["fido", "credential", "self-test", "--rk"])
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["assertion_verified"] is True and payload["resident"] is True
    assert bytes.fromhex(payload["credential_id"]) in card.creds
    make = _requests(card.sent, c.CTAP_MAKE_CREDENTIAL)
    assert make[0][c.MC_OPTIONS] == {"rk": True} and c.MC_PIN_UV_AUTH_PARAM not in make[0]
    assert "register -> assert -> verify: PASS" in human.stdout


def test_self_test_reports_a_bad_signature(monkeypatch):
    class BadSigCard(FakeCredCard):
        def transmit(self, apdu):
            data, sw1, sw2 = super().transmit(apdu)
            if bytes(apdu)[5:6] == bytes([c.CTAP_GET_ASSERTION]):
                body = cbor2.loads(bytes(data[1:]))
                body[c.GAR_SIGNATURE] = bytes(70)
                data = [0x00, *cbor2.dumps(body)]
            return data, sw1, sw2

    wire_session(monkeypatch, BadSigCard())
    as_json, human = run_both_modes(["fido", "credential", "self-test"])
    assert json.loads(as_json.stdout)["assertion_verified"] is False
    assert "FAIL" in human.stdout and "registered key: False" in human.stdout


@pytest.mark.parametrize("protocol", [1, 2])
def test_self_test_with_pin_sends_a_pin_uv_auth_param(monkeypatch, protocol):
    card = _pin_cred_card(b"1234", protocol=protocol)
    wire_session(monkeypatch, card)
    monkeypatch.setenv("FIDO_PIN", "1234")
    args = ["--json", "fido", "credential", "self-test", "--pin-env", "FIDO_PIN"]
    result = run([*args, "--rp-id", "example.com", "--protocol", str(protocol)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["assertion_verified"] is True
    tokens = _requests(card.sent, c.CTAP_CLIENT_PIN)
    perms = [t[c.CP_PERMISSIONS] for t in tokens if c.CP_PERMISSIONS in t]
    assert perms == [c.PERM_MAKE_CREDENTIAL | c.PERM_GET_ASSERTION, c.PERM_GET_ASSERTION]
    make = _requests(card.sent, c.CTAP_MAKE_CREDENTIAL)[0]
    mac = hmac.new(card.pin_card.token, make[c.MC_CLIENT_DATA_HASH], hashlib.sha256).digest()
    assert make[c.MC_PIN_UV_AUTH_PARAM] == (mac[:16] if protocol == 1 else mac)
    assert "1234" not in result.output


def test_self_test_with_an_unset_pin_env_stops_before_registering(monkeypatch):
    card = _pin_cred_card(b"1234")
    wire_session(monkeypatch, card)
    monkeypatch.delenv("NO_SUCH_PIN", raising=False)
    result = run(["--json", "fido", "credential", "self-test", "--pin-env", "NO_SUCH_PIN"])
    assert result.exit_code != 0
    assert "environment variable NO_SUCH_PIN is not set" in result.stdout
    assert _requests(card.sent, c.CTAP_MAKE_CREDENTIAL) == []


def test_self_test_with_a_wrong_pin_is_refused_by_the_card(monkeypatch):
    card = _pin_cred_card(b"1234")
    wire_session(monkeypatch, card)
    monkeypatch.setenv("FIDO_PIN", "0000")
    result = run(["--json", "fido", "credential", "self-test", "--pin-env", "FIDO_PIN"])
    assert result.exit_code != 0
    assert "PIN is invalid" in result.stdout
    assert card.card.creds == {}


LIST = ["fido", "credential", "list", "--pin-env", "FIDO_PIN"]


def test_credential_list_names_each_resident_credential(monkeypatch):
    wire_session(monkeypatch, _pin_cred_card(b"1234", card=FakeCredMgmtCard()))
    monkeypatch.setenv("FIDO_PIN", "1234")
    as_json, human = run_both_modes(LIST)
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert (payload["existing"], payload["max_remaining"]) == (2, 10)
    assert [(x["rp_id"], x["user"]) for x in payload["credentials"]] == [
        ("example.com", "alice"),
        ("example.com", "bob"),
    ]
    text = " ".join(human.stdout.split())
    assert "Resident credentials: 2 (room for ~10 more)" in text
    assert f"- rp=example.com user=alice id={b'cred-1'.hex().upper()}" in text


def test_credential_list_prints_user_names_as_written(monkeypatch):
    names = ("a[/x]b", "[b]bob[/b]")
    wire_session(monkeypatch, _pin_cred_card(b"1234", card=FakeCredMgmtCard(names=names)))
    monkeypatch.setenv("FIDO_PIN", "1234")
    result = run(LIST)
    assert result.exit_code == 0, result.output
    assert "user=a[/x]b" in result.stdout and "user=[b]bob[/b]" in result.stdout


def test_ping_prints_the_version_string_as_written(info_card):
    info_card(FULL_INFO, version=b"FIDO_[/x]")
    result = run(["fido", "ping"])
    assert result.exit_code == 0, result.output
    assert "Version string: FIDO_[/x]" in result.stdout


def test_info_prints_card_strings_as_written(info_card):
    info = dict(FULL_INFO)
    info[c.INFO_VERSIONS] = ["FIDO_2_1", "[b]X[/b]"]
    info[c.INFO_EXTENSIONS] = ["a[/x]b"]
    info[c.INFO_OPTIONS] = {"[b]opt[/b]": True}
    info[c.INFO_ALGORITHMS] = [{"alg": -7, "type": "[b]pk[/b]"}]
    info_card(info)
    result = run(["fido", "info"])
    assert result.exit_code == 0, result.output
    for text in ("FIDO_2_1, [b]X[/b]", "a[/x]b", "option [b]opt[/b]", "-7 ([b]pk[/b])"):
        assert text in result.stdout
