# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``fido credential create``, ``assert`` and ``delete``, the ``config`` writes and ``reset``,
run against card doubles with nothing in ``fido.py`` patched."""

from __future__ import annotations

import json

import cbor2
import pytest
from _cardfakes import CtapRouter, fake_tty, run, run_both_modes, wire_session
from test_fido_credential import FakeCredCard
from test_fido_credmgmt import FakeCredMgmtCard
from test_fido_pinproto import FakeFidoCard

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.cli.commands import fido as fido_cmd


def _ctap(raw: bytes) -> tuple[int, dict]:
    payload = raw[5 : 5 + raw[4]]
    return payload[0], cbor2.loads(payload[1:]) if len(payload) > 1 else {}


class PolicyCard:
    """An authenticator whose getInfo reflects its config: alwaysUv and the minimum PIN length."""

    def __init__(self, *, always_uv: bool = False, min_pin_length: int = 4) -> None:
        self.always_uv = always_uv
        self.min_pin_length = min_pin_length
        self.reset_done = False
        self.sent: list[bytes] = []

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.sent.append(raw)
        if raw[1] == 0xA4:
            return list(b"FIDO_2_1"), 0x90, 0x00
        cmd, params = _ctap(raw)
        if cmd == c.CTAP_GET_INFO:
            info = {
                c.INFO_VERSIONS: ["FIDO_2_1"],
                c.INFO_OPTIONS: {"authnrCfg": True, "alwaysUv": self.always_uv},
                c.INFO_MIN_PIN_LENGTH: self.min_pin_length,
            }
            return [0x00, *cbor2.dumps(info)], 0x90, 0x00
        if cmd == c.CTAP_AUTHENTICATOR_CONFIG:
            sub = params[c.AC_SUBCOMMAND]
            if sub == c.AC_TOGGLE_ALWAYS_UV:
                self.always_uv = not self.always_uv
            elif sub == c.AC_SET_MIN_PIN_LENGTH:
                self.min_pin_length = params[c.AC_SUBCOMMAND_PARAMS][c.ACP_NEW_MIN_PIN_LENGTH]
            return [0x00], 0x90, 0x00
        if cmd == c.CTAP_RESET:
            self.reset_done = True
            return [0x00], 0x90, 0x00
        return [0x01], 0x90, 0x00

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


def _pin_router(card) -> CtapRouter:
    pin_card = FakeFidoCard()
    pin_card.pin = b"1234"
    return CtapRouter(pin_card, card)


@pytest.mark.parametrize("rk", [False, True], ids=["non-resident", "resident"])
def test_credential_create_registers_on_the_card(monkeypatch, rk):
    card = FakeCredCard()
    wire_session(monkeypatch, card)
    args = ["fido", "credential", "create", "--rp-id", "example.com", *(["--rk"] if rk else [])]
    as_json, human = run_both_modes(args)
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["registered"] is True and payload["rp_id"] == "example.com"
    assert bytes.fromhex(payload["credential_id"]) in card.creds
    make = next(_ctap(f)[1] for f in card.sent if f[1] == 0x10 and f[5] == c.CTAP_MAKE_CREDENTIAL)
    assert make.get(c.MC_OPTIONS) == ({"rk": True} if rk else None)
    assert "Registered credential on example.com." in human.output


def test_credential_create_with_a_pin_sends_a_pin_uv_auth_param(monkeypatch):
    router = _pin_router(FakeCredCard())
    wire_session(monkeypatch, router)
    monkeypatch.setenv("FIDO_PIN", "1234")
    result = run(["--json", "fido", "credential", "create", "--pin-env", "FIDO_PIN"])
    assert result.exit_code == 0, result.output
    make = next(_ctap(f)[1] for f in router.sent if f[1] == 0x10 and f[5] == c.CTAP_MAKE_CREDENTIAL)
    assert c.MC_PIN_UV_AUTH_PARAM in make


def test_credential_assert_signs_with_the_credential_it_names(monkeypatch):
    card = FakeCredCard()
    wire_session(monkeypatch, card)
    create = ["--json", "fido", "credential", "create", "--rp-id", "example.com"]
    ids = [json.loads(run(create).stdout)["credential_id"] for _ in range(2)]
    args = ["fido", "credential", "assert", "--rp-id", "example.com", "--credential-id", ids[1]]
    as_json, human = run_both_modes(args)
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["asserted"] is True and payload["credential_id"] == ids[1]
    assert payload["signature_len"] > 0
    get = next(_ctap(f)[1] for f in card.sent if f[1] == 0x10 and f[5] == c.CTAP_GET_ASSERTION)
    assert [x["id"] for x in get[c.GA_ALLOW_LIST]] == [bytes.fromhex(ids[1])]
    assert f"Assertion OK (credential {ids[1]}," in " ".join(human.output.split())


def test_credential_delete_removes_it_by_id(monkeypatch):
    cred = FakeCredMgmtCard()
    wire_session(monkeypatch, _pin_router(cred))
    monkeypatch.setenv("FIDO_PIN", "1234")
    args = ["--yes", "fido", "credential", "delete", "--credential-id", b"cred-1".hex()]
    as_json, human = run_both_modes([*args, "--pin-env", "FIDO_PIN"])
    assert json.loads(as_json.stdout) == {"deleted": True, "credential_id": b"cred-1".hex().upper()}
    assert cred.deleted == [b"cred-1", b"cred-1"]
    assert "Deleted credential." in human.output


def test_credential_delete_declined_sends_nothing(monkeypatch):
    router = _pin_router(FakeCredMgmtCard())
    wire_session(monkeypatch, router)
    monkeypatch.setenv("FIDO_PIN", "1234")
    args = ["fido", "credential", "delete", "--credential-id", "AABB", "--pin-env", "FIDO_PIN"]
    result = run(args, input="n\n")
    assert result.exit_code != 0
    assert router.sent == []


@pytest.mark.parametrize("command", ["list", "delete"])
def test_credential_management_without_a_pin_is_refused(monkeypatch, command):
    router = _pin_router(FakeCredMgmtCard())
    wire_session(monkeypatch, router)
    args = ["--yes", "fido", "credential", command, "--pin-env", ""]
    if command == "delete":
        args += ["--credential-id", "AABB"]
    result = run(args)
    assert result.exit_code != 0
    assert "credential management requires a PIN" in result.output


def test_credential_list_shows_an_unnamed_user_as_a_question_mark(monkeypatch):
    class UnnamedUsers(FakeCredMgmtCard):
        def _resp(self, status, payload=None):
            if isinstance(payload, dict) and c.CMR_USER in payload:
                payload = {**payload, c.CMR_USER: b"not-a-map"}
            return super()._resp(status, payload)

    wire_session(monkeypatch, _pin_router(UnnamedUsers()))
    monkeypatch.setenv("FIDO_PIN", "1234")
    result = run(["--json", "fido", "credential", "list", "--pin-env", "FIDO_PIN"])
    assert result.exit_code == 0, result.output
    assert {x["user"] for x in json.loads(result.stdout)["credentials"]} == {"?"}


def test_toggle_always_uv_reports_before_and_after(monkeypatch):
    card = PolicyCard(always_uv=False)
    wire_session(monkeypatch, card)
    as_json, human = run_both_modes(["--yes", "fido", "config", "toggle-always-uv"])
    assert json.loads(as_json.stdout) == {"always_uv_before": False, "always_uv_after": True}
    assert "alwaysUv: True -> False" in human.output  # the second run toggles it back


@pytest.mark.parametrize("force", [False, True], ids=["plain", "force-change-pin"])
def test_min_pin_length_reports_before_and_after(monkeypatch, force):
    card = PolicyCard(min_pin_length=4)
    wire_session(monkeypatch, card)
    args = ["--yes", "fido", "config", "min-pin-length", "--length", "6"]
    as_json, human = run_both_modes([*args, *(["--force-change-pin"] if force else [])])
    assert json.loads(as_json.stdout) == {
        "min_pin_length_before": 4,
        "min_pin_length_after": 6,
        "force_change_pin": force,
    }
    config = next(
        _ctap(f)[1] for f in card.sent if f[1] == 0x10 and f[5] == c.CTAP_AUTHENTICATOR_CONFIG
    )
    assert (c.ACP_FORCE_CHANGE_PIN in config[c.AC_SUBCOMMAND_PARAMS]) is force
    assert "min PIN length: 6 -> 6" in human.output  # the second run starts from 6


def test_min_pin_length_below_four_is_refused(monkeypatch):
    card = PolicyCard()
    wire_session(monkeypatch, card)
    result = run(["--yes", "fido", "config", "min-pin-length", "--length", "3"])
    assert result.exit_code != 0
    assert "minimum PIN length must be at least 4" in result.output
    assert card.sent == []


def test_reset_with_the_flag_resets_the_authenticator(monkeypatch):
    card = PolicyCard()
    wire_session(monkeypatch, card)
    as_json, human = run_both_modes(["fido", "reset", "--i-understand-this-wipes-all-credentials"])
    assert json.loads(as_json.stdout) == {"reset": True}
    assert card.reset_done
    assert "FIDO2 authenticator reset." in human.output


def test_reset_needs_the_flag_without_a_terminal(monkeypatch):
    card = PolicyCard()
    wire_session(monkeypatch, card)
    result = run(["fido", "reset"])
    assert result.exit_code != 0
    assert "needs --i-understand-this-wipes-all-credentials non-interactively" in result.output
    assert card.sent == []


@pytest.mark.parametrize(("typed", "reset"), [("RESET-FIDO", True), ("reset", False)])
def test_reset_on_a_terminal_wants_the_phrase(monkeypatch, typed, reset):
    card = PolicyCard()
    wire_session(monkeypatch, card)
    fake_tty(monkeypatch, fido_cmd)
    result = run(["fido", "reset"], input=f"{typed}\n")
    assert (result.exit_code == 0) is reset, result.output
    assert "Type RESET-FIDO to continue" in result.output
    assert card.reset_done is reset
