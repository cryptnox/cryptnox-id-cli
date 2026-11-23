# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What the PIN and PUK commands show for the answers the verifier rules read anew:
``63C0`` (no retry limit), ``6983`` over contactless, the quickstart pre-flight, and a
value that cannot fit on the wire."""

from __future__ import annotations

import contextlib
import json

import pytest
from _cardfakes import (
    CONTACT_READER,
    PICC_READER,
    PIV_GET_STATUS,
    PIV_STATUS_CONTACT,
    PIV_STATUS_CONTACTLESS,
    run,
    run_both_modes,
    wire_session,
)
from click.testing import CliRunner

from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.applets.piv.verifier import PIN, Op, Outcome, Verdict
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.pcsc import CardSession

SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
PROBE_PIN = "00200080"
PROBE_PUK = "00200081"


def _pad(value: str) -> str:
    return (value.encode() + b"\xff" * (8 - len(value))).hex().upper()


VERIFY = "0020008008" + _pad("123456")
CHANGE_PIN = "0024008010" + _pad("123456") + _pad("654321")
UNBLOCK = "002C008010" + _pad("12345678") + _pad("654321")


def _card(mock_connection, exchanges: dict[str, str], status: str | None, reader: str, monkeypatch):
    exchanges = {SELECT_PIV: f"{APT}|9000", **exchanges}
    if status is not None:
        exchanges[PIV_GET_STATUS] = f"{status}|9000"
    wire_session(monkeypatch, mock_connection("3B00", exchanges, []), reader_name=reader)


# ------------------------------------------------------------------------ 63C0 #
def test_pin_change_63c0_is_no_retry_limit_not_a_block(monkeypatch, mock_connection):
    _card(mock_connection, {CHANGE_PIN: "|63C0"}, PIV_STATUS_CONTACT, CONTACT_READER, monkeypatch)
    as_json, human = run_both_modes(
        ["piv", "pin", "change", "--old-pin", "123456", "--new-pin", "654321"]
    )
    assert as_json.exit_code == 6
    payload = json.loads(as_json.stdout)
    assert payload["changed"] is False and payload["sw"] == "63C0"
    assert not {"blocked", "recovery", "retries_remaining"} & payload.keys()
    assert "no retry limit" in payload["message"]
    assert "blocked" not in human.output


def test_status_63c0_is_not_blocked(monkeypatch, mock_connection):
    probes = {PROBE_PIN: "|63C6", PROBE_PUK: "|63C0"}
    _card(mock_connection, probes, PIV_STATUS_CONTACT, CONTACT_READER, monkeypatch)
    as_json, human = run_both_modes(["piv", "pin", "status"])
    puk = json.loads(as_json.stdout)["puk"]
    assert puk["blocked"] is False and puk["retries_remaining"] is None
    assert puk["state"] == "no_retry_limit"
    assert "PUK (81): no retry limit" in human.output
    as_json, human = run_both_modes(["piv", "status"])
    assert json.loads(as_json.stdout)["puk"]["blocked"] is False
    assert "PUK (81): set, no retry limit" in human.output
    assert "(blocked)" not in human.output


# ---------------------------------------------------------- 6983 over contactless #
def test_status_6983_over_contactless_is_no_tries_there_not_blocked(monkeypatch, mock_connection):
    probes = {PROBE_PIN: "|6983", PROBE_PUK: "|6982"}
    _card(mock_connection, probes, PIV_STATUS_CONTACTLESS, PICC_READER, monkeypatch)
    for args in (["piv", "pin", "status"], ["piv", "status"], ["info"], ["report", "piv"]):
        as_json, human = run_both_modes(args)
        assert as_json.exit_code == 0, as_json.output
        payload = json.loads(as_json.stdout)
        body = payload.get("piv", payload)
        if "state" in body and isinstance(body["state"], dict):
            body = body["state"]["piv"]
        pin = body["pin"]
        assert pin["blocked"] is None and pin["retries_remaining"] == 0
        assert pin["state"] == "no_tries_on_interface" and pin["interface"] == "contactless"
        assert "(blocked)" not in human.output and ": blocked" not in human.output
    note = json.loads(run(["--json", "piv", "pin", "status"]).stdout)["note"]
    assert "accepts the PIN" in note and "restores them" in note


def test_status_6983_over_contact_stays_blocked(monkeypatch, mock_connection):
    probes = {PROBE_PIN: "|6983", PROBE_PUK: "|63C6"}
    _card(mock_connection, probes, PIV_STATUS_CONTACT, CONTACT_READER, monkeypatch)
    as_json, human = run_both_modes(["piv", "status"])
    assert json.loads(as_json.stdout)["pin"]["blocked"] is True
    assert "PIN (80): set, blocked" in human.output
    assert ", PIN blocked" in run(["info"]).output


@pytest.mark.parametrize(
    ("pin_sw", "status", "reader", "words"),
    [
        ("63C6", PIV_STATUS_CONTACT, CONTACT_READER, "6 tries left"),
        ("63C0", PIV_STATUS_CONTACT, CONTACT_READER, "no retry limit"),
        ("6983", PIV_STATUS_CONTACT, CONTACT_READER, "blocked"),
        (
            "6983",
            PIV_STATUS_CONTACTLESS,
            PICC_READER,
            "no tries left over this interface (contact tries may remain)",
        ),
    ],
)
def test_the_status_commands_word_a_verdict_alike(
    monkeypatch, mock_connection, pin_sw, status, reader, words
):
    probes = {PROBE_PIN: f"|{pin_sw}", PROBE_PUK: "|63C6"}
    _card(mock_connection, probes, status, reader, monkeypatch)
    assert f"PIN (80): {words}" in run(["piv", "pin", "status"]).output
    assert f"PIN (80): set, {words}" in run(["piv", "status"]).output
    assert f", PIN {words}" in " ".join(run(["info"]).output.split())


def test_pin_verify_6983_over_contactless_names_the_limit(monkeypatch, mock_connection):
    _card(mock_connection, {VERIFY: "|6983"}, PIV_STATUS_CONTACTLESS, PICC_READER, monkeypatch)
    as_json, human = run_both_modes(["piv", "pin", "verify", "--pin", "123456"])
    assert as_json.exit_code == 6
    payload = json.loads(as_json.stdout)
    assert payload["message"] == "No PIN tries left over this interface."
    assert "contact tries may remain" in payload["hint"]
    assert "blocked" not in payload
    assert "Authentication method blocked" not in human.output


def test_pin_verify_6983_over_contact_is_blocked_with_the_recovery(monkeypatch, mock_connection):
    _card(mock_connection, {VERIFY: "|6983"}, PIV_STATUS_CONTACT, CONTACT_READER, monkeypatch)
    as_json, human = run_both_modes(["piv", "pin", "verify", "--pin", "123456"])
    payload = json.loads(as_json.stdout)
    assert payload["blocked"] is True and "piv pin unblock" in payload["recovery"]
    assert "piv pin unblock" in human.output


def test_pin_unblock_6a81_over_contactless_names_the_interface(monkeypatch, mock_connection):
    _card(mock_connection, {UNBLOCK: "|6A81"}, PIV_STATUS_CONTACTLESS, PICC_READER, monkeypatch)
    as_json, human = run_both_modes(
        ["piv", "pin", "unblock", "--puk", "12345678", "--new-pin", "654321"]
    )
    assert as_json.exit_code == 6
    message = json.loads(as_json.stdout)["message"]
    assert "refuses the PUK over this interface" in message
    assert "Function not supported" not in human.output


def test_pin_change_6982_names_the_interface_not_the_admin_key(monkeypatch, mock_connection):
    _card(mock_connection, {CHANGE_PIN: "|6982"}, PIV_STATUS_CONTACTLESS, PICC_READER, monkeypatch)
    as_json, human = run_both_modes(
        ["piv", "pin", "change", "--old-pin", "123456", "--new-pin", "654321"]
    )
    assert "contact reader" in json.loads(as_json.stdout)["message"]
    assert "admin key" not in human.output


def test_objects_read_6983_over_contactless_keeps_exit_1(monkeypatch, mock_connection):
    _card(mock_connection, {VERIFY: "|6983"}, PIV_STATUS_CONTACTLESS, PICC_READER, monkeypatch)
    args = ["piv", "objects", "read", "--object", "printed"]
    for result in run_both_modes(args, env={"CRYPTNOX_PIV_PIN": "123456"}):
        assert result.exit_code == 1, result.output
        assert "No PIN tries left over this interface" in result.output


# --------------------------------------------------------- quickstart pre-flight #
def _facts():
    from test_quickstart import _facts as facts

    return facts(pin_configured=True)


@pytest.mark.parametrize(
    ("status", "reader", "words"),
    [
        (PIV_STATUS_CONTACTLESS, PICC_READER, "No PIN tries left over this interface"),
        (
            PIV_STATUS_CONTACT,
            CONTACT_READER,
            "The PIN is blocked. Recover it with `piv pin unblock`",
        ),
    ],
)
def test_quickstart_pre_flight_names_the_cause(monkeypatch, mock_connection, status, reader, words):
    exchanges = {VERIFY: "|6983", PIV_GET_STATUS: f"{status}|9000"}
    session = CardSession(mock_connection("3B00", exchanges, []), reader_name=reader)

    @contextlib.contextmanager
    def open_session(self):
        yield session

    monkeypatch.setattr(AppContext, "open_session", open_session)
    monkeypatch.setattr(piv_cmd, "_collect_quickstart_facts", lambda s, ref, mech: (_facts(), "x"))
    monkeypatch.setattr(piv_cmd, "_select", PivApplet)
    monkeypatch.setattr(
        piv_cmd,
        "_set_verifier",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("write reached the card")),
    )
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    result = CliRunner().invoke(
        piv_cmd.command, ["quickstart", "--default-keys"], obj=AppContext(json=True, yes=True)
    )
    assert result.exit_code != 0
    assert getattr(result.exception, "exit_code", None) == 6
    assert "VERIFY PIN (quickstart pre-flight)" in str(result.exception)
    assert words in str(result.exception)
    assert "Authentication method blocked" not in str(result.exception)


# ------------------------------------------------------------ values that do not fit #
class _Untouched:
    def __init__(self):
        self.sent: list[bytes] = []

    def transmit(self, apdu):
        self.sent.append(bytes(apdu))
        return [], 0x90, 0x00

    def get_atr(self):
        return b"\x3b\x00"

    def disconnect(self):
        pass


@pytest.mark.parametrize(
    "args",
    [
        ["piv", "pin", "verify", "--pin", "123456789"],
        ["piv", "pin", "change", "--old-pin", "123456", "--new-pin", "123456789"],
        ["piv", "pin", "unblock", "--puk", "123", "--new-pin", "654321"],
        ["piv", "puk", "change", "--old-puk", "12345678", "--new-puk", "123456789"],
        ["piv", "perso", "set-pin", "--pin", "123456789", "--default-keys"],
        ["piv", "perso", "set-puk", "--puk", "123", "--default-keys"],
        ["piv", "perso", "smoke-test", "--pin", "123"],
    ],
    ids=["verify", "pin-change", "pin-unblock", "puk-change", "set-pin", "set-puk", "smoke"],
)
def test_a_value_that_does_not_fit_exits_2_and_sends_nothing(monkeypatch, args):
    conn = _Untouched()
    wire_session(monkeypatch, conn)
    result = run(["--json", *args])
    assert result.exit_code == 2, result.output
    assert conn.sent == []
    error = json.loads(result.stdout)
    assert error["error"] == "invalid_input" and "4 to 8" in error["message"]


@pytest.mark.parametrize(
    "args",
    [["piv", "objects", "read", "--object", "printed"], ["piv", "perso", "smoke-test"]],
    ids=["objects-read", "smoke-test"],
)
def test_a_pin_from_the_environment_that_does_not_fit_opens_no_session(monkeypatch, args):
    conn = _Untouched()
    wire_session(monkeypatch, conn)
    result = run(args, env={"CRYPTNOX_PIV_PIN": "123456789"})
    assert result.exit_code == 2, result.output
    assert "4 to 8" in result.output
    assert conn.sent == []


def test_an_empty_pin_is_refused_before_the_card(monkeypatch):
    conn = _Untouched()
    wire_session(monkeypatch, conn)
    result = run(["piv", "pin", "verify"], env={"CRYPTNOX_PIV_PIN": ""})
    assert result.exit_code == 2, result.output
    assert conn.sent == []


def test_the_status_commands_name_an_answer_the_rules_do_not_read(monkeypatch, mock_connection):
    probes = {PROBE_PIN: "|6F00", PROBE_PUK: "|63C6"}
    _card(mock_connection, probes, PIV_STATUS_CONTACT, CONTACT_READER, monkeypatch)
    text = "PIN (80): Unknown card error (no precise diagnosis) (SW=6F00)"
    assert text in run(["piv", "pin", "status"]).output
    assert text in run(["piv", "status"]).output


@pytest.mark.parametrize(
    ("verdict", "default", "style"),
    [
        (Verdict.NO_TRIES_ON_INTERFACE, None, "yellow"),
        (Verdict.NO_TRIES_ON_INTERFACE, "green", "yellow"),
        (Verdict.BLOCKED, None, "red"),
        (Verdict.TRIES_LEFT, None, None),
        (Verdict.TRIES_LEFT, "green", "green"),
    ],
)
def test_the_status_commands_colour_a_verdict_alike(verdict, default, style):
    outcome = Outcome(Op.STATUS, PIN, 0x63C2, verdict, tries=2)
    text = outcome.status_text
    expected = f"[{style}]{text}[/{style}]" if style else text
    assert piv_cmd._styled_status(outcome, default) == expected


def test_a_secret_without_a_new_value_variable_has_no_new_input():
    with pytest.raises(ValueError):
        _ = piv_cmd._PIN_INPUT.new.new


# ---------------------------------------------------------- validate, unread verifier #
@pytest.mark.parametrize(
    ("puk", "deny", "detail"),
    [
        ("|6F00", [], "Unknown card error (no precise diagnosis) (SW=6F00)"),
        (None, [PROBE_PUK], "not readable"),
    ],
    ids=["unknown-answer", "probe-failed"],
)
def test_validate_marks_a_verifier_the_probe_left_unknown(
    monkeypatch, mock_connection, puk, deny, detail
):
    exchanges = {SELECT_PIV: f"{APT}|9000", PROBE_PIN: "|63C3"}
    if puk:
        exchanges[PROBE_PUK] = puk
    conn = mock_connection("3B00", exchanges, deny)
    wire_session(monkeypatch, conn, reader_name=CONTACT_READER)
    checks = {
        c["check"]: c for c in json.loads(run(["--json", "piv", "validate"]).stdout)["checks"]
    }
    assert checks["PUK configured"] == {
        "check": "PUK configured",
        "ok": False,
        "detail": detail,
        "unknown": True,
    }
    assert checks["PIN configured"] == {"check": "PIN configured", "ok": True, "detail": ""}


@pytest.mark.parametrize(
    ("status", "reader", "said", "unsaid"),
    [
        (PIV_STATUS_CONTACT, CONTACT_READER, "over the contact interface too", "contact reader"),
        (PIV_STATUS_CONTACTLESS, PICC_READER, "Use a contact reader", "contact interface too"),
    ],
    ids=["contact", "contactless"],
)
def test_validate_words_a_refused_verifier_for_its_interface(
    monkeypatch, mock_connection, status, reader, said, unsaid
):
    probes = {PROBE_PIN: "|6982", PROBE_PUK: "|6982"}
    _card(mock_connection, probes, status, reader, monkeypatch)
    checks = json.loads(run(["--json", "piv", "validate"]).stdout)["checks"]
    pin = next(c for c in checks if c["check"] == "PIN configured")
    assert pin["ok"] is False and pin["unknown"] is True
    assert said in pin["detail"] and unsaid not in pin["detail"]


def test_validate_without_a_detected_applet_reports_the_verifiers_absent(
    monkeypatch, mock_connection
):
    conn = mock_connection("3B00", {SELECT_PIV: f"{APT}|9000"}, [])
    answer, selects = conn.transmit, []

    def transmit(apdu):
        if bytes(apdu).hex().upper() == SELECT_PIV and not selects:
            selects.append(apdu)
            return [], 0x6F, 0x00
        return answer(apdu)

    conn.transmit = transmit
    wire_session(monkeypatch, conn, reader_name=CONTACT_READER)
    checks = {
        c["check"]: c for c in json.loads(run(["--json", "piv", "validate"]).stdout)["checks"]
    }
    for label in ("PIN configured", "PUK configured"):
        assert checks[label] == {"check": label, "ok": False, "detail": ""}
