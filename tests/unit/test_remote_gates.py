# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Consent gates for ``remote reset`` and ``remote dev-reset``. No socket, no card."""

import contextlib
import json
import sys

import pytest
from _cardfakes import wire_session
from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import remote as remote_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.remote import channel as rchannel

ATR = "3BFA1300FF910131FE000031C173C84000009000D2"
SELECT_ISD = "00A4040008A00000015100000000"
SELECT_SSD = "00A4040009A0000001515350410100"
SELECT_PIV = "00A404000BA00000030800001000010000"
CPLC_CMD = "80CA9F7F00"
CPLC_RESP = (
    "9F7F2A4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
)
KEY_INFO = "80CA00E000"
KEY_INFO_ONE = "E012C00401018010C00402018010C00403018010"
KEY_INFO_TWO = "E018C00401018010C00402018010C00403018010C00401028810"
APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
    "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
    "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
GET_VERSION = "00CB3F00055C032F475600"
GET_STATUS = "00CB3F00055C032F475300"
# OpenFIPS201-P71D600-FIPS 2.0.0 with the FIPS flag on: the build cards ship with.
VERSION_FIPS = "532680184F70656E464950533230312D503731443630302D46495053810102820100830100840100"
STATUS_FIPS = "53188001078101008201008301008401008501008601008701FF"
IRREVERSIBLE = "--i-understand-this-is-irreversible"


class _FakeSys:
    """The real ``sys``, but ``stdin.isatty()`` reports a terminal."""

    class _Stdin:
        def isatty(self):
            return True

        def __getattr__(self, name):
            return getattr(sys.stdin, name)

    stdin = _Stdin()

    def __getattr__(self, name):
        return getattr(sys, name)


class ScriptedChannel:
    def __init__(self, script):
        self.script = list(script)
        self.sent: list[dict] = []

    def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    def recv(self, timeout=None) -> str:
        return json.dumps(self.script.pop(0))

    def close(self) -> None:
        pass


@pytest.fixture
def wired(monkeypatch, mock_connection):
    """A pre-personalized FIPS-mode card, security domain on key version 1, scripted service."""
    conn = mock_connection(
        ATR,
        {
            SELECT_ISD: "6F108408A000000151000000A5049F6501FF|9000",
            SELECT_SSD: "6F118409A00000015153504101A5049F6501FF|9000",
            SELECT_PIV: f"{APT}|9000",
            GET_VERSION: f"{VERSION_FIPS}|9000",
            GET_STATUS: f"{STATUS_FIPS}|9000",
            "00A4040000": "|9000",
            CPLC_CMD: f"{CPLC_RESP}|9000",
            KEY_INFO: f"{KEY_INFO_ONE}|9000",
        },
        [],
    )
    wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
    monkeypatch.delenv(rchannel.URL_ENV, raising=False)
    holder: dict = {"conn": conn, "opened": 0}

    @contextlib.contextmanager
    def fake_open(url, **kwargs):
        holder["opened"] += 1
        yield holder["channel"]

    monkeypatch.setattr(rchannel, "open_channel", fake_open)

    def arm(script):
        holder["channel"] = ScriptedChannel(script)
        return holder["channel"]

    holder["arm"] = arm
    return holder


def run(args, **kwargs):
    return CliRunner().invoke(root, args, **kwargs)


OK_RESULT = {"type": "result", "ok": True, "wiped_and_reprovisioned": True, "steps": []}


# --------------------------------------------------------------------------- #
# Fail closed                                                                 #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("op", ["reset", "dev-reset"])
def test_non_interactive_without_the_flag_refuses_before_connecting(wired, op):
    wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", op])
    assert result.exit_code == 1
    assert "needs --i-understand-this-is-irreversible" in json.loads(result.stdout)["message"]
    assert wired["opened"] == 0


@pytest.mark.parametrize("op", ["reset", "dev-reset"])
def test_yes_is_not_a_bypass(wired, op):
    wired["arm"]([OK_RESULT])
    result = run(["--yes", "--json", "remote", op])
    assert result.exit_code == 1
    assert wired["opened"] == 0


def test_wrong_phrase_aborts(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "sys", _FakeSys())
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset"], input="reset-piv\n")
    assert result.exit_code != 0
    assert wired["opened"] == 0
    assert "Before" in result.output  # the inventory was shown before asking


def test_right_phrase_proceeds(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "sys", _FakeSys())
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset"], input="RESET-PIV\n")
    assert result.exit_code == 0, result.output
    assert wired["opened"] == 1
    assert "After" in result.output


def test_dry_run_refuses_before_anything_opens(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("reader must not be opened under --dry-run")

    monkeypatch.setattr(AppContext, "open_session", boom)
    for op in ("reset", "dev-reset"):
        result = run(["--dry-run", "remote", op, "--i-understand-this-is-irreversible"])
        assert result.exit_code != 0
        assert "nothing was sent to the card" in result.output


@pytest.mark.parametrize("op", ["reset", "dev-reset"])
def test_endpoint_override_is_refused(wired, op, monkeypatch):
    monkeypatch.setenv(rchannel.URL_ENV, "ws://localhost:9999")
    result = run(["--json", "remote", op, "--i-understand-this-is-irreversible"])
    assert result.exit_code == 13
    assert "production service" in json.loads(result.stdout)["message"]


# --------------------------------------------------------------------------- #
# The flagged path                                                            #
# --------------------------------------------------------------------------- #
def test_reset_payload_carries_before_after_and_params(wired):
    channel = wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", "reset", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    # The derived key and the FIPS-mode build are the defaults, and both are sent
    # explicitly so the outcome never depends on the service's own defaults.
    assert channel.sent[0] == {
        "type": "hello",
        "op": "reset",
        "params": {"fused": True, "piv_variant": "fips"},
    }
    assert payload["piv_variant"] == "fips"
    assert payload["before"]["piv_ssd_key_versions"] == [1]
    assert payload["before"]["piv_state"] == "PivPrePersonalized"
    assert payload["after"]["piv_ssd_key_versions"] == [1]
    assert payload["verified_locally"]["piv_ssd_present_after"] is True
    assert payload["verified_locally"]["piv_present_after"] is True
    assert payload["result"]["wiped_and_reprovisioned"] is True


def test_reset_default_keys_warns_that_the_service_refuses_it(wired):
    channel = wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", "--default-keys", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 0, result.output
    assert channel.sent[0]["params"] == {"fused": False, "piv_variant": "fips"}
    assert "factory token" in result.output


def test_dev_reset_default_keys_selects_the_ssd_proof(wired):
    channel = wired["arm"]([OK_RESULT])
    result = run(["remote", "dev-reset", "--default-keys", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 0, result.output
    assert channel.sent[0]["params"] == {"fused": False, "piv_variant": "fips"}
    assert "factory token" not in result.output


def test_default_keys_help_differs_per_operation():
    reset_help = " ".join(run(["remote", "reset", "--help"]).output.split())
    dev_reset_help = " ".join(run(["remote", "dev-reset", "--help"]).output.split())
    assert "factory token" in reset_help
    assert "key version 2" in dev_reset_help
    assert "retry" not in reset_help + dev_reset_help


def test_fused_flag_no_longer_exists(wired):
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", "--fused", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 2  # click usage error


def test_dev_reset_needs_no_token_and_sends_none(wired, monkeypatch):
    monkeypatch.setenv("CRYPTNOX_REMOTE_DEV_TOKEN", "left-over-value")
    channel = wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", "dev-reset", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 0, result.output
    assert channel.sent[0]["params"] == {"fused": True, "piv_variant": "fips"}


def test_dev_reset_help_mentions_no_token():
    result = run(["remote", "dev-reset", "--help"])
    assert "--dev-token" not in result.output
    assert "CRYPTNOX_REMOTE_DEV_TOKEN" not in result.output


def test_after_inventory_reflects_a_new_key_version(wired):
    # The service loads key version 2 into the security domain; the local
    # read afterwards must show it.
    conn = wired["conn"]
    channel = wired["arm"]([OK_RESULT])
    original = conn.transmit

    def evolving(apdu):
        data, sw1, sw2 = original(apdu)
        if bytes(apdu).hex().upper() == KEY_INFO and channel.sent:
            return list(bytes.fromhex(KEY_INFO_TWO)), 0x90, 0x00
        return data, sw1, sw2

    conn.transmit = evolving
    result = run(["--json", "remote", "reset", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["before"]["piv_ssd_key_versions"] == [1]
    assert payload["after"]["piv_ssd_key_versions"] == [1, 2]


def test_service_failure_still_releases_the_card(wired, monkeypatch):
    released = []
    conn = wired["conn"]
    monkeypatch.setattr(conn, "disconnect", lambda: released.append(True))
    wired["arm"]([{"type": "result", "ok": False, "error": "isd auth failed"}])
    result = run(["--json", "remote", "reset", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 16
    assert released == [True]


# --------------------------------------------------------------------------- #
# The key-free security domain probe                                          #
# --------------------------------------------------------------------------- #
def test_ssd_key_versions_absent_and_present(wired, mock_connection):
    from cryptnox_id_cli.transport.pcsc import CardSession

    absent = mock_connection(ATR, {SELECT_SSD: "|6A82"}, [])
    assert remote_cmd._ssd_key_versions(CardSession(absent)) is None
    assert remote_cmd._ssd_key_versions(CardSession(wired["conn"])) == [1]
    two = mock_connection(ATR, {SELECT_SSD: "6F11|9000", KEY_INFO: f"{KEY_INFO_TWO}|9000"}, [])
    assert remote_cmd._ssd_key_versions(CardSession(two)) == [1, 2]


# --------------------------------------------------------------------------- #
# What the service says about the channel it used, and the applet's NFC lock  #
# --------------------------------------------------------------------------- #
def test_channel_is_shown_and_a_legacy_level_on_scp03_is_warned_about(wired):
    chan = {"scp": "SCP03", "level": "0x03", "mode": "legacy", "responses_authenticated": False}
    wired["arm"]([{**OK_RESULT, "channel": chan}])
    result = run(["--json", "remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 0, result.output
    assert "drove this SCP03 card at the legacy channel level" in result.stderr
    assert json.loads(result.stdout)["result"]["channel"] == chan
    wired["arm"]([{**OK_RESULT, "channel": chan}])
    result = run(["remote", "reset", IRREVERSIBLE])
    assert (
        "Admin channel: SCP03 level 0x03, legacy (the card's answers are not authenticated)"
        in result.output
    )
    assert "channel: {" not in result.output


def test_a_hardened_channel_is_shown_without_a_warning(wired):
    chan = {"scp": "SCP03", "level": "0x33", "mode": "hardened", "responses_authenticated": True}
    wired["arm"]([{**OK_RESULT, "channel": chan}])
    result = run(["remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 0, result.output
    assert "Admin channel: SCP03 level 0x33, hardened" in result.output
    assert "legacy channel level" not in result.output


def test_a_result_without_a_channel_is_shown_as_not_reported(wired):
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 0, result.output
    assert "Admin channel: not reported by the service (treated as legacy)" in result.output


def test_nfc_admin_lock_set_is_shown(wired):
    lock = {"restrict_contactless_admin": True, "sw": "9000"}
    wired["arm"]([{**OK_RESULT, "nfc_admin_lock": lock}])
    result = run(["remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 0, result.output
    assert "Contactless administration: refused by the applet from now on" in result.output
    assert "could not set" not in result.output
    assert "nfc_admin_lock: {" not in result.output


def test_nfc_admin_lock_not_set_is_warned_about_and_sanitised(wired):
    lock = {"restrict_contactless_admin": False, "error": "SW 6985 \x1b[31m[red]x"}
    wired["arm"]([{**OK_RESULT, "nfc_admin_lock": lock}])
    result = run(["remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 0, result.output
    assert "could not set the applet's contactless-administration lock" in result.output
    assert "lock NOT set (SW 6985 [red]x)" in result.output
    assert "\x1b" not in result.output


def test_contactless_reader_is_warned_about_before_consent(wired, monkeypatch):
    wire_session(monkeypatch, wired["conn"], reader_name="ACS ACR1552 1S CL Reader PICC 0")
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 0, result.output
    before = result.output.split("Before")[0]
    assert "looks like a contactless reader" in before
    assert "refuses" not in before  # the gate covers attest; reset runs through the card manager


def test_contact_reader_gets_no_contactless_warning(wired):
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 0, result.output
    assert "contactless reader" not in result.output


# --------------------------------------------------------------------------- #
# A failed local check is an exit code, not only a red line                   #
# --------------------------------------------------------------------------- #
def test_a_failed_local_check_exits_17_after_the_result(wired):
    wired["arm"]([{**OK_RESULT, "cplc_uid": "0000000000000000"}])
    result = run(["--json", "remote", "reset", IRREVERSIBLE])
    assert result.exit_code == 17
    payload = json.loads(result.stdout)  # the result object, not an error object
    assert payload["verified_locally"]["cplc_uid_matches"] is False
    assert "local verification failed: cplc_uid_matches" in result.stderr
