"""Consent gates for ``remote reset`` and ``remote dev-reset``. No socket, no card."""

import contextlib
import json
import sys

import pytest
from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import remote as remote_cmd
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
    """A blank-PIV card with a security domain on key version 1, and a scripted service."""
    conn = mock_connection(
        ATR,
        {
            SELECT_ISD: "6F108408A000000151000000A5049F6501FF|9000",
            SELECT_SSD: "6F118409A00000015153504101A5049F6501FF|9000",
            SELECT_PIV: "|6A82",
            "00A4040000": "|9000",
            CPLC_CMD: f"{CPLC_RESP}|9000",
            KEY_INFO: f"{KEY_INFO_ONE}|9000",
        },
        [],
    )
    monkeypatch.setattr(remote_cmd, "pick_reader", lambda pref: "Fake Reader 00 00")
    monkeypatch.setattr(remote_cmd, "connect", lambda name: conn)
    monkeypatch.delenv(rchannel.URL_ENV, raising=False)
    monkeypatch.delenv(remote_cmd.DEV_ACCESS_ENV, raising=False)
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
def test_non_interactive_without_the_flag_refuses_before_connecting(wired, op, monkeypatch):
    monkeypatch.setenv(remote_cmd.DEV_ACCESS_ENV, "dev-credential")
    wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", op])
    assert result.exit_code == 1
    assert "needs --i-understand-this-is-irreversible" in json.loads(result.stdout)["message"]
    assert wired["opened"] == 0


@pytest.mark.parametrize("op", ["reset", "dev-reset"])
def test_yes_is_not_a_bypass(wired, op, monkeypatch):
    monkeypatch.setenv(remote_cmd.DEV_ACCESS_ENV, "dev-credential")
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

    monkeypatch.setattr(remote_cmd, "pick_reader", boom)
    for op in ("reset", "dev-reset"):
        result = run(["--dry-run", "remote", op, "--i-understand-this-is-irreversible"])
        assert result.exit_code != 0
        assert "nothing was sent to the card" in result.output


@pytest.mark.parametrize("op", ["reset", "dev-reset"])
def test_endpoint_override_is_refused(wired, op, monkeypatch):
    monkeypatch.setenv(rchannel.URL_ENV, "ws://localhost:9999")
    monkeypatch.setenv(remote_cmd.DEV_ACCESS_ENV, "dev-credential")
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
    # The derived key is the default; only --default-keys turns it off.
    assert channel.sent[0] == {"type": "hello", "op": "reset", "params": {"fused": True}}
    assert payload["before"]["piv_ssd_key_versions"] == [1]
    assert payload["before"]["piv_state"] == "PivNotPresent"
    assert payload["after"]["piv_ssd_key_versions"] == [1]
    assert payload["verified_locally"]["piv_ssd_present_after"] is True
    assert payload["verified_locally"]["piv_present_after"] is False
    assert payload["result"]["wiped_and_reprovisioned"] is True


def test_default_keys_selects_the_dev_path_and_warns(wired):
    channel = wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", "--default-keys", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 0, result.output
    assert channel.sent[0]["params"] == {"fused": False}
    assert "--default-keys" in result.output


def test_fused_flag_no_longer_exists(wired):
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", "--fused", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 2  # click usage error


def test_dev_reset_sends_the_credential_from_the_environment_only(wired, monkeypatch):
    monkeypatch.setenv(remote_cmd.DEV_ACCESS_ENV, "dev-credential-value")
    channel = wired["arm"]([OK_RESULT])
    result = run(
        ["--json", "remote", "dev-reset", "--i-understand-this-is-irreversible"],
    )
    assert result.exit_code == 0, result.output
    assert channel.sent[0]["params"] == {"fused": True, "dev_token": "dev-credential-value"}
    assert "dev-credential-value" not in result.output


def test_dev_reset_without_the_credential_fails_closed(wired):
    wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", "dev-reset", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 3  # secret_input
    assert wired["opened"] == 0


def test_dev_reset_has_no_credential_option():
    result = run(["remote", "dev-reset", "--help"])
    assert "--dev-token" not in result.output
    assert "CRYPTNOX_REMOTE_DEV_TOKEN" in result.output


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
