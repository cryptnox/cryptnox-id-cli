"""The ``remote`` command group: wiring, output shape, gates. No socket, no card."""

import contextlib
import json

import pytest
from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import remote as remote_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.remote import channel as rchannel

ATR = "3BFA1300FF910131FE000031C173C84000009000D2"
CPLC_CMD = "80CA9F7F00"
CPLC_RESP = (
    "9F7F2A4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
)
SELECT_ISD = "00A4040008A00000015100000000"
SELECT_WALLET = "00A4040007A000001000011200"


class ScriptedChannel:
    def __init__(self, script):
        self.script = list(script)
        self.sent: list[dict] = []
        self.closed = False

    def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    def recv(self, timeout=None) -> str:
        return json.dumps(self.script.pop(0))

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def wired(monkeypatch, mock_connection):
    """Patch the reader, the card and the channel; return the scripted channel."""
    conn = mock_connection(
        ATR,
        {SELECT_ISD: "6F108408A000000151000000A5049F6501FF|9000", CPLC_CMD: f"{CPLC_RESP}|9000"},
        [],
    )
    monkeypatch.setattr(remote_cmd, "pick_reader", lambda pref: "Fake Reader 00 00")
    monkeypatch.setattr(remote_cmd, "connect", lambda name: conn)
    holder: dict = {}

    @contextlib.contextmanager
    def fake_open(url, **kwargs):
        holder["url"] = url
        yield holder["channel"]

    monkeypatch.setattr(rchannel, "open_channel", fake_open)
    monkeypatch.delenv(rchannel.URL_ENV, raising=False)

    def arm(script):
        holder["channel"] = ScriptedChannel(script)
        return holder["channel"]

    holder["arm"] = arm
    return holder


def run(args, **kwargs):
    return CliRunner().invoke(root, args, **kwargs)


# --------------------------------------------------------------------------- #
# Wiring                                                                      #
# --------------------------------------------------------------------------- #
def test_group_is_registered_with_both_read_only_commands():
    result = run(["remote", "--help"])
    assert result.exit_code == 0
    assert "authenticate" in result.output
    assert "inspect" in result.output


def test_dry_run_refuses_before_anything_opens(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("reader must not be opened under --dry-run")

    monkeypatch.setattr(remote_cmd, "pick_reader", boom)
    result = run(["--dry-run", "remote", "inspect"])
    assert result.exit_code != 0
    assert "nothing was sent to the card" in result.output


# --------------------------------------------------------------------------- #
# A whole operation through the command                                       #
# --------------------------------------------------------------------------- #
def test_authenticate_json_payload(wired):
    channel = wired["arm"](
        [
            {"type": "pow_challenge", "challenge": "0011223344556677", "bits": 4},
            {"type": "atr"},
            {"type": "log", "msg": "hello from the service"},
            {"type": "apdu", "hex": CPLC_CMD},
            {"type": "result", "ok": True, "cplc_uid": "4301012345670042", "atr": ATR},
        ]
    )
    result = run(["--json", "remote", "authenticate"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)

    assert payload["op"] == "authenticate"
    assert payload["endpoint"] == rchannel.PRODUCTION_URL
    assert wired["url"] == rchannel.PRODUCTION_URL
    assert payload["card"]["atr"] == ATR
    assert payload["card"]["cplc_uid"] == "4301012345670042"
    assert payload["card"]["ic_serial"] == "01234567"
    assert payload["result"]["ok"] is True
    assert payload["verified_locally"] == {"cplc_uid_matches": True, "atr_matches": True}
    assert payload["relay"]["apdus_relayed"] == 1
    assert payload["relay"]["pow_bits"] == 4
    assert payload["relay"]["service_log"] == ["hello from the service"]
    assert [f["type"] for f in channel.sent] == ["hello", "pow", "atr_resp", "apdu_resp"]
    assert channel.sent[0]["op"] == "authenticate"


def test_mismatch_between_service_and_card_is_reported_not_hidden(wired):
    wired["arm"]([{"type": "result", "ok": True, "cplc_uid": "0000000000000000"}])
    result = run(["--json", "remote", "authenticate"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["verified_locally"]["cplc_uid_matches"] is False


def test_human_output_separates_asserted_from_verified(wired):
    wired["arm"]([{"type": "result", "ok": True, "piv_ssd": {"present": False}}])
    result = run(["remote", "inspect"])
    assert result.exit_code == 0, result.output
    assert "asserted by the service" in result.output
    assert "Verified locally" in result.output
    assert "piv_ssd" in result.output


# --------------------------------------------------------------------------- #
# Failures map to their exit codes and JSON shapes                            #
# --------------------------------------------------------------------------- #
def test_policy_refusal_exits_15_with_the_header(wired):
    wired["arm"]([{"type": "apdu", "hex": SELECT_WALLET}])
    result = run(["--json", "remote", "inspect"])
    assert result.exit_code == 15
    error = json.loads(result.stdout)
    assert error["error"] == "remote_policy"
    assert error["apdu_header"] == "00A40400"


def test_service_failure_exits_16_with_the_result(wired):
    wired["arm"]([{"type": "result", "ok": False, "error": "rate limit"}])
    result = run(["--json", "remote", "inspect"])
    assert result.exit_code == 16
    error = json.loads(result.stdout)
    assert error["error"] == "remote_failed"
    assert error["result"]["error"] == "rate limit"


def test_protocol_violation_exits_14(wired):
    wired["arm"]([{"type": "nonsense"}])
    result = run(["--json", "remote", "inspect"])
    assert result.exit_code == 14
    assert json.loads(result.stdout)["error"] == "remote_protocol"


def test_card_is_released_even_when_the_operation_fails(wired, monkeypatch):
    released = []
    conn = remote_cmd.connect("x")
    monkeypatch.setattr(conn, "disconnect", lambda: released.append(True))
    wired["arm"]([{"type": "nonsense"}])
    run(["--json", "remote", "inspect"])
    assert released == [True]


# --------------------------------------------------------------------------- #
# Endpoint override                                                           #
# --------------------------------------------------------------------------- #
def test_env_override_redirects_read_only_ops_and_warns(wired, monkeypatch):
    monkeypatch.setenv(rchannel.URL_ENV, "ws://localhost:9999")
    wired["arm"]([{"type": "result", "ok": True}])
    result = run(["remote", "inspect"])
    assert result.exit_code == 0, result.output
    assert wired["url"] == "ws://localhost:9999"
    assert "non-production endpoint" in result.output


def test_env_override_to_a_remote_plain_ws_is_refused(wired, monkeypatch):
    monkeypatch.setenv(rchannel.URL_ENV, "ws://piv.cryptnox.com")
    result = run(["--json", "remote", "inspect"])
    assert result.exit_code == 13
    assert json.loads(result.stdout)["error"] == "remote_connect"


def test_endpoint_helper_refuses_override_for_operations_that_change_the_card(monkeypatch):
    monkeypatch.setenv(rchannel.URL_ENV, "ws://localhost:9999")
    with pytest.raises(Exception, match="runs only against the production service"):
        remote_cmd._endpoint("reset")


# --------------------------------------------------------------------------- #
# Transcript                                                                  #
# --------------------------------------------------------------------------- #
def test_relayed_commands_reach_the_apdu_log(wired, tmp_path):
    log = tmp_path / "apdu.log"
    wired["arm"]([{"type": "apdu", "hex": CPLC_CMD}, {"type": "result", "ok": True}])
    result = run(["--apdu-log", str(log), "remote", "inspect"])
    assert result.exit_code == 0, result.output
    text = log.read_text()
    assert "> " + CPLC_CMD in text
    assert "< " + CPLC_RESP + "9000" in text


def test_app_context_apdu_trace_writes_and_traces(tmp_path):
    app = AppContext(apdu_log_path=str(tmp_path / "t.log"), verbose=False)
    app.apdu_trace("> 00A4040000")
    app.close()
    assert "> 00A4040000" in (tmp_path / "t.log").read_text()
