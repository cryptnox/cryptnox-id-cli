"""``remote ping``: what the service runs and offers. No socket, and no card at all."""

import contextlib
import json

import pytest
from click.testing import CliRunner

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import relay
from cryptnox_id_cli.transport.errors import RemoteOperationError, RemoteProtocolError

PONG = {
    "type": "result",
    "ok": True,
    "op": "ping",
    "ops": [
        "attest",
        "authenticate",
        "dev-reset",
        "fuse",
        "gptest",
        "inspect",
        "provision",
        "reset",
    ],
    "token_valid": None,
    "token_label": None,
    "server_time": 1794413946,
    "build": {"commit": "c434903e63e7", "released": "2026-11-11T11:50:09Z", "lib": "0.3.0"},
    "scp": {
        "policy": "auto",
        "legacy_attest": "refuse",
        "legacy_requires_token": True,
        "refuse_contactless_admin": True,
        "levels": {"SCP03": "0x33 (C-MAC+C-ENC+R-MAC+R-ENC)"},
    },
    "piv_variants": {
        "default": "fips",
        "enabled": ["fips", "fipsoff"],
        "deployed": {"fips": True, "fipsoff": True},
    },
}


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
def service(monkeypatch):
    """A scripted service, and a reader that must never be opened."""

    def boom(*a, **k):
        raise AssertionError("remote ping must not open the reader")

    monkeypatch.setattr(AppContext, "open_session", boom)
    monkeypatch.delenv(rchannel.URL_ENV, raising=False)
    holder: dict = {}

    @contextlib.contextmanager
    def fake_open(url, **kwargs):
        holder["url"] = url
        yield holder["channel"]

    monkeypatch.setattr(rchannel, "open_channel", fake_open)

    def arm(script):
        holder["channel"] = ScriptedChannel(script)
        return holder["channel"]

    holder["arm"] = arm
    return holder


def run(args, **kwargs):
    return CliRunner().invoke(root, args, **kwargs)


# --------------------------------------------------------------------------- #
# The exchange                                                                #
# --------------------------------------------------------------------------- #
def test_ping_sends_one_hello_and_returns_the_answer():
    channel = ScriptedChannel([{"type": "log", "msg": "hi"}, PONG])
    answer = relay.ping(channel)
    assert channel.sent == [{"type": "hello", "op": "ping", "params": {}}]
    assert answer["build"]["commit"] == "c434903e63e7"


def test_ping_answers_a_proof_of_work_if_the_service_ever_asks():
    channel = ScriptedChannel(
        [{"type": "pow_challenge", "challenge": "0011223344556677", "bits": 4}, PONG]
    )
    relay.ping(channel)
    assert [f["type"] for f in channel.sent] == ["hello", "pow"]


@pytest.mark.parametrize("frame", [{"type": "apdu", "hex": "80CA9F7F00"}, {"type": "atr"}])
def test_a_frame_that_asks_for_the_card_is_a_protocol_violation(frame):
    with pytest.raises(RemoteProtocolError, match="asked for the card during a ping"):
        relay.ping(ScriptedChannel([frame]))


def test_a_refused_ping_is_a_classified_failure():
    with pytest.raises(RemoteOperationError) as info:
        relay.ping(ScriptedChannel([{"type": "result", "ok": False, "error": "unknown op 'ping'"}]))
    assert info.value.reason == "unsupported_operation"


# --------------------------------------------------------------------------- #
# The command                                                                 #
# --------------------------------------------------------------------------- #
def test_ping_json_separates_what_this_tool_runs_from_what_it_does_not(service):
    service["arm"]([PONG])
    result = run(["--json", "remote", "ping"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["op"] == "ping"
    assert payload["endpoint"] == rchannel.PRODUCTION_URL
    assert payload["operations_available"] == [
        "authenticate",
        "inspect",
        "attest",
        "reset",
        "dev-reset",
    ]
    assert payload["operations_not_in_this_client"] == ["fuse", "gptest", "provision"]
    assert payload["service"]["build"]["commit"] == "c434903e63e7"
    assert payload["service"]["piv_variants"]["enabled"] == ["fips", "fipsoff"]
    assert isinstance(payload["clock_skew_seconds"], int)
    # Factory-tooling fields are not this tool's business.
    assert "token_label" not in payload["service"]
    assert "token_valid" not in payload["service"]


def test_ping_human_output(service):
    service["arm"]([PONG])
    result = run(["remote", "ping"])
    assert result.exit_code == 0, result.output
    text = " ".join(result.output.split())
    assert "Service build: c434903e63e7, released 2026-11-11T11:50:09Z (card library 0.3.0)" in text
    assert "Operations: authenticate, inspect, attest, reset, dev-reset" in text
    assert "offered, not run by this tool: fuse, gptest, provision" in text
    assert "PIV applet builds: fips (default), fipsoff" in text
    assert "contactless interface: refused" in text


def test_ping_with_an_older_service_that_reports_little(service):
    service["arm"]([{"type": "result", "ok": True, "op": "ping", "ops": ["inspect"]}])
    result = run(["remote", "ping"])
    assert result.exit_code == 0, result.output
    text = " ".join(result.output.split())
    assert "Service build: not reported" in text
    assert "PIV applet builds: not reported (the FIPS-mode build only)" in text


def test_ping_marks_a_build_the_service_lists_but_does_not_hold(service):
    pong = dict(
        PONG,
        piv_variants={
            "default": "fips",
            "enabled": ["fips", "fipsoff"],
            "deployed": {"fips": True, "fipsoff": False},
        },
    )
    service["arm"]([pong])
    text = " ".join(run(["remote", "ping"]).output.split())
    assert "fipsoff (not installed on the service)" in text


def test_ping_text_from_the_service_is_sanitised(service):
    pong = dict(PONG, build={"commit": "abc\x1b[31mdef\x07", "released": "x" * 400})
    service["arm"]([pong])
    payload = json.loads(run(["--json", "remote", "ping"]).stdout)
    assert payload["service"]["build"]["commit"] == "abcdef"
    assert len(payload["service"]["build"]["released"]) < 230


def test_ping_follows_the_endpoint_override_and_says_so(service, monkeypatch):
    monkeypatch.setenv(rchannel.URL_ENV, "ws://localhost:9999")
    service["arm"]([PONG])
    result = run(["remote", "ping"])
    assert result.exit_code == 0, result.output
    assert service["url"] == "ws://localhost:9999"
    assert "non-production endpoint" in result.output


def test_ping_runs_under_dry_run_because_it_touches_no_card(service):
    service["arm"]([PONG])
    result = run(["--dry-run", "--json", "remote", "ping"])
    assert result.exit_code == 0, result.output


def test_a_refused_ping_exits_16_with_its_reason(service):
    service["arm"](
        [
            {
                "type": "result",
                "ok": False,
                "error": "rate limited (source 203.0.113.9); retry in 42s",
            }
        ]
    )
    result = run(["--json", "remote", "ping"])
    assert result.exit_code == 16
    error = json.loads(result.stdout)
    assert error["reason"] == "rate_limited_source"
    assert error["retry_in_seconds"] == 42
