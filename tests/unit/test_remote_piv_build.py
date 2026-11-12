"""Choosing and checking the PIV applet build through the service. No socket, no card.

The applet answers two vendor reads without authentication: its version (with a
label that names the build) and its status (with the FIPS flag). The vectors
below are the answers of a real card carrying each build.
"""

import contextlib
import json

import pytest
from _cardfakes import wire_session
from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import remote as remote_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.remote import channel as rchannel

ATR = "3BD518FF81B1FE451FC38073C821106F"
SELECT_ISD = "00A4040008A00000015100000000"
SELECT_SSD = "00A4040009A0000001515350410100"
SELECT_PIV = "00A404000BA00000030800001000010000"
CPLC_CMD = "80CA9F7F00"
CPLC_RESP = (
    "9F7F2A4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
)
KEY_INFO = "80CA00E000"
KEY_INFO_TWO = "E018C00401018010C00402018010C00403018010C00401028810"
APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
    "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
    "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
GET_VERSION = "00CB3F00055C032F475600"
GET_STATUS = "00CB3F00055C032F475300"
# OpenFIPS201-P71D600 2.0.0, FIPS flag off / OpenFIPS201-P71D600-FIPS 2.0.0, FIPS flag on.
VERSION_FIPS_OFF = "532180134F70656E464950533230312D50373144363030810102820100830100840100"
STATUS_FIPS_OFF = "5318800107810100820100830100840100850100860100870100"
VERSION_FIPS = "532680184F70656E464950533230312D503731443630302D46495053810102820100830100840100"
STATUS_FIPS = "53188001078101008201008301008401008501008601008701FF"

PONG = {
    "type": "result",
    "ok": True,
    "op": "ping",
    "piv_variants": {
        "default": "fips",
        "enabled": ["fips", "fipsoff"],
        "deployed": {"fips": True, "fipsoff": True},
    },
}
OK_RESULT = {"type": "result", "ok": True, "wiped_and_reprovisioned": True, "steps": []}


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


def card(mock_connection, version, status):
    return mock_connection(
        ATR,
        {
            SELECT_ISD: "6F108408A000000151000000A5049F6501FF|9000",
            SELECT_SSD: "6F118409A00000015153504101A5049F6501FF|9000",
            SELECT_PIV: f"{APT}|9000",
            "00A4040000": "|9000",
            CPLC_CMD: f"{CPLC_RESP}|9000",
            KEY_INFO: f"{KEY_INFO_TWO}|9000",
            GET_VERSION: f"{version}|9000",
            GET_STATUS: f"{status}|9000",
        },
        [],
    )


@pytest.fixture
def wired(monkeypatch, mock_connection):
    """A card carrying the build with FIPS mode off, and a scripted service."""
    conn = card(mock_connection, VERSION_FIPS_OFF, STATUS_FIPS_OFF)
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


FLAG = "--i-understand-this-is-irreversible"


# --------------------------------------------------------------------------- #
# Asking for a build                                                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("op", ["reset", "dev-reset"])
@pytest.mark.parametrize(
    "option",
    [
        ["--fips-off"],
        ["--piv-variant", "fipsoff"],
        ["--piv-variant", "FIPSOFF"],
        ["--fips-off", "--piv-variant", "fipsoff"],
    ],
)
def test_the_build_with_fips_mode_off_is_asked_of_the_service_first_then_requested(
    wired, op, option
):
    channel = wired["arm"]([PONG, OK_RESULT])
    result = run(["--json", "remote", op, *option, FLAG])
    assert result.exit_code == 0, result.output
    assert channel.sent[0] == {"type": "hello", "op": "ping", "params": {}}
    assert channel.sent[1] == {
        "type": "hello",
        "op": op,
        "params": {"fused": True, "piv_variant": "fipsoff"},
    }
    assert wired["opened"] == 2
    assert json.loads(result.stdout)["piv_variant"] == "fipsoff"


def test_the_default_build_needs_no_question_to_the_service(monkeypatch, mock_connection, wired):
    wire_session(monkeypatch, card(mock_connection, VERSION_FIPS, STATUS_FIPS), reader_name="R")
    channel = wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", "reset", "--piv-variant", "fips", FLAG])
    assert result.exit_code == 0, result.output
    assert [f["op"] for f in channel.sent] == ["reset"]
    assert channel.sent[0]["params"] == {"fused": True, "piv_variant": "fips"}


@pytest.mark.parametrize(
    "offer",
    [
        {"default": "fips", "enabled": ["fips"], "deployed": {"fips": True}},
        {
            "default": "fips",
            "enabled": ["fips", "fipsoff"],
            "deployed": {"fips": True, "fipsoff": False},
        },
    ],
)
def test_a_build_the_service_does_not_offer_stops_before_the_reader(wired, monkeypatch, offer):
    def boom(*a, **k):
        raise AssertionError("the reader must not be opened")

    monkeypatch.setattr(AppContext, "open_session", boom)
    channel = wired["arm"]([dict(PONG, piv_variants=offer), OK_RESULT])
    result = run(["--json", "remote", "reset", "--fips-off", FLAG])
    assert result.exit_code == 1
    assert (
        "does not offer the PIV applet build with FIPS mode off"
        in (json.loads(result.stdout)["message"])
    )
    assert [f["op"] for f in channel.sent] == ["ping"]


@pytest.mark.parametrize(
    "answer",
    [
        {"type": "result", "ok": False, "error": "unknown op 'ping'"},  # an older service
        {"type": "result", "ok": True, "op": "ping"},  # one that does not list builds
    ],
)
def test_when_the_service_cannot_say_the_request_goes_ahead(wired, answer):
    channel = wired["arm"]([answer, OK_RESULT])
    result = run(["--json", "remote", "reset", "--fips-off", FLAG])
    assert result.exit_code == 0, result.output
    assert channel.sent[1]["params"]["piv_variant"] == "fipsoff"


def test_the_two_options_must_not_contradict_each_other(wired):
    wired["arm"]([PONG, OK_RESULT])
    result = run(["remote", "reset", "--fips-off", "--piv-variant", "fips", FLAG])
    assert result.exit_code == 2
    assert "contradict" in result.output
    assert wired["opened"] == 0


def test_an_unknown_build_is_a_usage_error(wired):
    result = run(["remote", "reset", "--piv-variant", "bogus", FLAG])
    assert result.exit_code == 2
    assert wired["opened"] == 0


def test_resolution_of_the_two_options():
    assert remote_cmd._resolve_piv_build(None, False) == "fips"
    assert remote_cmd._resolve_piv_build("FIPS", False) == "fips"
    assert remote_cmd._resolve_piv_build(None, True) == "fipsoff"
    assert remote_cmd._resolve_piv_build("fipsoff", False) == "fipsoff"


# --------------------------------------------------------------------------- #
# Asking the applet which build it is                                         #
# --------------------------------------------------------------------------- #
def test_the_applet_is_asked_which_build_it_is_before_and_after(wired):
    wired["arm"]([PONG, dict(OK_RESULT, piv_variant="fipsoff")])
    result = run(["--json", "remote", "reset", "--fips-off", FLAG])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    expected = {"label": "OpenFIPS201-P71D600", "version": "2.0.0", "fips_mode": False}
    assert payload["before"]["piv_build"] == expected
    assert payload["after"]["piv_build"] == expected
    assert payload["verified_locally"]["piv_build_matches"] is True
    assert "does not carry" not in result.stderr


def test_a_card_that_does_not_carry_the_requested_build_is_flagged(wired):
    # The service says the reset went well, yet the applet still reports FIPS mode off.
    wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", "reset", FLAG])
    assert result.exit_code == 17, result.output  # printed, then refused
    payload = json.loads(result.stdout)
    assert payload["piv_variant"] == "fips"
    assert payload["verified_locally"]["piv_build_matches"] is False
    assert "local verification failed: piv_build_matches" in result.stderr
    assert "does not carry the requested PIV applet FIPS-mode build" in result.stderr
    assert "build with FIPS mode off (OpenFIPS201-P71D600 2.0.0)" in result.stderr


def test_the_fips_mode_build_is_recognised(monkeypatch, mock_connection, wired):
    conn = card(mock_connection, VERSION_FIPS, STATUS_FIPS)
    wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
    wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", "reset", FLAG])
    payload = json.loads(result.stdout)
    assert payload["after"]["piv_build"] == {
        "label": "OpenFIPS201-P71D600-FIPS",
        "version": "2.0.0",
        "fips_mode": True,
    }
    assert payload["verified_locally"]["piv_build_matches"] is True


def test_without_an_applet_the_build_is_unknown_not_wrong(monkeypatch, mock_connection, wired):
    conn = mock_connection(
        ATR,
        {
            SELECT_ISD: "6F108408A000000151000000A5049F6501FF|9000",
            SELECT_PIV: "|6A82",
            "00A4040000": "|9000",
            CPLC_CMD: f"{CPLC_RESP}|9000",
        },
        [],
    )
    wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
    wired["arm"]([OK_RESULT])
    result = run(["--json", "remote", "reset", FLAG])
    # An applet that is absent after the reset fails the presence checks (exit 17);
    # the build itself stays unknown rather than wrong.
    assert result.exit_code == 17, result.output
    payload = json.loads(result.stdout)
    assert payload["after"]["piv_build"] is None
    assert payload["verified_locally"]["piv_build_matches"] is None
    assert "piv_build_matches" not in result.stderr


def test_human_output_names_the_build_and_warns_about_what_fips_off_means(wired):
    wired["arm"]([PONG, OK_RESULT])
    result = run(["remote", "reset", "--fips-off", FLAG])
    assert result.exit_code == 0, result.output
    text = " ".join(result.output.split())
    assert "reinstalled as the build with FIPS mode off" in text
    assert "a PIN shorter than 6 digits" in text
    assert "PIV applet build: build with FIPS mode off (OpenFIPS201-P71D600 2.0.0)" in text
    assert "piv_build_matches: match" in text
    assert "holds no FIPS 140-3 validation" in text


def test_going_back_to_the_fips_mode_build_is_announced(wired):
    wired["arm"]([OK_RESULT])
    result = run(["remote", "reset", FLAG])
    assert "this operation installs the FIPS-mode build" in " ".join(result.output.split())


def test_help_names_both_builds():
    for op in ("reset", "dev-reset"):
        text = " ".join(run(["remote", op, "--help"]).output.split())
        assert "--piv-variant [fips|fipsoff]" in text
        assert "--fips-off" in text
        assert "FIPS mode off" in text


# --------------------------------------------------------------------------- #
# inspect                                                                     #
# --------------------------------------------------------------------------- #
def _inspect_result(fips_mode):
    status = {} if fips_mode is None else {"fips_mode": fips_mode}
    return {
        "type": "result",
        "ok": True,
        "piv_applet": {"present": True, "applet": {"status": status}},
    }


@pytest.mark.parametrize(("reported", "expected"), [(False, True), (True, False), (None, None)])
def test_inspect_reads_the_build_itself_and_compares_it_with_the_service(wired, reported, expected):
    wired["arm"]([_inspect_result(reported)])
    result = run(["--json", "remote", "inspect"])
    assert result.exit_code == (17 if expected is False else 0), result.output
    payload = json.loads(result.stdout)
    assert payload["piv_build"]["fips_mode"] is False
    assert payload["verified_locally"]["piv_build_matches"] is expected


def test_inspect_human_output_shows_the_build(wired):
    wired["arm"]([_inspect_result(False)])
    text = " ".join(run(["remote", "inspect"]).output.split())
    assert "PIV applet build (read locally): build with FIPS mode off" in text


def test_authenticate_does_not_read_the_build(wired):
    wired["arm"]([{"type": "result", "ok": True}])
    payload = json.loads(run(["--json", "remote", "authenticate"]).stdout)
    assert "piv_build" not in payload
    assert "piv_build_matches" not in payload["verified_locally"]
