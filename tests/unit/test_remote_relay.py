"""The operation loop, driven by a scripted service and a mock card."""

import json

import pytest

from cryptnox_id_cli.remote import pow as rpow
from cryptnox_id_cli.remote import relay
from cryptnox_id_cli.remote.channel import FrameChannel
from cryptnox_id_cli.secrets.redaction import Redactor
from cryptnox_id_cli.transport.errors import (
    RemoteConnectError,
    RemoteError,
    RemoteOperationError,
    RemotePolicyError,
    RemoteProtocolError,
)

ATR = "3BFA1300FF910131FE000031C173C84000009000D2"
CPLC_CMD = "80CA9F7F00"
CPLC_RESP = (
    "9F7F2A4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
)
SELECT_SSD = "00A4040009A0000001515350410100"
SELECT_PIV = "00A404000BA00000030800001000010000"
SELECT_WALLET = "00A4040007A000001000011200"
KEY_INFO = "80CA00E000"
KEY_INFO_RESP = "E012C00401018010C00402018010C00403018010"


class ScriptedChannel:
    """A FrameChannel that plays server frames in order and records client frames.

    A script entry is either a frame dict (sent to the client as one message),
    a string (sent raw, for framing tests), or an exception (raised on recv).
    """

    def __init__(self, script):
        self.script = list(script)
        self.sent: list[dict] = []
        self.closed = False
        self.timeouts: list[float | None] = []

    def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    def recv(self, timeout=None) -> str:
        self.timeouts.append(timeout)
        if not self.script:
            raise RemoteConnectError("script exhausted: the service went silent")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, str):
            return item
        return json.dumps(item)

    def close(self) -> None:
        self.closed = True

    # Convenience for assertions.
    def sent_types(self) -> list[str]:
        return [f["type"] for f in self.sent]


def pow_challenge(bits: int = 8, challenge: str = "00112233445566778899aabbccddeeff") -> dict:
    return {"type": "pow_challenge", "challenge": challenge, "bits": bits}


def card(mock_connection, exchanges=None, deny=None):
    return mock_connection(ATR, exchanges or {}, deny or [])


def test_scripted_channel_satisfies_the_protocol():
    assert isinstance(ScriptedChannel([]), FrameChannel)


# --------------------------------------------------------------------------- #
# The happy path                                                              #
# --------------------------------------------------------------------------- #
def test_authenticate_end_to_end(mock_connection):
    channel = ScriptedChannel(
        [
            pow_challenge(bits=8),
            {"type": "atr"},
            {"type": "log", "msg": "reading CPLC"},
            {"type": "apdu", "hex": CPLC_CMD},
            {"type": "result", "ok": True, "cplc_uid": "4301012345670042"},
        ]
    )
    conn = card(mock_connection, {CPLC_CMD: f"{CPLC_RESP}|9000"})
    logs: list[str] = []
    lines: list[str] = []

    report = relay.run_operation(
        channel, conn, "authenticate", transcript=lines.append, on_log=logs.append
    )

    assert report.ok is True
    assert report.result == {"ok": True, "cplc_uid": "4301012345670042"}
    assert report.apdus_relayed == 1
    assert report.atr == bytes.fromhex(ATR)
    assert report.pow_bits == 8
    assert logs == ["reading CPLC"]

    assert channel.sent_types() == ["hello", "pow", "atr_resp", "apdu_resp"]
    assert channel.sent[0] == {"type": "hello", "op": "authenticate", "params": {}}
    nonce = channel.sent[1]["nonce"]
    assert isinstance(nonce, int)
    assert (
        rpow.leading_zero_bits(
            rpow.digest_for(bytes.fromhex("00112233445566778899aabbccddeeff"), nonce)
        )
        >= 8
    )
    assert channel.sent[2] == {"type": "atr_resp", "atr": ATR}
    assert channel.sent[3] == {"type": "apdu_resp", "data": CPLC_RESP, "sw1": 0x90, "sw2": 0x00}

    assert lines == ["> " + CPLC_CMD, "< " + CPLC_RESP + "9000"]


def test_hello_carries_params(mock_connection):
    channel = ScriptedChannel([{"type": "result", "ok": True}])
    relay.run_operation(channel, card(mock_connection), "inspect", {"fused": False})
    assert channel.sent[0]["params"] == {"fused": False}


def test_a_failed_select_is_returned_verbatim(mock_connection):
    channel = ScriptedChannel(
        [
            {"type": "apdu", "hex": SELECT_SSD},
            {"type": "result", "ok": True, "piv_ssd": {"present": False}},
        ]
    )
    report = relay.run_operation(channel, card(mock_connection), "inspect")
    assert channel.sent[-1] == {"type": "apdu_resp", "data": "", "sw1": 0x6A, "sw2": 0x82}
    assert report.apdus_relayed == 1


def test_several_frames_in_one_message_are_all_handled(mock_connection):
    two = (
        json.dumps({"type": "log", "msg": "a"}) + "\n" + json.dumps({"type": "result", "ok": True})
    )
    channel = ScriptedChannel([two])
    report = relay.run_operation(channel, card(mock_connection), "inspect")
    assert report.log_lines == ["a"]
    assert report.ok


def test_recv_uses_the_configured_timeout(mock_connection):
    channel = ScriptedChannel([{"type": "result", "ok": True}])
    relay.run_operation(channel, card(mock_connection), "inspect", recv_timeout=42.0)
    assert channel.timeouts == [42.0]


# --------------------------------------------------------------------------- #
# The relay is raw: no chaining, no retries, no commands of its own           #
# --------------------------------------------------------------------------- #
def test_61xx_goes_back_to_the_service_untouched(mock_connection):
    """The service owns GET RESPONSE. The client must never issue one itself."""
    channel = ScriptedChannel(
        [
            {"type": "apdu", "hex": CPLC_CMD},
            {"type": "result", "ok": True},
        ]
    )
    sent_to_card: list[str] = []
    conn = card(mock_connection, {CPLC_CMD: "AABB|6110"})
    original = conn.transmit

    def spy(apdu):
        sent_to_card.append(bytes(apdu).hex().upper())
        return original(apdu)

    conn.transmit = spy
    relay.run_operation(channel, conn, "inspect")
    assert sent_to_card == [CPLC_CMD]  # no 00C0 GET RESPONSE from the client
    assert channel.sent[-1] == {"type": "apdu_resp", "data": "AABB", "sw1": 0x61, "sw2": 0x10}


def test_6cxx_goes_back_to_the_service_untouched(mock_connection):
    channel = ScriptedChannel([{"type": "apdu", "hex": CPLC_CMD}, {"type": "result", "ok": True}])
    conn = card(mock_connection, {CPLC_CMD: "|6C2A"})
    relay.run_operation(channel, conn, "inspect")
    assert channel.sent[-1] == {"type": "apdu_resp", "data": "", "sw1": 0x6C, "sw2": 0x2A}


# --------------------------------------------------------------------------- #
# Policy is enforced before anything reaches the card                         #
# --------------------------------------------------------------------------- #
def test_a_refused_command_never_reaches_the_card_and_ends_the_operation(mock_connection):
    channel = ScriptedChannel(
        [
            {"type": "apdu", "hex": SELECT_WALLET},
            {"type": "result", "ok": True},  # never reached
        ]
    )
    conn = card(mock_connection, {SELECT_WALLET: "|9000"})
    touched: list[str] = []
    original = conn.transmit
    conn.transmit = lambda apdu: (touched.append(bytes(apdu).hex()), original(apdu))[1]

    with pytest.raises(RemotePolicyError, match="SELECT of AID A0000010000112"):
        relay.run_operation(channel, conn, "inspect")
    assert touched == []
    assert channel.sent_types() == ["hello"]  # no apdu_resp for the refused command


def test_policy_follows_the_card_not_the_service(mock_connection):
    # The service selects the PIV applet, the card says 6A82; a PIV read that
    # follows must be judged in the card-manager context, and refused there.
    channel = ScriptedChannel(
        [
            {"type": "apdu", "hex": SELECT_PIV},
            {"type": "apdu", "hex": "00CB3FFF055C035FC10200"},
        ]
    )
    with pytest.raises(RemotePolicyError, match="while the isd is selected"):
        relay.run_operation(channel, card(mock_connection), "inspect")


def test_wall_clock_budget_is_enforced(mock_connection):
    # started, elapsed for the first command, elapsed for the second.
    ticks = iter([0.0, 0.0, 1000.0])
    channel = ScriptedChannel(
        [{"type": "apdu", "hex": CPLC_CMD}, {"type": "apdu", "hex": CPLC_CMD}]
    )
    conn = card(mock_connection, {CPLC_CMD: f"{CPLC_RESP}|9000"})
    with pytest.raises(RemoteError, match="exceeded 120 seconds"):
        relay.run_operation(channel, conn, "inspect", clock=lambda: next(ticks))


# --------------------------------------------------------------------------- #
# Failures                                                                    #
# --------------------------------------------------------------------------- #
def test_result_not_ok_raises_with_the_payload(mock_connection):
    channel = ScriptedChannel([{"type": "result", "ok": False, "error": "rate limit exceeded"}])
    with pytest.raises(RemoteOperationError, match="rate limit exceeded") as info:
        relay.run_operation(channel, card(mock_connection), "inspect")
    assert info.value.result == {"ok": False, "error": "rate limit exceeded"}
    assert info.value.to_dict()["result"]["error"] == "rate limit exceeded"


def test_result_without_ok_is_a_failure(mock_connection):
    channel = ScriptedChannel([{"type": "result"}])
    with pytest.raises(RemoteOperationError, match="reported inspect as failed"):
        relay.run_operation(channel, card(mock_connection), "inspect")


def test_failure_text_from_the_service_is_sanitised(mock_connection):
    channel = ScriptedChannel([{"type": "result", "ok": False, "error": "\x1b[31mnope\x1b[0m"}])
    with pytest.raises(RemoteOperationError) as info:
        relay.run_operation(channel, card(mock_connection), "inspect")
    assert "\x1b" not in str(info.value)


def test_second_pow_challenge_is_refused(mock_connection):
    channel = ScriptedChannel([pow_challenge(4), pow_challenge(4)])
    with pytest.raises(RemoteProtocolError, match="second proof-of-work"):
        relay.run_operation(channel, card(mock_connection), "inspect")


def test_card_error_is_reported_to_the_service_then_aborts(mock_connection):
    channel = ScriptedChannel([{"type": "apdu", "hex": "00A4040000"}])
    conn = card(mock_connection, deny=["00A4040000"])
    with pytest.raises(RemoteError, match="card stopped answering"):
        relay.run_operation(channel, conn, "inspect")
    assert channel.sent[-1]["type"] == "apdu_resp"
    assert "error" in channel.sent[-1]
    assert "data" not in channel.sent[-1]


def test_connection_loss_propagates(mock_connection):
    channel = ScriptedChannel([RemoteConnectError("closed")])
    with pytest.raises(RemoteConnectError, match="closed"):
        relay.run_operation(channel, card(mock_connection), "inspect")


def test_malformed_frame_ends_the_operation(mock_connection):
    channel = ScriptedChannel(["not json at all"])
    with pytest.raises(RemoteProtocolError, match="malformed"):
        relay.run_operation(channel, card(mock_connection), "inspect")


def test_unknown_frame_type_ends_the_operation(mock_connection):
    channel = ScriptedChannel([{"type": "surprise"}])
    with pytest.raises(RemoteProtocolError, match="unsupported frame type"):
        relay.run_operation(channel, card(mock_connection), "inspect")


# --------------------------------------------------------------------------- #
# Transcript masking                                                          #
# --------------------------------------------------------------------------- #
def test_known_reads_are_shown_and_everything_else_is_masked():
    r = Redactor()
    assert relay.redact_relayed_command(bytes.fromhex(CPLC_CMD), r) == CPLC_CMD
    assert relay.redact_relayed_command(bytes.fromhex(SELECT_PIV), r) == SELECT_PIV
    put_data = bytes.fromhex("00DB3FFF0A5C035FC1025303AABBCC")
    assert relay.redact_relayed_command(put_data, r) == "00DB3FFF<REDACTED:11B>"
    assert relay.redact_relayed_command(bytes.fromhex("0047009C"), r) == "0047009C"


def test_unmasked_transcript_falls_back_to_the_standard_redactor():
    r = Redactor()
    put_data = bytes.fromhex("00DB3FFF0A5C035FC1025303AABBCC")
    assert relay.redact_relayed_command(put_data, r, unmasked=True) == put_data.hex().upper()
    # Even unmasked, the standard redactor keeps masking verifier data.
    verify = bytes.fromhex("0020008008313233343536FFFF")
    assert "313233343536" not in relay.redact_relayed_command(verify, r, unmasked=True)


def test_responses_are_masked_outside_known_reads():
    r = Redactor()
    assert relay.redact_relayed_response(b"\xaa\xbb", 0x90, 0x00, 0xCA, r) == "AABB9000"
    assert relay.redact_relayed_response(b"\xaa\xbb", 0x90, 0x00, 0x47, r) == "<REDACTED:2B>9000"
    assert relay.redact_relayed_response(b"", 0x6A, 0x82, 0x47, r) == "6A82"
    assert relay.redact_relayed_response(b"\xaa", 0x90, 0x00, 0x47, r, unmasked=True) == "AA9000"


def test_relayed_transcript_masks_by_default(mock_connection):
    generate = "0047009C05AC03800111"
    channel = ScriptedChannel([{"type": "apdu", "hex": generate}, {"type": "result", "ok": True}])
    # Give inspect a policy that lets the command through, so the masking alone is tested.
    from cryptnox_id_cli.remote.policy import PIV, RelayPolicy

    policy = RelayPolicy("inspect")
    policy.rules.allowed_ins[PIV] |= {0x47}  # type: ignore[index]
    policy.context = PIV
    conn = card(mock_connection, {generate: "7F49AABB|9000"})
    lines: list[str] = []
    relay.run_operation(channel, conn, "inspect", policy=policy, transcript=lines.append)
    assert lines == ["> 0047009C<REDACTED:6B>", "< <REDACTED:4B>9000"]
