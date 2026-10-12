"""The frame codec: everything from the service is untrusted input."""

import json

import pytest

from cryptnox_id_cli.remote import protocol as proto
from cryptnox_id_cli.transport.errors import RemoteProtocolError


# --------------------------------------------------------------------------- #
# Decoding messages into frames                                               #
# --------------------------------------------------------------------------- #
def test_single_object_message():
    frames = proto.decode_frames('{"type":"atr"}')
    assert frames == [{"type": "atr"}]


def test_newline_separated_objects_in_one_message():
    frames = proto.decode_frames('{"type":"log","msg":"a"}\n{"type":"atr"}\n')
    assert [f["type"] for f in frames] == ["log", "atr"]


def test_bytes_message_is_decoded_as_utf8():
    assert proto.decode_frames(b'{"type":"atr"}') == [{"type": "atr"}]


def test_non_utf8_message_is_refused():
    with pytest.raises(RemoteProtocolError, match="UTF-8"):
        proto.decode_frames(b"\xff\xfe{")


def test_malformed_json_is_refused():
    with pytest.raises(RemoteProtocolError, match="malformed JSON"):
        proto.decode_frames("{not json}")


def test_json_that_is_not_an_object_is_refused():
    with pytest.raises(RemoteProtocolError, match="not a JSON object"):
        proto.decode_frames("[1, 2, 3]")


def test_empty_message_is_refused():
    with pytest.raises(RemoteProtocolError, match="empty message"):
        proto.decode_frames("   \n  \n")


def test_oversize_message_is_refused_before_parsing():
    huge = '{"type":"log","msg":"' + "x" * (proto.MAX_MESSAGE_BYTES + 10) + '"}'
    with pytest.raises(RemoteProtocolError, match="larger than"):
        proto.decode_frames(huge)


def test_too_many_frames_in_one_message_is_refused():
    message = "\n".join(['{"type":"atr"}'] * (proto.MAX_FRAMES_PER_MESSAGE + 1))
    with pytest.raises(RemoteProtocolError, match="more than"):
        proto.decode_frames(message)


# --------------------------------------------------------------------------- #
# Typing the frames                                                           #
# --------------------------------------------------------------------------- #
def test_pow_challenge_parsed():
    frame = proto.parse_server_frame({"type": "pow_challenge", "challenge": "00ff", "bits": 20})
    assert isinstance(frame, proto.PowChallenge)
    assert frame.challenge == b"\x00\xff"
    assert frame.bits == 20


def test_pow_challenge_without_bits_is_refused():
    with pytest.raises(RemoteProtocolError, match="bit count"):
        proto.parse_server_frame({"type": "pow_challenge", "challenge": "00ff"})


def test_pow_challenge_bits_must_not_be_a_bool():
    # json.loads turns `true` into a bool, which is an int subclass; a bool is
    # not a difficulty.
    with pytest.raises(RemoteProtocolError, match="bit count"):
        proto.parse_server_frame({"type": "pow_challenge", "challenge": "00ff", "bits": True})


def test_apdu_frame_parsed():
    frame = proto.parse_server_frame({"type": "apdu", "hex": "00A4040000"})
    assert isinstance(frame, proto.ApduCommand)
    assert frame.apdu == bytes.fromhex("00A4040000")
    assert frame.header_hex == "00A40400"


def test_apdu_shorter_than_a_header_is_refused():
    with pytest.raises(RemoteProtocolError, match="shorter than an APDU header"):
        proto.parse_server_frame({"type": "apdu", "hex": "00A4"})


def test_apdu_with_invalid_hex_is_refused():
    with pytest.raises(RemoteProtocolError, match="invalid hex"):
        proto.parse_server_frame({"type": "apdu", "hex": "00zz040000"})


def test_apdu_with_odd_length_hex_is_refused():
    with pytest.raises(RemoteProtocolError, match="odd-length"):
        proto.parse_server_frame({"type": "apdu", "hex": "00A40400001"})


def test_oversize_apdu_is_refused():
    with pytest.raises(RemoteProtocolError, match="exceeds"):
        proto.parse_server_frame({"type": "apdu", "hex": "AA" * (proto.MAX_APDU_BYTES + 1)})


def test_atr_request_parsed():
    assert isinstance(proto.parse_server_frame({"type": "atr"}), proto.AtrRequest)


def test_result_keeps_every_field_except_the_type():
    frame = proto.parse_server_frame(
        {"type": "result", "ok": True, "wiped_and_reprovisioned": True, "steps": []}
    )
    assert isinstance(frame, proto.OpResult)
    assert frame.ok is True
    assert frame.payload == {"ok": True, "wiped_and_reprovisioned": True, "steps": []}
    assert "type" not in frame.payload


def test_result_without_ok_is_not_treated_as_success():
    frame = proto.parse_server_frame({"type": "result", "error": "rate limit"})
    assert isinstance(frame, proto.OpResult)
    assert frame.ok is False


def test_unknown_frame_type_is_reported_not_skipped():
    with pytest.raises(RemoteProtocolError, match="unsupported frame type"):
        proto.parse_server_frame({"type": "reboot_everything"})


def test_frame_without_a_type_is_refused():
    with pytest.raises(RemoteProtocolError, match="without a type"):
        proto.parse_server_frame({"msg": "hello?"})


def test_unknown_fields_on_a_known_frame_are_ignored():
    frame = proto.parse_server_frame({"type": "atr", "future_field": 1})
    assert isinstance(frame, proto.AtrRequest)


# --------------------------------------------------------------------------- #
# Untrusted text                                                              #
# --------------------------------------------------------------------------- #
def test_log_message_is_stripped_of_ansi_and_control_characters():
    frame = proto.parse_server_frame({"type": "log", "msg": "\x1b[31mred\x1b[0m\x07 and \x00 gone"})
    assert isinstance(frame, proto.LogMessage)
    assert "\x1b" not in frame.message
    assert "\x07" not in frame.message
    assert "\x00" not in frame.message
    assert "red" in frame.message


def test_log_message_is_capped():
    frame = proto.parse_server_frame({"type": "log", "msg": "x" * 10_000})
    assert isinstance(frame, proto.LogMessage)
    assert len(frame.message) <= proto.MAX_TEXT_CHARS + 20
    assert "truncated" in frame.message


def test_log_message_that_is_not_a_string_is_coerced():
    frame = proto.parse_server_frame({"type": "log", "msg": {"nested": "object"}})
    assert isinstance(frame, proto.LogMessage)
    assert isinstance(frame.message, str)


# --------------------------------------------------------------------------- #
# Frames this client sends                                                    #
# --------------------------------------------------------------------------- #
def test_hello_names_the_operation_and_carries_params():
    frame = proto.hello_frame("attest", {"slot": "9C", "algorithm": "ECCP256"})
    assert frame["type"] == "hello"
    assert frame["op"] == "attest"
    assert frame["params"] == {"slot": "9C", "algorithm": "ECCP256"}


def test_hello_refuses_an_operation_the_service_does_not_expose():
    with pytest.raises(ValueError, match="unknown remote operation"):
        proto.hello_frame("format-everything")


def test_hello_without_params_sends_an_empty_object():
    assert proto.hello_frame("inspect")["params"] == {}


def test_apdu_response_carries_uppercase_hex_and_integer_status_bytes():
    frame = proto.apdu_response_frame(b"\xde\xad", 0x90, 0x00)
    assert frame == {"type": "apdu_resp", "data": "DEAD", "sw1": 0x90, "sw2": 0x00}


def test_apdu_response_with_no_body_sends_empty_hex():
    assert proto.apdu_response_frame(b"", 0x6A, 0x82)["data"] == ""


def test_apdu_error_frame_shape():
    assert proto.apdu_error_frame("card removed") == {
        "type": "apdu_resp",
        "error": "card removed",
    }


def test_atr_response_shape():
    assert proto.atr_response_frame(b"\x3b\xfa")["atr"] == "3BFA"


def test_encode_is_compact_single_line_json():
    text = proto.encode_frame(proto.hello_frame("inspect"))
    assert "\n" not in text
    assert " " not in text
    assert json.loads(text)["op"] == "inspect"


def test_round_trip_through_the_codec():
    text = proto.encode_frame({"type": "atr"})
    assert proto.decode_frames(text) == [{"type": "atr"}]
