"""How a failed remote operation is explained. Pure mapping: no socket, no card.

The sentences below are the ones the service sends today; the mapping reads the
flag first where there is one, so each case is also tried with the wording
changed.
"""

import pytest

from cryptnox_id_cli.remote import refusal
from cryptnox_id_cli.transport.errors import RemoteOperationError

CASES = [
    (
        "reset",
        {"error": "internal error (ref 1a2b3c4d)", "internal_error": True, "ref": "1a2b3c4d"},
        "internal_error",
    ),
    (
        "inspect",
        {"error": "rate limit for card 4301012345670042; retry in 2031s"},
        "rate_limited_card",
    ),
    (
        "inspect",
        {"error": "rate limited (source 203.0.113.9); retry in 42s"},
        "rate_limited_source",
    ),
    ("attest", {"error": "server busy (concurrency cap), retry later"}, "busy"),
    ("reset", {"error": "idle/op timeout"}, "timeout"),
    ("reset", {"error": "operation deadline exceeded"}, "timeout"),
    (
        "attest",
        {
            "error": "attest is not available on this card: its secure channel (SCP02 (no "
            "R-MAC/R-ENC on these cards)) cannot authenticate the card's responses",
            "legacy_channel": True,
            "attest_unavailable": True,
        },
        "legacy_channel",
    ),
    (
        "reset",
        {"error": "reset requires an access token on this card", "legacy_channel": True},
        "legacy_channel",
    ),
    (
        "attest",
        {
            "error": "attest refused: the card reports it is being driven over the CONTACTLESS "
            "interface; PIV administration is contact-only",
            "contactless": True,
        },
        "contactless",
    ),
    (
        "reset",
        {"error": "unknown piv_variant 'bogus' (known: fips, fipsoff)"},
        "piv_build_unavailable",
    ),
    (
        "reset",
        {"error": "piv_variant 'fipsoff' is disabled on this service"},
        "piv_build_unavailable",
    ),
    (
        "reset",
        {"error": "the PIV CAP for variant 'fipsoff' is not deployed on the server"},
        "piv_build_unavailable",
    ),
    (
        "reset",
        {
            "error": "reset of a card on the public default key requires a Cryptnox factory "
            "token (the card cannot prove it is genuine)"
        },
        "factory_token_required",
    ),
    (
        "attest",
        {
            "error": "attest refused: the card's derived keys no longer authenticate: not a "
            "genuine Cryptnox card, or consumer-locked"
        },
        "card_not_genuine",
    ),
    (
        "dev-reset",
        {"error": "refused: the card did not authenticate with its derived KVN2 (not a genuine"},
        "card_not_genuine",
    ),
    # a finalized applet: the service's flag, and what a build from before it answered
    (
        "attest",
        {
            "error": "attest refused: the PIV applet is finalized. Attesting generates a new "
            "key in slot 9C and the key now in that slot is overwritten.",
            "applet_finalized": True,
            "confirmation_required": "replace_key",
        },
        "applet_finalized",
    ),
    (
        "attest",
        {
            "error": "attest refused: the finalized PIV applet has no ECCP256 key object in "
            "slot 9C (GENERATE SW=6A80)",
            "applet_finalized": True,
        },
        "applet_finalized",
    ),
    ("attest", {"error": "create 9B mgmt key failed SW=6986"}, "applet_finalized"),
    ("attest", {"error": "create slot 9C (adminKey=9B) failed SW=6986"}, "applet_finalized"),
    ("dev-reset", {"error": "unknown op 'dev-reset'"}, "unsupported_operation"),
    (
        "attest",
        {"error": "unsupported slot '9B' (PIV key slots 9A, 9C, 9D, 9E)"},
        "unsupported_request",
    ),
    ("attest", {"error": "unknown algorithm 'RSA1024'"}, "unsupported_request"),
    ("inspect", {"error": "proof-of-work failed"}, "proof_of_work"),
    ("reset", {"error": "wipe: delete PIV instance + package + SSD failed rc=1"}, "refused"),
    ("reset", {}, "refused"),
]


@pytest.mark.parametrize(("op", "payload", "reason"), CASES)
def test_each_known_answer_gets_its_reason(op, payload, reason):
    found = refusal.classify(op, {"ok": False, **payload})
    assert found.reason == reason
    assert found.reason in refusal.REASONS
    assert found.message and "\n" not in found.message


def test_flags_decide_before_wording():
    # The service may reword a sentence; the flag beside it is what is read.
    assert refusal.classify("attest", {"error": "nope", "legacy_channel": True}).reason == (
        "legacy_channel"
    )
    assert refusal.classify("attest", {"error": "nope", "contactless": True}).reason == (
        "contactless"
    )
    assert refusal.classify("reset", {"error": "nope", "internal_error": True}).reason == (
        "internal_error"
    )
    # A flag that is not exactly true is not a flag.
    assert refusal.classify("attest", {"error": "nope", "legacy_channel": "yes"}).reason == (
        "refused"
    )


def test_waiting_time_and_reference_are_extracted():
    limited = refusal.classify("inspect", {"error": "rate limit for card 43; retry in 2031s"})
    assert limited.retry_in_seconds == 2031
    assert "about 34 minutes" in limited.message
    source = refusal.classify("inspect", {"error": "rate limited (source 203.0.113.9)"})
    assert source.retry_in_seconds is None and "Retry in a minute" in source.message

    fault = refusal.classify("reset", {"error": "internal error (ref 1A2B3C4D)"})
    assert fault.ref == "1a2b3c4d"
    assert "Quote reference 1a2b3c4d" in fault.message
    # A reference that is not hex is not repeated.
    odd = refusal.classify(
        "reset", {"error": "internal error", "internal_error": True, "ref": "x; rm -rf"}
    )
    assert odd.ref is None and "Quote reference" not in odd.message


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (1, "1 second"),
        (42, "42 seconds"),
        (90, "about 2 minutes"),
        (2031, "about 34 minutes"),
        (5400, "about 1.5 hours"),
        (7200, "about 2 hours"),
    ],
)
def test_waiting_times_read_naturally(seconds, text):
    assert refusal.describe_wait(seconds) == text


def test_an_unknown_answer_keeps_the_service_sentence():
    found = refusal.classify("inspect", {"error": "something \x1b[31mnew\x1b[0m happened"})
    assert found.reason == "refused"
    assert found.message == "the service reported inspect as failed: something new happened"
    assert found.service_text == "something new happened"


def test_the_error_object_carries_the_reason_and_extras():
    plain = RemoteOperationError("m", result={"ok": False})
    assert plain.to_dict() == {
        "error": "remote_failed",
        "message": "m",
        "reason": "refused",
        "result": {"ok": False},
    }
    full = RemoteOperationError(
        "m", result={}, reason="rate_limited_card", retry_in_seconds=60, ref="ab12cd34"
    )
    assert full.to_dict()["retry_in_seconds"] == 60
    assert full.to_dict()["ref"] == "ab12cd34"
    assert full.exit_code == 16
