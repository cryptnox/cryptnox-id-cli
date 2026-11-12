"""What a failed remote operation means, in terms the card holder can act on.

The service answers a refused or failed operation with ``ok: false``, a sentence
in ``error`` and, for some cases, a flag beside it. This module maps that answer
to a ``reason`` a script can branch on and a message that says what to do next.

The mapping reads flags first and wording second, and recognises only sentences
the service is known to send; anything else stays ``refused`` with the service's
own sentence. The service's sentence is never dropped: it stays in the result
the error carries, and the command prints it as a note.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from . import protocol as proto

#: Every reason this module can return.
REASONS: tuple[str, ...] = (
    "internal_error",
    "rate_limited_card",
    "rate_limited_source",
    "busy",
    "timeout",
    "legacy_channel",
    "contactless",
    "piv_build_unavailable",
    "factory_token_required",
    "card_not_genuine",
    "applet_finalized",
    "answer_altered",
    "unsupported_operation",
    "unsupported_request",
    "proof_of_work",
    "refused",
)

_RETRY_IN = re.compile(r"retry in (\d{1,7}) ?s\b")
_REFERENCE = re.compile(r"^[0-9a-fA-F]{4,32}$")
_REFERENCE_IN_TEXT = re.compile(r"\(ref ([0-9a-fA-F]{4,32})\)")


@dataclass(frozen=True)
class Refusal:
    """A failed operation, classified."""

    reason: str
    message: str
    retry_in_seconds: int | None = None
    ref: str | None = None
    service_text: str | None = None


def describe_wait(seconds: int) -> str:
    """A waiting time the way a person would say it."""
    if seconds < 90:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    minutes = round(seconds / 60)
    if minutes < 90:
        return f"about {minutes} minutes"
    return f"about {round(seconds / 3600, 1):g} hours"


def service_text(payload: Mapping[str, object]) -> str | None:
    """The sentence the service gave for the failure, made safe to display."""
    for key in ("error", "message", "reason", "detail"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return proto.sanitize_server_text(value)
    return None


def _retry_in(text: str) -> int | None:
    found = _RETRY_IN.search(text)
    return int(found.group(1)) if found else None


def _reference(payload: Mapping[str, object], text: str) -> str | None:
    ref = payload.get("ref")
    if isinstance(ref, str) and _REFERENCE.match(ref):
        return ref.lower()
    found = _REFERENCE_IN_TEXT.search(text)
    return found.group(1).lower() if found else None


def classify(op: str, payload: Mapping[str, object]) -> Refusal:
    """Classify the result frame of an operation the service reported as failed."""
    text = service_text(payload) or ""
    low = text.lower()

    def refusal(reason: str, message: str, **extra: object) -> Refusal:
        return Refusal(reason=reason, message=message, service_text=text or None, **extra)  # type: ignore[arg-type]

    if payload.get("internal_error") is True or low.startswith("internal error"):
        ref = _reference(payload, text)
        quote = f" Quote reference {ref} to Cryptnox support." if ref else ""
        return refusal(
            "internal_error",
            f"the service failed while running {op}: an error on its side, not a refusal. "
            f"What the card holds now is unknown; run `remote inspect` before repeating.{quote}",
            ref=ref,
        )

    if low.startswith("rate limit for card"):
        wait = _retry_in(low)
        when = f" It accepts the next one in {describe_wait(wait)}." if wait is not None else ""
        return refusal(
            "rate_limited_card",
            "the service has reached its limit of operations for this card."
            f"{when} Every remote operation counts toward it, `remote inspect` and "
            "`remote authenticate` included; `remote ping` does not.",
            retry_in_seconds=wait,
        )

    if low.startswith("rate limited (source"):
        wait = _retry_in(low)
        when = f" Retry in {describe_wait(wait)}." if wait is not None else " Retry in a minute."
        return refusal(
            "rate_limited_source",
            f"the service is limiting connections from this network address.{when}",
            retry_in_seconds=wait,
        )

    if "server busy" in low:
        return refusal(
            "busy",
            "the service is running as many operations as it accepts at once. Nothing was "
            "changed on the card; retry in a moment.",
        )

    if low in ("idle/op timeout", "operation deadline exceeded"):
        return refusal(
            "timeout",
            f"the service stopped waiting during {op}: the card or the connection was too "
            "slow. The operation may be half done; run `remote inspect`, then repeat it.",
        )

    if payload.get("legacy_channel") is True:
        if op == "attest" or payload.get("attest_unavailable") is True:
            return refusal(
                "legacy_channel",
                "key attestation is not available for this card. Its PIV security domain "
                "speaks a secure channel that cannot authenticate the card's answers, so the "
                "service cannot prove that the key it would certify came from the card. "
                "Nothing was written.",
            )
        return refusal(
            "legacy_channel",
            f"the service runs {op} on this card for Cryptnox only: its secure channel "
            "cannot authenticate the card's answers, so the service does not drive it "
            "without an access token. Contact Cryptnox support.",
        )

    if payload.get("contactless") is True or "contact-only" in low:
        return refusal(
            "contactless",
            "the card answered over the contactless interface, and the service administers "
            "the PIV function over the contact interface only. Put the card in a contact "
            "reader and repeat.",
        )

    if (
        low.startswith("unknown piv_variant")
        or (low.startswith("piv_variant") and "disabled" in low)
        or low.startswith("the piv cap for variant")
    ):
        return refusal(
            "piv_build_unavailable",
            "the service does not offer the requested PIV applet build. Nothing was changed "
            "on the card; `remote ping` lists the builds it offers.",
        )

    if (
        "derived keys no longer authenticate" in low
        or "did not authenticate with its derived" in low
    ):
        return refusal(
            "card_not_genuine",
            "the card did not prove it is genuine with its own keys: it is not a genuine "
            "Cryptnox card, its Cryptnox keyset was deleted, or it is already on the default "
            "keys. Nothing was changed; contact Cryptnox support.",
        )

    if "factory token" in low:
        return refusal(
            "factory_token_required",
            f"the service reserves this form of {op} to Cryptnox (it needs a factory token). "
            "Nothing was changed on the card; contact Cryptnox support.",
        )

    if payload.get("applet_finalized") is True:
        if payload.get("confirmation_required") == "replace_key":
            return refusal(
                "applet_finalized",
                f"the PIV applet on this card is finalized, and {op} overwrites the key now "
                "in the slot. The service does that only when the client confirms it, and "
                "this run did not: the applet's state could not be read here to ask first. "
                "Nothing was changed.",
            )
        return refusal(
            "applet_finalized",
            "the PIV applet on this card is finalized and the slot has no key object for "
            "this algorithm; nothing can be added to a finalized applet. Nothing was "
            "changed. `piv inventory` lists the key objects the slot has; `remote reset` "
            "gives an empty applet and erases the PIV keys and certificates.",
        )

    if "failed sw=6986" in low:
        # Older service builds stop at the first creation a finalized applet refuses.
        return refusal(
            "applet_finalized",
            f"the PIV applet refused a change to its structure during {op} (status 6986), "
            "which is what a finalized applet answers, and this build of the service cannot "
            "attest a key on a finalized applet. Nothing was certified.",
        )

    if "r-mac mismatch" in low:
        return refusal(
            "answer_altered",
            "an answer from the card was altered between the service and the card. Check "
            "the relay path and report it; do not retry in a loop.",
        )

    if low.startswith("unknown op"):
        return refusal(
            "unsupported_operation",
            f"this service does not offer {op}. `remote ping` lists what it offers.",
        )

    if low.startswith(("unsupported slot", "unsupported ca_obj", "unknown algorithm")):
        return refusal(
            "unsupported_request",
            f"the service does not accept this request: {text}. Nothing was changed on the card.",
        )

    if low.startswith("proof-of-work failed"):
        return refusal(
            "proof_of_work",
            "the service rejected the proof-of-work answer. Nothing was sent to the card; "
            "retry, and report it if it repeats.",
        )

    if text:
        return refusal("refused", f"the service reported {op} as failed: {text}")
    return refusal("refused", f"the service reported {op} as failed")
