# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The PIV PIN (80) and PUK (81): the cardholder commands that present or probe them,
and what the applet's answers to those commands mean.

This is the only place that sends VERIFY (with a value and as the empty status
probe), cardholder CHANGE REFERENCE DATA and RESET RETRY COUNTER for the PIN and
PUK, and the only place that reads their status words. The rules follow OpenFIPS201:

* ``63C0`` comes only from a verifier with no retry limit; an exhausted counter
  answers ``6983``.
* ``6983`` is a block on the contact interface. Over contactless it means that
  interface has no tries left, while the contact interface may still have some.
* ``6982`` is the verifier's access rule refusing this interface.

The applet's interface report is read only when an answer depends on it, never
from the verifier listing, and never with another VERIFY: every VERIFY, the probe
included, clears the applet's PIN-always flag.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from enum import Enum

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv import inventory
from cryptnox_id_cli.applets.piv.inventory import AppletStatus
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import (
    CryptnoxError,
    InputError,
    StatusWordError,
    describe_sw,
)
from cryptnox_id_cli.transport.pcsc import is_contactless_interface

PIN = c.REF_PIV_PIN
PUK = c.REF_PUK

#: Every PIN and PUK goes on the wire as exactly this many bytes, padded with 0xFF.
VALUE_LENGTH = 8
#: The shortest value the applet stores, in either build.
MIN_VALUE_LENGTH = 4

_PAD = b"\xff"


class Interface(str, Enum):
    CONTACT = "contact"
    CONTACTLESS = "contactless"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    OK = "ok"
    TRIES_LEFT = "tries_left"
    WRONG = "wrong"
    NO_RETRY_LIMIT = "no_retry_limit"
    BLOCKED = "blocked"
    NO_TRIES_ON_INTERFACE = "no_tries_on_interface"
    REFUSED_ON_INTERFACE = "refused_on_interface"
    NOT_CONFIGURED = "not_configured"
    NO_VALUE = "no_value"
    BAD_VALUE = "bad_value"
    OTHER = "other"


@dataclass(frozen=True)
class OpRules:
    """What reading a verifier command's answer depends on."""

    key: str
    probe: bool = False
    verb: str = "changed"
    counts_puk: bool = False
    sets_value: bool = False
    #: What 6A88 and 6A80 mean for this command, ``{label}`` being its verifier.
    no_value: str = ""
    bad_value: str = ""


class Op(Enum):
    """A verifier command; its value holds the rules for reading the answer."""

    STATUS = OpRules("status", probe=True, verb="verified")
    VERIFY = OpRules(
        "verify",
        verb="verified",
        no_value="The {label} holds no value yet, or this card has no such verifier; no try "
        "was used.",
        bad_value="The card refused the length of the value; no try was used. This tool sends "
        f"{VALUE_LENGTH}-byte values.",
    )
    CHANGE = OpRules(
        "change",
        sets_value=True,
        no_value="The {label} holds no value yet, or this card does not let it be changed; no "
        "try was used.",
        bad_value="The card refused the values: a length it does not take, or a new {label} its "
        "rules do not allow (digits, minimum length).",
    )
    UNBLOCK = OpRules(
        "unblock",
        counts_puk=True,
        sets_value=True,
        no_value="The PUK holds no value, or the PIN is missing or cannot be updated on this "
        "card; no try was used.",
        bad_value="The card refused the values: a length it does not take, or a new PIN its "
        "rules do not allow (digits, minimum length).",
    )

    def counter(self, ref: int) -> int:
        """The verifier whose tries and block the answer reports."""
        return PUK if self.value.counts_puk else ref


_LABEL = {PIN: "PIN", PUK: "PUK"}

#: How a status line words each verdict.
_STATUS_TEXT = {
    Verdict.OK: "configured",
    Verdict.TRIES_LEFT: "{tries} tries left",
    Verdict.WRONG: "{tries} tries left",
    Verdict.NO_RETRY_LIMIT: "no retry limit",
    Verdict.BLOCKED: "blocked",
    Verdict.NO_TRIES_ON_INTERFACE: "no tries left over this interface (contact tries may remain)",
    Verdict.REFUSED_ON_INTERFACE: "not usable over this interface (SW={sw})",
    Verdict.NOT_CONFIGURED: "not configured",
}

_PIN_REFUSED = (
    "the card refuses PIN and PUK commands over this interface (SW={sw}). PIN and PUK "
    "are contact-only on every built-in profile but ms-logon-nfc, which is what a "
    "contactless (NFC/PICC) reader gets even when the PIN is set. Use a contact reader "
    "for anything that asks for the PIN."
)
_PUK_ALONE_REFUSED = (
    "the card refuses PUK commands over this interface (SW={sw}) and accepts the PIN "
    "there: the PUK is contact-only on this card. A PIN with no tries left here may "
    "only have used up its contactless tries: a correct PIN on a contact reader "
    "restores them, and the PUK is the last resort."
)
_PUK_REFUSED = (
    "the card refuses the PUK over this interface (SW={sw}). The PUK is contact-only "
    "on every built-in profile. Use a contact reader for anything that asks for the PUK."
)
_FIPS_REFUSED = (
    "the card refuses PIN and PUK commands over this interface (SW={sw}): the "
    "FIPS-mode build takes them over contactless only inside secure messaging, which "
    "this tool does not use. Use a contact reader for anything that asks for the PIN "
    "or PUK."
)
_CONTACT_REFUSED = (
    "the card's access rule refuses the {label} over the contact interface too (SW={sw}): "
    "it requires an access mode, secure messaging or VCI that this session does not have."
)
_NO_TRIES_HINT = {
    PIN: (
        "The PIN is blocked, or the card's contactless limit for it is reached (contact "
        "tries may remain). Check `piv pin status` from a contact reader, which does not "
        "consume a try; if it reports blocked, recover with `piv pin unblock` (needs the PUK)."
    ),
    PUK: (
        "The PUK is blocked, or the card's contactless limit for it is reached (contact "
        "tries may remain). Check `piv pin status` from a contact reader, which does not "
        "consume a try. A blocked PUK has no recovery path."
    ),
}
_RECOVERY = {
    PIN: "Recover it with `piv pin unblock` (needs the PUK).",
    PUK: "A blocked PUK has no recovery path.",
}


@dataclass(frozen=True)
class Outcome:
    """What the card answered to one verifier command, already interpreted."""

    op: Op
    ref: int
    sw: int
    verdict: Verdict
    #: Tries left on this interface; for ``unblock``, the PUK's.
    tries: int | None = None
    interface: Interface = Interface.UNKNOWN
    #: The sentence a command result carries (``message`` in ``payload()``).
    message: str = ""
    hint: str | None = None
    recovery: str | None = None

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.OK

    @property
    def configured(self) -> bool | None:
        if self.verdict is Verdict.NOT_CONFIGURED:
            return False
        if self.verdict in (Verdict.REFUSED_ON_INTERFACE, Verdict.OTHER):
            return None
        return True

    @property
    def blocked(self) -> bool | None:
        if self.verdict is Verdict.BLOCKED:
            return True
        if self.verdict in (
            Verdict.NO_TRIES_ON_INTERFACE,
            Verdict.REFUSED_ON_INTERFACE,
            Verdict.OTHER,
        ):
            return None
        return False

    @property
    def verified(self) -> bool:
        return self.op.value.probe and self.ok

    @property
    def refused(self) -> bool:
        return self.verdict is Verdict.REFUSED_ON_INTERFACE

    @property
    def over_fifteen_tries(self) -> bool:
        """More tries left than a profile of this tool allows (a 63D0 to 63FF answer)."""
        return self.tries is not None and self.tries > 15

    @property
    def status_text(self) -> str:
        """The short verdict a status line prints; a command result carries ``message``."""
        text = _STATUS_TEXT.get(self.verdict)
        if text:
            return text.format(tries=self.tries, sw=self.sw_hex)
        described = self.message.rstrip(".")
        # describe_sw already names the SW for one it has no text for.
        return described if f"SW={self.sw_hex}" in described else f"{described} (SW={self.sw_hex})"

    @property
    def sw_hex(self) -> str:
        return f"{self.sw:04X}"

    def detail(self) -> str:
        """The message with its hint and recovery, as one text."""
        return " ".join(t for t in (self.message, self.hint, self.recovery) if t)

    def error(self, context: str) -> StatusWordError:
        """The status-word error for a command this answer stops."""
        return StatusWordError(self.sw >> 8, self.sw & 0xFF, context=context, hint=self.detail())

    def to_dict(self) -> dict[str, object]:
        """The status shape (``pin`` / ``puk`` in status, info, report, export-config)."""
        return {
            "ref": f"{self.ref:02X}",
            "configured": self.configured,
            "blocked": self.blocked,
            "verified": self.verified,
            "retries_remaining": self.tries,
            "refused_on_interface": self.refused,
            "state": self.verdict.value,
            "interface": self.interface.value,
        }

    def payload(self) -> dict[str, object]:
        """The result object of ``pin verify``, ``pin change``, ``pin unblock``, ``puk change``."""
        out: dict[str, object] = {
            self.op.value.verb: self.ok,
            "sw": self.sw_hex,
            "message": self.message,
        }
        if self.verdict is Verdict.WRONG:
            out["retries_remaining"] = self.tries
        if self.verdict is Verdict.BLOCKED:
            out["blocked"] = True
        if self.recovery:
            out["recovery"] = self.recovery
        if self.hint:
            out["hint"] = self.hint
        return out


@dataclass(frozen=True)
class Probe:
    """The empty-VERIFY status of the PIN and the PUK."""

    pin: Outcome
    #: None when the PUK probe failed after the PIN answered (``status(partial=True)``).
    puk: Outcome | None

    @property
    def note(self) -> str | None:
        return refused_note(self.pin, self.puk)

    @property
    def note_scope(self) -> str:
        return "PIN/PUK state" if self.pin.refused else "PUK state"

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "pin": self.pin.to_dict(),
            "puk": self.puk.to_dict() if self.puk else None,
        }
        if self.note:
            out["note"] = self.note
        return out


def refused_note(pin: Outcome | None, puk: Outcome | None) -> str | None:
    """Why the PIN or PUK state cannot be read here, when the card refused a probe."""
    for outcome in (pin, puk):
        if outcome is not None and outcome.refused:
            return outcome.hint
    return None


def unread_note(pin: Outcome | None, puk: Outcome | None) -> str | None:
    """Why the probe left the PIN or PUK state unknown, when it did."""
    for label, outcome in (("PIN", pin), ("PUK", puk)):
        if outcome is None:
            return f"the {label} probe failed."
        if outcome.configured is None:
            sw = outcome.sw_hex
            return f"the card answered the {label} probe with SW={sw}: {outcome.message}"
    return None


def check_length(value: bytes, what: str = "PIN or PUK") -> None:
    """Refuse a PIN or PUK value the card can never take."""
    if not MIN_VALUE_LENGTH <= len(value) <= VALUE_LENGTH:
        raise InputError(
            f"the {what} must be {MIN_VALUE_LENGTH} to {VALUE_LENGTH} bytes; this one is "
            f"{len(value)}. It was not sent to the card."
        )


def pad(value: bytes, what: str = "PIN or PUK") -> bytes:
    """The wire form of a PIN or PUK value."""
    check_length(value, what)
    return bytes(value) + _PAD * (VALUE_LENGTH - len(value))


# --------------------------------------------------------------------- commands #
def status(
    piv: PivApplet, *, applet_status: AppletStatus | None = None, partial: bool = False
) -> Probe:
    """Probe the PIN and the PUK without spending a try.

    ``applet_status`` is the applet's own status when the caller already read it.
    With ``partial``, a PUK probe that raises leaves ``puk`` None and keeps the PIN.
    """
    lookup = _InterfaceLookup(piv, applet_status)

    def probe(ref: int) -> int:
        apdu = APDU(0x00, c.INS_VERIFY, 0x00, ref)
        return piv.session.transmit(apdu, context="VERIFY (status)").sw

    pin_sw = probe(PIN)
    puk_sw: int | None = None
    try:
        puk_sw = probe(PUK)
    except CryptnoxError:
        if not partial:
            raise
    if {0x6983, 0x6982} & {pin_sw, puk_sw}:
        lookup()
    pin = _judge(Op.STATUS, PIN, pin_sw, lookup)
    if puk_sw is None:
        return Probe(pin, None)
    usable = pin.verdict in _PIN_ANSWERED
    return Probe(pin, _judge(Op.STATUS, PUK, puk_sw, lookup, pin_usable=usable))


def verify(piv: PivApplet, value: bytes, ref: int = PIN) -> Outcome:
    """Present a PIN (or PUK). A wrong value spends a try."""
    padded = pad(value, _LABEL.get(ref, "value"))
    _register(piv, value, padded)
    resp = piv.session.transmit(
        APDU(0x00, c.INS_VERIFY, 0x00, ref, data=padded), context="VERIFY PIN"
    )
    return _judge(Op.VERIFY, ref, resp.sw, _InterfaceLookup(piv))


def require_pin(piv: PivApplet, pin: bytes, *, context: str = "VERIFY PIN") -> None:
    """Verify the PIN or raise; nothing is sent after a correct PIN."""
    outcome = verify(piv, pin)
    if outcome.ok:
        return
    if outcome.verdict is Verdict.NO_RETRY_LIMIT:
        raise CryptnoxError(f"PIN verification failed (SW={outcome.sw_hex}): {outcome.detail()}")
    if outcome.verdict in (
        Verdict.BLOCKED,
        Verdict.NO_TRIES_ON_INTERFACE,
        Verdict.REFUSED_ON_INTERFACE,
    ):
        raise CryptnoxError(f"PIN verification refused (SW={outcome.sw_hex}): {outcome.detail()}")
    raise outcome.error(context)


def change(piv: PivApplet, ref: int, old: bytes, new: bytes) -> Outcome:
    """Cardholder CHANGE REFERENCE DATA: a wrong current value spends a try."""
    label = _LABEL.get(ref, "value")
    body = pad(old, f"current {label}") + pad(new, f"new {label}")
    _register(piv, old, new, body)
    resp = piv.session.transmit(
        APDU(0x00, c.INS_CHANGE_REFERENCE_DATA, 0x00, ref, data=body),
        context="CHANGE REFERENCE DATA",
    )
    return _judge(Op.CHANGE, ref, resp.sw, _InterfaceLookup(piv))


def unblock(piv: PivApplet, puk: bytes, new_pin: bytes) -> Outcome:
    """RESET RETRY COUNTER: a new PIN with its counter reset, for the PUK."""
    body = pad(puk, "PUK") + pad(new_pin, "new PIN")
    _register(piv, puk, new_pin, body)
    resp = piv.session.transmit(
        APDU(0x00, c.INS_RESET_RETRY, 0x00, PIN, data=body), context="RESET RETRY COUNTER"
    )
    return _judge(Op.UNBLOCK, PIN, resp.sw, _InterfaceLookup(piv))


def _register(piv: PivApplet, *secrets: bytes) -> None:
    for secret in secrets:
        piv.session.redactor.register(secret)


# -------------------------------------------------------------------- interface #
@dataclass(frozen=True)
class _InterfaceFacts:
    interface: Interface
    fips_mode: bool | None
    #: ``Reader '<name>'`` when the reader advertises contactless, read while connected.
    reader: str | None


_NO_FACTS = _InterfaceFacts(Interface.UNKNOWN, None, None)


class _InterfaceLookup:
    """Reads the interface facts at most once, and only when asked."""

    def __init__(self, piv: PivApplet, applet_status: AppletStatus | None = None) -> None:
        self._piv = piv
        self.facts: _InterfaceFacts | None = None
        if applet_status is not None:
            self.facts = self._from(applet_status)

    def __call__(self) -> _InterfaceFacts:
        if self.facts is None:
            status = None
            with contextlib.suppress(CryptnoxError, ValueError):
                status = inventory.read_status(self._piv)
            self.facts = self._from(status)
        return self.facts

    def _from(self, status: AppletStatus | None) -> _InterfaceFacts:
        session = self._piv.session
        name = getattr(session, "reader_name", None)
        atr = None
        with contextlib.suppress(Exception):
            atr = session.atr
        evidence = is_contactless_interface(name, atr)
        reader = (f"Reader '{name}'" if name else "This reader") if evidence else None
        if status is not None and status.reports_interface:
            interface = Interface.CONTACTLESS if status.contactless else Interface.CONTACT
            return _InterfaceFacts(interface, status.fips_mode, reader)
        # No evidence is not proof of contact.
        interface = Interface.CONTACTLESS if evidence else Interface.UNKNOWN
        return _InterfaceFacts(interface, status.fips_mode if status else None, reader)


def _with_reader(text: str, facts: _InterfaceFacts) -> str:
    return f"{text} {facts.reader} advertises a contactless interface." if facts.reader else text


# ------------------------------------------------------------------- rule table #
def _tries(sw: int) -> int | None:
    """X of 63CX, including the 63D0-63FF overflow of a count above 15."""
    if sw >> 8 == 0x63 and sw & 0xFF >= 0xC0:
        return (sw & 0xFF) - 0xC0
    return None


def _describe(sw: int) -> str:
    return describe_sw(sw >> 8, sw & 0xFF).message


#: PIN probe answers that show the card takes the PIN over this interface.
_PIN_ANSWERED = (
    Verdict.OK,
    Verdict.TRIES_LEFT,
    Verdict.NO_RETRY_LIMIT,
    Verdict.NO_TRIES_ON_INTERFACE,
)


def _refused_text(refused_ref: int, sw: int, facts: _InterfaceFacts, *, puk_alone: bool) -> str:
    if facts.interface is Interface.CONTACT:
        return _CONTACT_REFUSED.format(label=_LABEL.get(refused_ref, "verifier"), sw=f"{sw:04X}")
    if facts.interface is Interface.CONTACTLESS and facts.fips_mode:
        text = _FIPS_REFUSED
    elif refused_ref == PIN:
        text = _PIN_REFUSED
    elif puk_alone:
        text = _PUK_ALONE_REFUSED
    else:
        text = _PUK_REFUSED
    return _with_reader(text.format(sw=f"{sw:04X}"), facts)


def _judge(
    op: Op,
    ref: int,
    sw: int,
    lookup: _InterfaceLookup,
    *,
    pin_usable: bool = False,
) -> Outcome:
    """The one table from a status word (and, where it matters, the interface)."""
    rules = op.value
    counter = op.counter(ref)
    label = _LABEL.get(counter, f"{counter:02X}")

    def outcome(
        verdict: Verdict,
        message: str = "",
        *,
        tries: int | None = None,
        hint: str | None = None,
        recovery: str | None = None,
    ) -> Outcome:
        return Outcome(
            op,
            ref,
            sw,
            verdict,
            tries=tries,
            interface=(lookup.facts or _NO_FACTS).interface,
            message=message,
            hint=hint,
            recovery=recovery,
        )

    tries = _tries(sw)
    if sw == 0x9000:
        return outcome(Verdict.OK, "Success.")
    if tries == 0:
        return outcome(
            Verdict.NO_RETRY_LIMIT, f"Verification failed; this {label} has no retry limit."
        )
    if tries is not None:
        if rules.probe:
            return outcome(Verdict.TRIES_LEFT, tries=tries)
        return outcome(
            Verdict.WRONG, f"Verification failed; {tries} attempt(s) remaining.", tries=tries
        )
    if sw == 0x6983:
        facts = lookup()
        if facts.interface is Interface.CONTACT:
            return outcome(
                Verdict.BLOCKED, f"The {label} is blocked.", tries=0, recovery=_RECOVERY[counter]
            )
        return outcome(
            Verdict.NO_TRIES_ON_INTERFACE,
            f"No {label} tries left over this interface.",
            tries=0,
            hint=_with_reader(_NO_TRIES_HINT[counter], facts),
        )
    # RESET RETRY COUNTER answers 6A81 for any PUK access failure.
    refused_puk = op is Op.UNBLOCK and sw == 0x6A81
    if sw == 0x6982 or refused_puk:
        facts = lookup()
        if refused_puk and facts.interface is not Interface.CONTACTLESS:
            return outcome(Verdict.OTHER, _describe(sw))
        text = _refused_text(PUK if refused_puk else ref, sw, facts, puk_alone=pin_usable)
        if rules.probe:
            return outcome(Verdict.REFUSED_ON_INTERFACE, hint=text)
        return outcome(Verdict.REFUSED_ON_INTERFACE, text)
    if rules.probe:
        if sw in (0x6A88, 0x6A82, 0x6A80):
            return outcome(Verdict.NOT_CONFIGURED)
        return outcome(Verdict.OTHER, _describe(sw))
    if sw == 0x6A88:
        return outcome(Verdict.NO_VALUE, rules.no_value.format(label=label))
    if sw == 0x6A80:
        return outcome(Verdict.BAD_VALUE, rules.bad_value.format(label=label))
    if sw == 0x6984 and rules.sets_value:
        return outcome(
            Verdict.BAD_VALUE,
            f"The card refused the new {_LABEL.get(ref, label)}: it was used before.",
        )
    if sw == 0x6986 and op is Op.UNBLOCK:
        return outcome(Verdict.NOT_CONFIGURED, "This card has no PUK.")
    return outcome(Verdict.OTHER, _describe(sw))
