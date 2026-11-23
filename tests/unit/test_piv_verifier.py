# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The verifier rule table: each operation, status word and interface, and the one
length rule.

The applet facts behind the rows: ``63C0`` comes only from a verifier with no retry
limit; ``6983`` is a block over contact and "no tries left on this interface" over
contactless; ``6982`` is the access rule refusing this interface; RESET RETRY COUNTER
answers ``6A81`` for any PUK access failure.
"""

from __future__ import annotations

import pytest

from cryptnox_id_cli.applets.piv import verifier
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.applets.piv.verifier import Interface, Verdict
from cryptnox_id_cli.transport.errors import CryptnoxError, InputError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession

GET_STATUS = bytes.fromhex("00CB3F00055C032F475300")
CONTACT = bytes.fromhex("5306800107860100")
CONTACTLESS = bytes.fromhex("5306800107860101")
FIPS_CONTACTLESS = bytes.fromhex("53098001078601018701FF")
PICC_READER = "ACS ACR1552 1S CL Reader PICC 0"
CONTACT_READER = "ACS ACR39U ICC Reader 0"


class Card:
    """Answers verifier commands with chosen status words and the 2F4753 status read.

    ``status`` is the 2F4753 body, or None to refuse the read (6A82).
    """

    def __init__(self, sw=0x9000, *, probe=None, status=None, atr=b"\x3b\x00"):
        self.sw = sw
        self.probe = probe or {}
        self.status = status
        self.atr = atr
        self.frames: list[bytes] = []

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.frames.append(raw)
        if raw == GET_STATUS:
            if self.status is None:
                return [], 0x6A, 0x82
            return list(self.status), 0x90, 0x00
        probe = raw[1] == 0x20 and len(raw) == 4
        sw = self.probe.get(raw[3], 0x9000) if probe else self.sw
        return [], sw >> 8, sw & 0xFF

    def get_atr(self):
        if isinstance(self.atr, Exception):
            raise self.atr
        return self.atr

    def disconnect(self):
        pass

    @property
    def status_reads(self) -> int:
        return self.frames.count(GET_STATUS)


def _piv(card: Card, reader: str | None = CONTACT_READER) -> PivApplet:
    return PivApplet(CardSession(card, reader_name=reader))


# ------------------------------------------------------------------ status probe #
@pytest.mark.parametrize(
    ("sw", "verdict", "configured", "blocked", "verified", "tries"),
    [
        (0x9000, Verdict.OK, True, False, True, None),
        (0x63C3, Verdict.TRIES_LEFT, True, False, False, 3),
        (0x63D4, Verdict.TRIES_LEFT, True, False, False, 20),
        (0x63C0, Verdict.NO_RETRY_LIMIT, True, False, False, None),
        (0x6A88, Verdict.NOT_CONFIGURED, False, False, False, None),
        (0x6A82, Verdict.NOT_CONFIGURED, False, False, False, None),
        (0x6A80, Verdict.NOT_CONFIGURED, False, False, False, None),
        (0x6F00, Verdict.OTHER, None, None, False, None),
    ],
)
def test_probe_answers_that_need_no_interface(sw, verdict, configured, blocked, verified, tries):
    card = Card(probe={0x80: sw, 0x81: sw}, status=CONTACT)
    probe = verifier.status(_piv(card))
    for outcome in (probe.pin, probe.puk):
        assert outcome.verdict is verdict
        assert (outcome.configured, outcome.blocked, outcome.verified) == (
            configured,
            blocked,
            verified,
        )
        assert outcome.tries == tries and outcome.retries == tries
        assert outcome.refused is False
    assert card.status_reads == 0  # lazy: these answers do not depend on the interface
    assert probe.note is None


@pytest.mark.parametrize(
    ("status", "reader", "atr", "verdict", "interface"),
    [
        (CONTACT, CONTACT_READER, b"\x3b\x00", Verdict.BLOCKED, Interface.CONTACT),
        (CONTACTLESS, CONTACT_READER, b"\x3b\x00", Verdict.NO_TRIES_ON_INTERFACE, "contactless"),
        (None, PICC_READER, b"\x3b\x00", Verdict.NO_TRIES_ON_INTERFACE, "contactless"),
        (None, None, bytes.fromhex("3B8180018080"), Verdict.NO_TRIES_ON_INTERFACE, "contactless"),
        (None, CONTACT_READER, b"\x3b\x00", Verdict.NO_TRIES_ON_INTERFACE, "unknown"),
    ],
    ids=["contact", "applet-contactless", "reader-name", "atr", "no-evidence"],
)
def test_probe_6983_is_a_block_only_over_contact(status, reader, atr, verdict, interface):
    card = Card(probe={0x80: 0x6983, 0x81: 0x6983}, status=status, atr=atr)
    probe = verifier.status(_piv(card, reader))
    assert card.status_reads == 1  # one read for the pair
    assert card.frames.index(GET_STATUS) == 2  # after both probes
    pin = probe.pin
    assert pin.verdict is verdict and pin.interface == interface
    assert pin.tries == 0 and pin.configured is True
    if verdict is Verdict.BLOCKED:
        assert pin.blocked is True and "piv pin unblock" in (pin.recovery or "")
        assert pin.to_dict()["blocked"] is True
    else:
        assert pin.blocked is None and pin.to_dict()["blocked"] is None
        assert "contact tries may remain" in (pin.hint or "")
        assert "`piv pin status` from a contact reader" in (pin.hint or "")
    assert pin.to_dict()["retries_remaining"] == 0


def test_probe_6982_is_unknown_not_false_and_names_the_contact_reader():
    card = Card(probe={0x80: 0x6982, 0x81: 0x6982}, status=CONTACTLESS)
    probe = verifier.status(_piv(card, PICC_READER))
    pin = probe.pin
    assert pin.verdict is Verdict.REFUSED and pin.refused is True
    assert pin.configured is None and pin.blocked is None and pin.tries is None
    assert pin.to_dict() == {
        "ref": "80",
        "configured": None,
        "blocked": None,
        "verified": False,
        "retries_remaining": None,
        "refused_on_interface": True,
        "state": "refused_on_interface",
        "interface": "contactless",
    }
    assert probe.note_scope == "PIN/PUK state"
    assert "contact-only" in (probe.note or "") and "contact reader" in (probe.note or "")
    assert (probe.note or "").endswith(
        f"Reader '{PICC_READER}' advertises a contactless interface."
    )


def test_probe_6982_on_the_fips_mode_build_over_contactless_names_secure_messaging():
    card = Card(probe={0x80: 0x6982, 0x81: 0x6982}, status=FIPS_CONTACTLESS)
    probe = verifier.status(_piv(card, PICC_READER))
    assert probe.pin.fips_mode is True
    assert "FIPS-mode build" in (probe.note or "") and "secure messaging" in (probe.note or "")


def test_probe_6982_on_the_puk_alone_does_not_assume_a_profile():
    card = Card(probe={0x80: 0x63C3, 0x81: 0x6982}, status=CONTACTLESS)
    probe = verifier.status(_piv(card, PICC_READER))
    assert probe.pin.verdict is Verdict.TRIES_LEFT and probe.pin.interface == "contactless"
    assert probe.puk.refused is True
    assert probe.note_scope == "PUK state"
    note = probe.note or ""
    assert "refuses PUK commands" in note and "accepts the PIN" in note
    assert "ms-logon-nfc" not in note


@pytest.mark.parametrize("pin_sw", [0x6A88, 0x6F00])
def test_probe_6982_on_the_puk_claims_nothing_about_a_pin_that_did_not_answer(pin_sw):
    card = Card(probe={0x80: pin_sw, 0x81: 0x6982}, status=CONTACTLESS)
    probe = verifier.status(_piv(card, PICC_READER))
    assert probe.puk is not None and probe.puk.refused is True
    note = probe.note or ""
    assert "refuses the PUK" in note and "accepts the PIN" not in note


def test_a_status_without_the_interface_tag_is_not_proof_of_contact():
    card = Card(probe={0x80: 0x6983, 0x81: 0x63C3}, status=bytes.fromhex("5303800107"))
    pin = verifier.status(_piv(card, PICC_READER)).pin
    assert pin.verdict is Verdict.NO_TRIES_ON_INTERFACE and pin.interface == "contactless"
    card = Card(probe={0x80: 0x6983, 0x81: 0x63C3}, status=bytes.fromhex("5303800107"))
    pin = verifier.status(_piv(card, CONTACT_READER)).pin
    assert pin.verdict is Verdict.NO_TRIES_ON_INTERFACE and pin.interface == "unknown"


class _PukGone(Card):
    def transmit(self, apdu):
        if bytes(apdu) == bytes.fromhex("00200081"):
            raise CryptnoxError("gone")
        return super().transmit(apdu)


def test_a_failed_puk_probe_raises_unless_partial():
    with pytest.raises(CryptnoxError):
        verifier.status(_piv(_PukGone(probe={0x80: 0x63C3})))
    probe = verifier.status(_piv(_PukGone(probe={0x80: 0x63C3})), partial=True)
    assert probe.pin.tries == 3 and probe.puk is None
    assert probe.to_dict()["puk"] is None


def test_a_status_the_caller_already_read_costs_no_extra_command():
    from cryptnox_id_cli.applets.piv import inventory

    card = Card(probe={0x80: 0x63C3, 0x81: 0x6983}, status=None)
    known = inventory.parse_status(CONTACT)
    probe = verifier.status(_piv(card), applet_status=known)
    assert card.status_reads == 0
    assert probe.puk.verdict is Verdict.BLOCKED
    assert probe.pin.interface == "contact"


# ------------------------------------------------------- VERIFY / CRD / RRC rows #
DATA_ROWS = [
    (0x9000, Verdict.OK, None),
    (0x63C5, Verdict.WRONG, 5),
    (0x63D2, Verdict.WRONG, 18),
    (0x63C0, Verdict.NO_RETRY_LIMIT, None),
    (0x6A88, Verdict.NO_VALUE, None),
    (0x6A80, Verdict.BAD_VALUE, None),
    (0x6F00, Verdict.OTHER, None),
]


def _run(op: str, card: Card, reader: str | None = CONTACT_READER):
    piv = _piv(card, reader)
    if op == "verify":
        return verifier.verify(piv, b"123456")
    if op == "change-pin":
        return verifier.change(piv, verifier.PIN, b"123456", b"654321")
    if op == "change-puk":
        return verifier.change(piv, verifier.PUK, b"12345678", b"87654321")
    return verifier.unblock(piv, b"12345678", b"654321")


OPS = ["verify", "change-pin", "change-puk", "unblock"]


@pytest.mark.parametrize("op", OPS)
@pytest.mark.parametrize(("sw", "verdict", "tries"), DATA_ROWS)
def test_value_commands_without_the_interface(op, sw, verdict, tries):
    card = Card(sw, status=CONTACT)
    outcome = _run(op, card)
    assert outcome.verdict is verdict and outcome.tries == tries
    assert outcome.ok is (sw == 0x9000)
    assert card.status_reads == 0
    payload = outcome.payload()
    assert payload["verified" if op == "verify" else "changed"] is outcome.ok
    assert payload["sw"] == f"{sw:04X}"
    assert ("retries_remaining" in payload) is (verdict is Verdict.WRONG)
    assert "blocked" not in payload and "recovery" not in payload
    if verdict is Verdict.WRONG:
        assert payload["message"] == f"Verification failed; {tries} attempt(s) remaining."
    if verdict is Verdict.NO_RETRY_LIMIT:
        assert "no retry limit" in outcome.message


@pytest.mark.parametrize("op", OPS)
def test_value_6983_over_contact_is_a_block_with_its_recovery(op):
    card = Card(0x6983, status=CONTACT)
    outcome = _run(op, card)
    assert card.status_reads == 1 and card.frames[-1] == GET_STATUS
    assert outcome.verdict is Verdict.BLOCKED and outcome.blocked is True
    payload = outcome.payload()
    assert payload["blocked"] is True
    expect = "piv pin unblock" if op in ("verify", "change-pin") else "no recovery path"
    assert expect in payload["recovery"]
    assert outcome.label == ("PIN" if op in ("verify", "change-pin") else "PUK")


@pytest.mark.parametrize("op", OPS)
def test_value_6983_over_contactless_leaves_the_contact_tries_open(op):
    card = Card(0x6983, status=CONTACTLESS)
    outcome = _run(op, card, PICC_READER)
    assert outcome.verdict is Verdict.NO_TRIES_ON_INTERFACE
    assert outcome.blocked is None and outcome.tries == 0
    payload = outcome.payload()
    assert "blocked" not in payload and "recovery" not in payload
    label = outcome.label
    assert payload["message"] == f"No {label} tries left over this interface."
    assert payload["hint"].startswith(f"The {label} is blocked, or ")
    assert payload["hint"].endswith(f"Reader '{PICC_READER}' advertises a contactless interface.")


@pytest.mark.parametrize("op", OPS)
def test_value_6982_names_the_interface_never_the_admin_key(op):
    outcome = _run(op, Card(0x6982, status=CONTACTLESS), PICC_READER)
    assert outcome.verdict is Verdict.REFUSED
    assert "contact reader" in outcome.message.lower()
    assert "admin key" not in outcome.message
    assert PICC_READER in outcome.message
    if op == "change-puk":
        assert "refuses the PUK" in outcome.message


def test_change_6984_is_a_new_value_used_before():
    outcome = _run("change-pin", Card(0x6984))
    assert outcome.verdict is Verdict.BAD_VALUE and "used before" in outcome.message


def test_unblock_counts_the_puk_tries():
    outcome = _run("unblock", Card(0x63C2))
    assert outcome.ref == verifier.PIN and outcome.label == "PUK" and outcome.tries == 2


def test_unblock_6a81_over_contactless_is_the_puk_refused_there():
    card = Card(0x6A81, status=CONTACTLESS)
    outcome = _run("unblock", card, PICC_READER)
    assert card.status_reads == 1
    assert outcome.verdict is Verdict.REFUSED
    assert "refuses the PUK over this interface (SW=6A81)" in outcome.message


def test_unblock_6a81_over_contact_keeps_its_plain_meaning():
    outcome = _run("unblock", Card(0x6A81, status=CONTACT))
    assert outcome.verdict is Verdict.OTHER
    assert outcome.message == "Function not supported by this applet."


def test_unblock_6986_is_a_card_without_a_puk():
    outcome = _run("unblock", Card(0x6986))
    assert outcome.verdict is Verdict.NOT_CONFIGURED and "no PUK" in outcome.message


def test_the_reader_note_is_kept_after_the_card_is_gone():
    card = Card(0x6983, status=None, atr=bytes.fromhex("3B8180018080"))
    outcome = _run("change-pin", card, None)
    card.atr = RuntimeError("disconnected")
    assert outcome.reader == "This reader"
    assert outcome.hint and outcome.hint.endswith("This reader advertises a contactless interface.")


# ----------------------------------------------------------------- require_pin #
def test_require_pin_sends_nothing_after_a_correct_pin():
    card = Card(0x9000, status=CONTACT)
    verifier.require_pin(_piv(card), b"123456")
    assert len(card.frames) == 1


@pytest.mark.parametrize(
    ("sw", "status", "words"),
    [
        (0x63C0, CONTACT, "no retry limit"),
        (0x6983, CONTACT, "The PIN is blocked. Recover it with `piv pin unblock`"),
        (0x6983, None, "The PIN is blocked, or the card's contactless limit for it is reached"),
        (0x6982, CONTACTLESS, "contact reader"),
    ],
)
def test_require_pin_raises_the_same_error_type_as_before(sw, status, words):
    with pytest.raises(CryptnoxError) as exc:
        verifier.require_pin(_piv(Card(sw, status=status)), b"123456")
    assert type(exc.value) is CryptnoxError and exc.value.exit_code == 1
    assert f"(SW={sw:04X})" in str(exc.value) and words in str(exc.value)


@pytest.mark.parametrize(
    ("sw", "words"),
    [(0x63C5, "5 attempt(s) remaining"), (0x6A88, "holds no value"), (0x6A82, "not found")],
)
def test_require_pin_other_answers_are_status_word_errors(sw, words):
    with pytest.raises(StatusWordError) as exc:
        verifier.require_pin(_piv(Card(sw)), b"123456", context="VERIFY PIN (test)")
    assert exc.value.exit_code == 6 and exc.value.context == "VERIFY PIN (test)"
    assert words in str(exc.value) and "blocked" not in str(exc.value)


# ------------------------------------------------------------------------- pad #
def test_pad_fills_to_eight_bytes_with_ff():
    assert verifier.pad(b"1234") == b"1234\xff\xff\xff\xff"
    assert verifier.pad(b"12345678") == b"12345678"
    assert verifier.VALUE_LENGTH == 8


@pytest.mark.parametrize("value", [b"", b"123", b"123456789"])
def test_pad_refuses_a_value_the_card_cannot_take(value):
    with pytest.raises(InputError) as exc:
        verifier.pad(value, "PIN")
    assert exc.value.exit_code == 2
    assert "4 to 8" in str(exc.value) and "Nothing was sent" in str(exc.value)


@pytest.mark.parametrize("op", OPS)
def test_a_value_that_does_not_fit_sends_nothing(op):
    card = Card()
    piv = _piv(card)
    with pytest.raises(InputError):
        if op == "verify":
            verifier.verify(piv, b"123456789")
        elif op == "change-pin":
            verifier.change(piv, verifier.PIN, b"123456", b"")
        elif op == "change-puk":
            verifier.change(piv, verifier.PUK, b"123", b"87654321")
        else:
            verifier.unblock(piv, b"12345678", b"123456789")
    assert card.frames == []


def test_values_are_registered_with_the_redactor():
    card = Card()
    piv = _piv(card)
    verifier.change(piv, verifier.PIN, b"123456", b"654321")
    masked = piv.session.redactor.mask(card.frames[0].hex().upper())
    assert "313233343536" not in masked and "363534333231" not in masked
