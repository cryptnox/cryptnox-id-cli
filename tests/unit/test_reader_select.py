"""Reader selection across multiple readers (the pure select_reader logic)."""

import pytest

from cryptnox_id_cli.transport.errors import NoReadersError, ReaderNotFoundError
from cryptnox_id_cli.transport.pcsc import ReaderInfo, is_contactless_interface, select_reader


def _r(index, name, present=True):
    return ReaderInfo(index, name, present, b"")


# The user's real setup: a contactless and a contact ACS reader plus a Cryptnox
# NFC reader, all with a card, plus an empty ACS SAM slot.
DUAL_ACS = [
    _r(0, "ACS ACR1252 1S CL Reader PICC 0"),
    _r(1, "ACS ACR1252 1S CL Reader SAM 0", present=False),
    _r(2, "ACS ACR39U ICC Reader 0"),
    _r(3, "Cryptnox NFC 0"),
]


def test_no_preference_refuses_to_guess_between_loaded_preferred_readers():
    with pytest.raises(ReaderNotFoundError, match="Multiple Cryptnox/ACS readers have a card"):
        select_reader(DUAL_ACS, None)


def test_index_selects_exact_reader():
    assert select_reader(DUAL_ACS, "0") == "ACS ACR1252 1S CL Reader PICC 0"
    assert select_reader(DUAL_ACS, "2") == "ACS ACR39U ICC Reader 0"


def test_substring_picks_contactless_vs_contact():
    assert "PICC" in select_reader(DUAL_ACS, "PICC")
    assert "ICC Reader" in select_reader(DUAL_ACS, "ICC Reader")
    assert "ACR39U" in select_reader(DUAL_ACS, "acr39u")  # case-insensitive


def test_ambiguous_substring_errors_not_first_match():
    # "ACR1252" matches both the PICC and the SAM line.
    with pytest.raises(ReaderNotFoundError, match="ambiguous"):
        select_reader(DUAL_ACS, "ACR1252")


def test_bad_index_and_no_match_error():
    with pytest.raises(ReaderNotFoundError, match="No reader at index 9"):
        select_reader(DUAL_ACS, "9")
    with pytest.raises(ReaderNotFoundError, match="No reader matching"):
        select_reader(DUAL_ACS, "Feitian")


def test_single_loaded_acs_auto_selected():
    infos = [
        _r(0, "ACS ACR1252 1S CL Reader PICC 0"),
        _r(1, "ACS ACR1252 1S CL Reader SAM 0", present=False),
        _r(2, "ACS ACR39U ICC Reader 0", present=False),
    ]
    assert select_reader(infos, None) == "ACS ACR1252 1S CL Reader PICC 0"


def test_single_acs_without_card_still_selected_for_clear_nocard_error():
    infos = [_r(0, "ACS ACR39U ICC Reader 0", present=False)]
    assert select_reader(infos, None) == "ACS ACR39U ICC Reader 0"


def test_no_readers_raises():
    with pytest.raises(NoReadersError):
        select_reader([], None)


def test_cryptnox_branded_reader_auto_selected():
    # The Cryptnox-branded units ("CryptnoxCR" contact, "Cryptnox NFC" contactless)
    # are the product's own readers - the no-preference default must pick them
    # (regression: the old ACS-only hints skipped them).
    infos = [_r(0, "Cryptnox NFC 0"), _r(1, "Feitian R502 0")]
    assert select_reader(infos, None) == "Cryptnox NFC 0"
    infos = [_r(0, "CryptnoxCR 0"), _r(1, "Feitian R502 0", present=False)]
    assert select_reader(infos, None) == "CryptnoxCR 0"


def test_loaded_cryptnox_and_acs_refuse_to_guess():
    infos = [_r(0, "CryptnoxCR 0"), _r(1, "ACS ACR39U ICC Reader 0")]
    with pytest.raises(ReaderNotFoundError, match="Multiple Cryptnox/ACS readers have a card"):
        select_reader(infos, None)


def test_no_preferred_multiple_requires_explicit_choice():
    infos = [_r(0, "Feitian R502 0"), _r(1, "Generic USB2.0-CRW 0")]
    with pytest.raises(ReaderNotFoundError, match="no Cryptnox/ACS reader detected"):
        select_reader(infos, None)


# ------------------------------------------------- interface classification --- #
# Regression (Windows contactless round 2026-08-18): `doctor` on the ACR1552 PICC
# interface answered "needs a contactless reader" - it assumed contact instead of
# checking. The classifier feeds the DESFire diagnosis, so name and ATR evidence
# each have to work alone.

_D600_CONTACT_ATR = bytes.fromhex("3BFA1300FF910131FE000031C173C84000009000D2")
_D321_CONTACT_ATR = bytes.fromhex("3BD518FF81 91FE1FC38073C821100A".replace(" ", ""))
_PICC_ATR = bytes.fromhex("3B8180018080")  # PC/SC v2 Part 3 construction for ISO 14443-4


def test_contactless_by_reader_name_alone():
    for name in (
        "ACS ACR1552 1S CL Reader PICC 0",
        "ACS ACR1252 1S CL Reader PICC 0",
        "HID Global OMNIKEY 5422CL Smartcard Reader 01",
        "SCM Microsystems Inc. SCL011 Contactless Reader 0",
    ):
        assert is_contactless_interface(name, None), name


def test_contact_readers_are_not_contactless():
    for name, atr in (
        (
            "Generic USB2.0-CRW [Smart Card Reader Interface] (20070818000000000) 00 00",
            _D600_CONTACT_ATR,
        ),
        ("ACS ACR39U ICC Reader 0", _D600_CONTACT_ATR),
        ("Alcor Micro AU9560 00 00", _D321_CONTACT_ATR),
    ):
        assert not is_contactless_interface(name, atr), name


def test_contactless_by_atr_alone_when_name_is_unhelpful():
    # A vendor name with no PICC/CL marker must not hide a contactless session:
    # the PC/SC-composed 3B 8x 80 01 ATR is the tell.
    assert is_contactless_interface("Some Vendor Reader 0", _PICC_ATR)
    assert is_contactless_interface(None, _PICC_ATR)


def test_no_evidence_means_not_contactless():
    assert not is_contactless_interface(None, None)
    assert not is_contactless_interface("Some Vendor Reader 0", b"\x3b")  # truncated ATR
