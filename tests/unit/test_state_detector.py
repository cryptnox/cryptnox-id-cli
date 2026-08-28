"""Transcript test: the detector must classify the real ACS card correctly."""

from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import (
    CardPresence,
    DesfireState,
    FidoState,
    PivState,
)
from cryptnox_id_cli.transport.pcsc import CardSession


def test_detect_real_acs_state(acs_session):
    st = StateDetector(acs_session).detect()
    assert st.presence == CardPresence.PRESENT
    assert st.piv == PivState.PARTIALLY_PERSONALIZED
    assert st.piv_apt is not None and st.piv_apt.label == "OpenFIPS201"
    assert st.piv_pin is not None and st.piv_pin.configured and st.piv_pin.retries == 5
    assert st.piv_puk is not None and st.piv_puk.configured and st.piv_puk.retries == 5
    assert st.piv_objects["printed"] is True
    assert st.piv_objects["chuid"] is False
    assert st.fido == FidoState.BLOCKED_BY_OS
    assert st.desfire == DesfireState.NEEDS_CONTACTLESS_READER


def test_piv_only_probe_skips_others(acs_session):
    st = StateDetector(acs_session, probe_fido=False, probe_desfire=False).detect()
    assert st.piv == PivState.PARTIALLY_PERSONALIZED
    assert st.fido == FidoState.UNKNOWN
    assert st.desfire == DesfireState.UNKNOWN


def test_blocked_fido_recorded_as_note(acs_session):
    st = StateDetector(acs_session).detect()
    assert any("Administrator" in n for n in st.notes)
    assert any("contactless" in n.lower() for n in st.notes)


def test_desfire_no_answer_on_contact_interface_says_wrong_reader(acs_transcript, mock_connection):
    """Contact reader (D600 contact ATR, no PICC marker): the advice stays 'use a
    contactless reader' - that really is the problem there."""
    conn = mock_connection(acs_transcript["atr"], {}, [])
    st = StateDetector(
        CardSession(conn, reader_name="ACS ACR39U ICC Reader 0"),
        probe_fido=False,
        probe_genuine=False,
    ).detect()
    assert st.desfire == DesfireState.NEEDS_CONTACTLESS_READER
    assert any("use a DESFire-capable contactless" in n for n in st.notes)


def test_desfire_no_answer_on_contactless_interface_does_not_recommend_one(mock_connection):
    """Regression (Windows round 2026-08-18): on the ACR1552 PICC interface the probe
    failure was reported as 'needs a contactless reader (the contact interface cannot
    reach it)' - recommending the reader already in use. On a contactless interface the
    diagnosis must point at presentation/reader capability instead."""
    conn = mock_connection("3B8180018080", {}, [])  # PC/SC-composed PICC ATR
    st = StateDetector(
        CardSession(conn, reader_name="ACS ACR1552 1S CL Reader PICC 0"),
        probe_fido=False,
        probe_genuine=False,
    ).detect()
    assert st.desfire == DesfireState.NO_ANSWER_CONTACTLESS
    assert not any("use a DESFire-capable contactless" in n for n in st.notes)
    assert any("re-present" in n.lower() for n in st.notes)
