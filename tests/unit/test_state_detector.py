"""Transcript test: the detector must classify the real ACS card correctly."""

from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import (
    CardPresence,
    DesfireState,
    FidoState,
    PivState,
)
from cryptnox_id_cli.transport.pcsc import CardSession

SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
GET_STATUS = "00CB3F00055C032F475300"
STATUS_SECURED = "531880010F8101008201008301008401008501008601008701FF"


def test_secured_flag_comes_from_the_applet_status_object(mock_connection):
    exchanges = {SELECT_PIV: f"{APT}|9000", GET_STATUS: f"{STATUS_SECURED}|9000"}
    conn = mock_connection("3B00", exchanges, [])
    st = StateDetector(
        CardSession(conn), probe_fido=False, probe_desfire=False, probe_genuine=False
    ).detect()
    assert st.piv_secured is True
    # Finalize locks the structure only; the personalization ladder stays separate.
    assert st.piv == PivState.PRE_PERSONALIZED
    assert st.to_dict()["piv"]["secured"] is True
    assert not any("SECURED" in n for n in st.notes)


def test_secured_flag_is_none_when_the_applet_has_no_status_object(acs_session):
    st = StateDetector(
        acs_session, probe_fido=False, probe_desfire=False, probe_genuine=False
    ).detect()
    assert st.piv_secured is None
    assert any("SECURED" in n for n in st.notes)


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
