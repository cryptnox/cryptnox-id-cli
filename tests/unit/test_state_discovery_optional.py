"""The PIV state reads PivPersonalized without a Discovery Object.

Discovery is optional in PIV and no built-in profile creates it; the detector must
not hold a complete card at PivPartiallyPersonalized because of it."""

from cryptnox_id_cli.applets.piv import objects as piv_obj
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.detector import _MANDATORY
from cryptnox_id_cli.state.model import PivState
from cryptnox_id_cli.transport.pcsc import CardSession

CHUID = "00CB3FFF055C035FC10200"
CCC = "00CB3FFF055C035FC10700"
DISCOVERY = "00CB3FFF035C017E00"
PRESENT = "5303AABBCC|9000"


def _detect(mock_connection, transcript, extra):
    exchanges = {**transcript["exchanges"], **extra}
    conn = mock_connection(transcript["atr"], exchanges, [])
    return StateDetector(
        CardSession(conn), probe_fido=False, probe_desfire=False, probe_genuine=False
    ).detect()


def test_mandatory_set_comes_from_the_object_registry():
    assert set(_MANDATORY) == {o.name for o in piv_obj.PIV_OBJECTS if o.mandatory}
    assert "discovery" not in _MANDATORY


def test_chuid_ccc_and_pin_make_the_card_personalized(mock_connection, acs_transcript):
    st = _detect(mock_connection, acs_transcript, {CHUID: PRESENT, CCC: PRESENT})
    assert st.piv == PivState.PERSONALIZED
    assert st.piv_objects["discovery"] is False


def test_discovery_is_still_reported_when_present(mock_connection, acs_transcript):
    st = _detect(
        mock_connection, acs_transcript, {CHUID: PRESENT, CCC: PRESENT, DISCOVERY: "7E00|9000"}
    )
    assert st.piv == PivState.PERSONALIZED
    assert st.piv_objects["discovery"] is True


def test_missing_ccc_keeps_the_card_partially_personalized(mock_connection, acs_transcript):
    st = _detect(mock_connection, acs_transcript, {CHUID: PRESENT})
    assert st.piv == PivState.PARTIALLY_PERSONALIZED
