# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""6982 on the PIN probe or on VERIFY means "not over this interface", not "not set".

A card personalized over a contactless reader runs ``set-pin`` and ``set-puk`` fine
(admin channel), then the first command that presents the PIN fails with 6982 while
``piv status`` claims ``PIN (80): not set``. The built-in profiles create the PIN and
PUK verifiers contact-only, so a contactless reader always gets 6982; the CLI must say
so instead of reporting an unset PIN.
"""

from __future__ import annotations

import json

import _cardfakes
import pytest

from cryptnox_id_cli.applets.piv import verifier
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.cli.commands.piv import _sign_with_session
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import PivState
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.pcsc import CardSession

SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
PROBE_PIN = "00200080"
PROBE_PUK = "00200081"
VERIFY_123456 = "0020008008313233343536FFFF"
PICC_ATR = "3B8180018080"  # PC/SC-composed contactless ATR
PICC_READER = "ACS ACR1552 1S CL Reader PICC 0"
CONTACT_ATR = "3BD518FF81B1FE451FC38073C821106F"  # a wired card's own ATR
CONTACT_READER = "ACS ACR39U ICC Reader 0"
REFUSED = "not usable over this interface"


def _card(mock_connection, atr: str, pin_sw: str, puk_sw: str):
    exchanges = {SELECT_PIV: f"{APT}|9000", PROBE_PIN: f"|{pin_sw}", PROBE_PUK: f"|{puk_sw}"}
    return mock_connection(atr, exchanges, [])


def _refusing_card(mock_connection, atr: str = PICC_ATR):
    return _card(mock_connection, atr, "6982", "6982")


def _detect(conn, reader_name: str):
    return StateDetector(
        CardSession(conn, reader_name=reader_name),
        probe_fido=False,
        probe_desfire=False,
        probe_genuine=False,
    ).detect()


# ---------------------------------------------------------------- probe parsing #
def _probe(mock_connection, sw: str, atr: str = CONTACT_ATR, reader: str = CONTACT_READER):
    conn = _card(mock_connection, atr, sw, sw)
    return verifier.status(PivApplet(CardSession(conn, reader_name=reader)))


def test_probe_6982_is_refused_and_unknown_not_unset(mock_connection):
    st = _probe(mock_connection, "6982").pin
    assert st.refused is True
    assert st.configured is None and st.blocked is None and st.tries is None
    assert st.to_dict()["refused_on_interface"] is True


@pytest.mark.parametrize("sw", ["9000", "63C6", "63C0", "6983", "6A88", "6A82", "6F00"])
def test_other_probe_answers_are_not_refused(mock_connection, sw):
    st = _probe(mock_connection, sw).pin
    assert st.refused is False
    assert st.to_dict()["refused_on_interface"] is False


# -------------------------------------------------------------- VERIFY failures #
def _require(mock_connection, sw: str, atr: str = CONTACT_ATR, reader: str = CONTACT_READER):
    conn = mock_connection(atr, {VERIFY_123456: f"|{sw}"}, [])
    with pytest.raises(CryptnoxError) as exc:
        verifier.require_pin(PivApplet(CardSession(conn, reader_name=reader)), b"123456")
    return str(exc.value)


def test_require_pin_6982_explains_the_interface(mock_connection):
    msg = _require(mock_connection, "6982")
    assert "6982" in msg and "contact reader" in msg
    # The generic status-word text points at a PIN or admin-key problem that is not there.
    assert "authenticate with the admin key" not in msg


def test_require_pin_names_a_contactless_reader(mock_connection):
    assert PICC_READER in _require(mock_connection, "6982", PICC_ATR, PICC_READER)


def test_hint_stays_generic_without_contactless_evidence(mock_connection):
    msg = _require(mock_connection, "6982")
    assert "contact-only" in msg and "advertises" not in msg


def test_require_pin_63c0_is_no_retry_limit(mock_connection):
    msg = _require(mock_connection, "63C0")
    assert "no retry limit" in msg and "blocked" not in msg


def test_sign_with_session_6982_names_the_reader(mock_connection):
    conn = mock_connection(PICC_ATR, {SELECT_PIV: f"{APT}|9000", VERIFY_123456: "|6982"}, [])
    session = CardSession(conn, reader_name=PICC_READER)
    with pytest.raises(CryptnoxError) as exc:
        _sign_with_session(session, 0x9C, 0x11, b"123456", lambda sign: sign(b"\0" * 32))
    assert PICC_READER in str(exc.value) and "contact reader" in str(exc.value)


# ---------------------------------------------------------------- state detector #
@pytest.mark.parametrize(
    ("pin_sw", "puk_sw"), [("6982", "6982"), ("6982", "6A88"), ("6A88", "6982")]
)
def test_detector_notes_the_interface_and_keeps_the_card_structured(
    mock_connection, pin_sw, puk_sw
):
    st = _detect(_card(mock_connection, PICC_ATR, pin_sw, puk_sw), PICC_READER)
    assert (st.piv_pin and st.piv_pin.refused) or (st.piv_puk and st.piv_puk.refused)
    assert any("contact reader" in n for n in st.notes)
    # No object answered (6A82) and a probe was refused: that verifier exists (a missing
    # one answers 6A88), so this is not a pre-personalized card.
    assert st.piv == PivState.PARTIALLY_PERSONALIZED


def test_detector_missing_verifiers_still_read_as_pre_personalized(mock_connection):
    st = _detect(_card(mock_connection, CONTACT_ATR, "6A88", "6A88"), CONTACT_READER)
    assert st.piv == PivState.PRE_PERSONALIZED
    assert not any("contact reader" in n for n in st.notes)


# ------------------------------------------------------------------- CLI output #
def test_pin_status_cli_says_not_usable_over_this_interface(monkeypatch, mock_connection):
    _cardfakes.wire_session(monkeypatch, _refusing_card(mock_connection), reader_name=PICC_READER)
    res = _cardfakes.run(["piv", "pin", "status"])
    assert res.exit_code == 0, res.output
    assert REFUSED in res.output
    assert "not configured" not in res.output
    assert "contact reader" in res.output and PICC_READER in res.output

    res_json = _cardfakes.run(["--json", "piv", "pin", "status"])
    assert res_json.exit_code == 0, res_json.output
    payload = json.loads(res_json.stdout)
    assert payload["pin"]["refused_on_interface"] is True
    assert payload["puk"]["refused_on_interface"] is True
    assert "contact reader" in payload["note"] and PICC_READER in payload["note"]


def test_pin_status_cli_unchanged_for_a_configured_pin(monkeypatch, mock_connection):
    conn = _card(mock_connection, CONTACT_ATR, "63C6", "63C6")
    _cardfakes.wire_session(monkeypatch, conn, reader_name=CONTACT_READER)
    res = _cardfakes.run(["piv", "pin", "status"])
    assert res.exit_code == 0, res.output
    assert "6 tries left" in res.output
    assert "interface" not in res.output
    payload = json.loads(_cardfakes.run(["--json", "piv", "pin", "status"]).stdout)
    assert "note" not in payload
    assert payload["pin"]["refused_on_interface"] is False


def test_piv_status_cli_marks_pin_not_usable(monkeypatch, mock_connection):
    _cardfakes.wire_session(monkeypatch, _refusing_card(mock_connection), reader_name=PICC_READER)
    res = _cardfakes.run(["piv", "status"])
    assert res.exit_code == 0, res.output
    assert REFUSED in res.output
    assert "not set" not in res.output
    assert "contact reader" in res.output
    payload = json.loads(_cardfakes.run(["--json", "piv", "status"]).stdout)
    assert payload["pin"]["refused_on_interface"] is True


def test_piv_status_cli_unchanged_on_a_contact_reader(monkeypatch, mock_connection):
    conn = _card(mock_connection, CONTACT_ATR, "63C6", "63C0")
    _cardfakes.wire_session(monkeypatch, conn, reader_name=CONTACT_READER)
    res = _cardfakes.run(["piv", "status"])
    assert res.exit_code == 0, res.output
    assert "PIN (80): set, 6 tries left" in res.output
    assert "PUK (81): set, no retry limit" in res.output
    assert REFUSED not in res.output


def test_pin_verify_cli_explains_6982(monkeypatch, mock_connection):
    exchanges = {SELECT_PIV: f"{APT}|9000", VERIFY_123456: "|6982"}
    conn = mock_connection(PICC_ATR, exchanges, [])
    _cardfakes.wire_session(monkeypatch, conn, reader_name=PICC_READER)
    res = _cardfakes.run(["piv", "pin", "verify", "--pin", "123456"])
    assert "PIN not verified" in res.output
    assert "contact reader" in res.output and PICC_READER in res.output
    assert "authenticate with the admin key" not in res.output
    res_json = _cardfakes.run(["--json", "piv", "pin", "verify", "--pin", "123456"])
    payload = json.loads(res_json.stdout)
    assert payload["verified"] is False and payload["sw"] == "6982"
    assert PICC_READER in payload["message"]


def test_validate_cli_marks_pin_unknown(monkeypatch, mock_connection):
    _cardfakes.wire_session(monkeypatch, _refusing_card(mock_connection), reader_name=PICC_READER)
    res = _cardfakes.run(["piv", "validate"])
    assert res.exit_code == 0, res.output
    assert "unknown" in res.output
    payload = json.loads(_cardfakes.run(["--json", "piv", "validate"]).stdout)
    pin_check = next(c for c in payload["checks"] if c["check"] == "PIN configured")
    assert pin_check["ok"] is False and pin_check["unknown"] is True
    assert "refuses PIN and PUK commands over this interface" in pin_check["detail"]
    assert PICC_READER in pin_check["detail"]


def test_quickstart_dry_run_refuses_on_a_refused_probe(monkeypatch, mock_connection):
    _cardfakes.wire_session(monkeypatch, _refusing_card(mock_connection), reader_name=PICC_READER)
    res = _cardfakes.run(["piv", "quickstart", "--dry-run"])
    assert res.exit_code != 0
    assert "cannot tell whether the PIN and PUK are set" in res.output
    assert PICC_READER in res.output
    assert "set-pin" not in res.output


def test_quickstart_names_the_puk_alone_when_only_the_puk_is_refused(monkeypatch, mock_connection):
    conn = _card(mock_connection, PICC_ATR, "63C3", "6982")
    _cardfakes.wire_session(monkeypatch, conn, reader_name=PICC_READER)
    res = _cardfakes.run(["piv", "quickstart", "--dry-run"])
    assert res.exit_code != 0
    assert "refuses PUK commands over this interface" in res.output
    assert "refuses PIN and PUK" not in res.output
