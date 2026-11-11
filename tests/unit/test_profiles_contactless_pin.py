"""A PIN usable over the contactless interface, and the ``ms-logon-nfc`` profile. No card.

Windows logs a user on with a PIV card over NFC when three things hold: the 9A key is
RSA, the 9A certificate, the CHUID and the CCC can be read over the contactless
interface, and the PIN is accepted there in clear, because the driver Windows ships has
no secure messaging. The applet build with FIPS mode off accepts such a PIN verifier
(contactless mode ``3F``); the FIPS-mode build refuses it with ``6E1C``.

The verifier bytes below are the ones the working card was provisioned with on
2026-10-20 (contact ``3F``, contactless ``3F``, 6 tries of which 3 over contactless).
"""

from __future__ import annotations

import json

import pytest
import yaml
from _cardfakes import run, wire_session

from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv import preperso as pp
from cryptnox_id_cli.applets.piv import profiles
from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.apdu import Response

PIN_CONTACT_ONLY = "65188B01808C013F8D01008E01068F0108900106910100920100"
PIN_OVER_NFC = "65188B01808C013F8D013F8E01068F0108900106910103920100"
PUK_CONTACT_ONLY = "65188B01818C013F8D01008E01088F0108900106910100920100"

ATR = "3BD518FF81B1FE451FC38073C821106F"
SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
    "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
    "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
GET_STATUS = "00CB3F00055C032F475300"
STATUS_FIPS_OFF = "5318800107810100820100830100840100850100860100870100"
STATUS_FIPS = "53188001078101008201008301008401008501008601008701FF"

LOAD = ["factory", "piv", "preperso", "load-config"]


def ops(name: str) -> dict[str, str]:
    """label -> hex of every operation a built-in profile writes."""
    return {label: op.hex().upper() for label, op in profiles.builtin(name).build_ops()}


def nfc_dict(**pin) -> dict:
    data = profiles.builtin("ms-logon-nfc").to_dict()
    data["pin"].update(pin)
    return data


# --------------------------------------------------------------------------- #
# The built-in profile                                                        #
# --------------------------------------------------------------------------- #
def test_the_other_built_in_profiles_keep_the_pin_on_the_contact_interface():
    for name in sorted(set(profiles.builtin_names()) - {"ms-logon-nfc"}):
        prof = profiles.builtin(name)
        written = ops(name)
        assert written["verifier PIN (80)"] == PIN_CONTACT_ONLY, name
        assert written["verifier PUK (81)"] == PUK_CONTACT_ONLY, name
        assert prof.contactless_pin_warning() is None
        assert "contactless" not in prof.to_dict()["pin"]
        assert "contactless" not in prof.to_dict()["puk"]


def test_ms_logon_nfc_is_valid_and_written_for_the_build_with_fips_mode_off():
    prof = profiles.builtin("ms-logon-nfc")
    assert prof.validate() == []
    assert prof.fips_mode is False
    assert prof.pin.over_contactless and not prof.puk.over_contactless


def test_ms_logon_nfc_writes_the_verifier_the_working_card_was_provisioned_with():
    written = ops("ms-logon-nfc")
    assert written["verifier PIN (80)"] == PIN_OVER_NFC
    # The PUK stays on the contact interface.
    assert written["verifier PUK (81)"] == PUK_CONTACT_ONLY


def test_ms_logon_nfc_differs_from_ms_logon_only_where_the_logon_needs_it():
    base, nfc = ops("ms-logon"), ops("ms-logon-nfc")
    assert list(base) == list(nfc)  # same objects, same order
    changed = {label for label in base if base[label] != nfc[label]}
    assert changed == {
        "verifier PIN (80)",
        "key auth (9A)",
        "key auth-rsa (9A)",
        "container auth-cert 5FC105",
        "container ccc 5FC107",
    }
    # 9A is used after the PIN on both interfaces; its certificate and the CCC are free to read.
    for label in ("key auth (9A)", "key auth-rsa (9A)"):
        assert "8C01018D0101" in nfc[label]
    for label in ("container auth-cert 5FC105", "container ccc 5FC107", "container chuid 5FC102"):
        assert "8C013F8D013F" in nfc[label]
    # The other keys stay off the contactless interface.
    for label in ("key sign (9C)", "key keymgmt (9D)", "key admin (9B)"):
        assert "8D0100" in nfc[label]


def test_ms_logon_nfc_gives_9a_a_signing_rsa_object():
    prof = profiles.builtin("ms-logon-nfc")
    rsa = [k for k in prof.keys if k.ref == 0x9A and k.mechanism == perso_mod.ALGORITHMS["RSA2048"]]
    assert len(rsa) == 1
    assert pp.key_signs(rsa[0].role, rsa[0].mechanism)
    assert prof.piv_auth_warning() is None


def test_the_profile_survives_a_yaml_round_trip():
    prof = profiles.builtin("ms-logon-nfc")
    text = prof.to_yaml()
    data = yaml.safe_load(text)
    assert data["fips_mode"] is False
    assert data["pin"]["contactless"] == "ALWAYS" and data["pin"]["contactless_retries"] == 3
    assert "contactless" not in data["puk"]
    again = profiles.from_yaml(text)
    assert again.build_payload() == prof.build_payload()
    assert again.validate() == []


def test_the_warning_names_what_crosses_the_radio_link():
    warning = profiles.builtin("ms-logon-nfc").contactless_pin_warning()
    assert warning is not None
    assert "the PIN usable over the contactless interface" in warning
    assert "in clear" in warning

    both = nfc_dict()
    both["puk"].update({"contactless": "ALWAYS", "contactless_retries": 2})
    prof = profiles.from_dict(both)
    assert prof.validate() == []
    assert "the PIN and the PUK usable" in (prof.contactless_pin_warning() or "")
    assert "8D013F" in dict(prof.build_ops())["verifier PUK (81)"].hex().upper()
    assert "910102" in dict(prof.build_ops())["verifier PUK (81)"].hex().upper()


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #
def test_the_fips_mode_build_cannot_be_asked_for_a_pin_over_contactless():
    data = nfc_dict()
    data["fips_mode"] = True
    errors = profiles.from_dict(data).validate()
    assert len(errors) == 1
    assert "PIN contactless ALWAYS" in errors[0]
    assert "which the FIPS-mode build refuses" in errors[0]
    assert "fips_mode: false" in errors[0]


def test_a_pin_over_contactless_needs_tries_there():
    errors = profiles.from_dict(nfc_dict(contactless_retries=0)).validate()
    assert any("contactless_retries of at least 1" in e and "6983" in e for e in errors), errors


@pytest.mark.parametrize("tries", [7, -1])
def test_the_contactless_tries_are_part_of_the_pin_tries(tries):
    errors = profiles.from_dict(nfc_dict(contactless_retries=tries)).validate()
    assert errors == [f"PIN contactless_retries {tries} out of range (0 to retries, 6)"]


@pytest.mark.parametrize("mode", ["SM", "PIN", "VCI", "SM_PIN"])
def test_only_never_and_always_are_written_for_a_pin(mode):
    errors = profiles.from_dict(nfc_dict(contactless=mode)).validate()
    assert errors == ["PIN contactless must be NEVER or ALWAYS"]


def test_an_unknown_mode_name_is_a_profile_error():
    with pytest.raises(profiles.ProfileError, match="unknown access mode"):
        profiles.from_dict(nfc_dict(contactless="SOMETIMES"))


def test_contact_only_with_spare_contactless_tries_is_written_as_given():
    # Harmless: the verifier is not reachable over contactless, the count is only stored.
    data = profiles.builtin("cryptnox-default").to_dict()
    data["pin"]["contactless_retries"] = 2
    prof = profiles.from_dict(data)
    assert prof.validate() == []
    assert prof.contactless_pin_warning() is None
    assert prof.to_dict()["pin"]["contactless"] == "NEVER"
    assert "8D0100" in dict(prof.build_ops())["verifier PIN (80)"].hex().upper()
    assert "910102" in dict(prof.build_ops())["verifier PIN (80)"].hex().upper()


# --------------------------------------------------------------------------- #
# load-config                                                                 #
# --------------------------------------------------------------------------- #
class _FakeAdmin:
    """The admin channel double: every PUT DATA ADMIN is accepted and recorded."""

    sent: list[str] = []

    def __init__(self, session) -> None:
        self.session = session

    def select(self) -> None:
        pass

    def open(self, keys, **kwargs) -> None:
        pass

    def send(self, apdu, *, context=None) -> Response:
        _FakeAdmin.sent.append(context or "")
        return Response(b"", 0x90, 0x00)


@pytest.fixture
def card(monkeypatch, mock_connection):
    def wire(status: str):
        exchanges = {SELECT_PIV: f"{APT}|9000", GET_STATUS: f"{status}|9000"}
        wire_session(monkeypatch, mock_connection(ATR, exchanges, []))
        _FakeAdmin.sent = []
        monkeypatch.setattr(factory_cmd, "PivAdmin", _FakeAdmin)

    return wire


def test_dry_run_warns_that_the_pin_crosses_the_radio_link():
    result = run(["--json", *LOAD, "--profile", "ms-logon-nfc", "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["profile"] == "ms-logon-nfc" and payload["fips_mode"] is False
    assert PIN_OVER_NFC in payload["bulk_hex"]
    assert "crosses the radio link in clear" in result.stderr
    assert "written for the PIV applet build with FIPS mode off" in result.stderr


def test_the_fips_mode_build_is_refused_before_anything_is_written(card):
    card(STATUS_FIPS)
    result = run(["--json", "--yes", *LOAD, "--profile", "ms-logon-nfc", "--default-keys"])
    assert result.exit_code == 8, result.output
    error = json.loads(result.stdout)
    assert error["error"] == "profile_error"
    assert "this card carries the FIPS-mode build" in error["message"]
    assert _FakeAdmin.sent == []


def test_the_build_with_fips_mode_off_takes_the_profile(card):
    card(STATUS_FIPS_OFF)
    result = run(["--json", "--yes", *LOAD, "--profile", "ms-logon-nfc", "--default-keys"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["applied"] is True
    assert len(_FakeAdmin.sent) == len(profiles.builtin("ms-logon-nfc").build_ops())


# --------------------------------------------------------------------------- #
# quickstart                                                                  #
# --------------------------------------------------------------------------- #
BLANK = piv_cmd.CardFacts(
    pin_configured=False,
    puk_configured=False,
    structure_present=False,
    key_object_present=False,
    cert_present=False,
    chuid_present=False,
    ccc_present=False,
)
QUICKSTART = [
    "piv",
    "quickstart",
    "--include-preperso",
    "--profile",
    "ms-logon-nfc",
    "--slot",
    "9A",
]


def _wire_quickstart(monkeypatch, mock_connection, status: str) -> dict:
    seen: dict = {}

    def facts(session, ref, mech):
        seen["mech"] = mech
        return BLANK, "PivPrePersonalized"

    exchanges = {SELECT_PIV: f"{APT}|9000", GET_STATUS: f"{status}|9000"}
    conn = mock_connection(ATR, exchanges, [])
    monkeypatch.setattr(AppContext, "open_session", lambda self: self.make_session(conn))
    monkeypatch.setattr(piv_cmd, "_collect_quickstart_facts", facts)
    return seen


def test_quickstart_plans_an_rsa_key_and_warns(monkeypatch, mock_connection):
    seen = _wire_quickstart(monkeypatch, mock_connection, STATUS_FIPS_OFF)
    result = run(["--json", *QUICKSTART, "--dry-run"])
    assert result.exit_code == 0, result.output
    # The Windows shape: RSA-2048 unless the caller says otherwise.
    assert seen["mech"] == perso_mod.ALGORITHMS["RSA2048"]
    assert "profile ms-logon-nfc on slot 9A: defaulting to RSA2048" in result.stderr
    assert "crosses the radio link in clear" in result.stderr
    steps = {s["step"]: s["status"] for s in json.loads(result.stdout)["steps"]}
    assert steps["preperso-load-config"] == "would-run"


def test_quickstart_refuses_the_fips_mode_build_before_showing_a_plan(monkeypatch, mock_connection):
    _wire_quickstart(monkeypatch, mock_connection, STATUS_FIPS)
    result = run(["--json", *QUICKSTART, "--dry-run"])
    assert result.exit_code == 8, result.output
    error = json.loads(result.stdout)
    assert error["error"] == "profile_error"
    assert "this card carries the FIPS-mode build" in error["message"]


# --------------------------------------------------------------------------- #
# On a contactless reader, a card set up this way                             #
# --------------------------------------------------------------------------- #
# What the card answered over a contactless reader on 2026-11-11: the PIN probe with the
# tries left for that interface, the PUK probe with 6982.
PICC_ATR = "3B8580018073C821100E"
PICC_READER = "Feitian R502 0"
PROBE_PIN = "00200080"
PROBE_PUK = "00200081"


def _card_over_nfc(mock_connection):
    exchanges = {SELECT_PIV: f"{APT}|9000", PROBE_PIN: "|63C3", PROBE_PUK: "|6982"}
    return mock_connection(PICC_ATR, exchanges, [])


def test_the_hint_names_whichever_was_refused():
    from cryptnox_id_cli.applets.piv import piv as piv_applet

    assert piv_applet.interface_refused_hint(False, False) is None
    assert piv_applet.interface_refused_hint(True, True) == piv_applet.PIN_INTERFACE_REFUSED_HINT
    assert piv_applet.interface_refused_hint(True, False) == piv_applet.PIN_INTERFACE_REFUSED_HINT
    puk_only = piv_applet.interface_refused_hint(False, True)
    assert puk_only == piv_applet.PUK_INTERFACE_REFUSED_HINT
    assert "refuses PUK commands" in puk_only and "accepts the PIN" in puk_only


def test_pin_status_over_contactless_says_the_puk_alone_is_refused(monkeypatch, mock_connection):
    wire_session(monkeypatch, _card_over_nfc(mock_connection), reader_name=PICC_READER)
    result = run(["--json", "piv", "pin", "status"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["pin"]["retries_remaining"] == 3
    assert payload["pin"]["refused_on_interface"] is False
    assert payload["puk"]["refused_on_interface"] is True
    # Not "the card refuses PIN and PUK commands": the PIN works here.
    assert "refuses PUK commands" in payload["note"]
    assert "PIN and PUK commands" not in payload["note"]
    assert PICC_READER in payload["note"]


def test_the_state_note_over_contactless_is_about_the_puk(mock_connection):
    from cryptnox_id_cli.state import StateDetector
    from cryptnox_id_cli.transport.pcsc import CardSession

    session = CardSession(_card_over_nfc(mock_connection), reader_name=PICC_READER)
    state = StateDetector(
        session, probe_fido=False, probe_desfire=False, probe_genuine=False
    ).detect()
    notes = [n for n in state.notes if "the card refuses" in n]
    assert len(notes) == 1
    assert notes[0].startswith("PUK state not readable")
    assert "PIN/PUK" not in notes[0]
