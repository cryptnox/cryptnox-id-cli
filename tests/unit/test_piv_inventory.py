"""Keyless inventory of the PIV applet (GET DATA ``2F47xx``). The response bytes
were captured from a D600 card carrying the ``cryptnox-default`` structure."""

from __future__ import annotations

import json

import pytest
from _cardfakes import run, run_both_modes, wire_session

from cryptnox_id_cli.applets.piv import inventory as inv
from cryptnox_id_cli.applets.piv.objects import get_data_extended_apdu
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.transport.pcsc import CardSession

SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
VERSION = "532680184F70656E464950533230312D503731443630302D46495053810102820100830100840100"
STATUS = "53188001078101008201008301008401008501008601008701FF"
STATUS_SECURED = "531880010F8101008201008301008401008501008601008701FF"
CONFIG = "530F800100810100820100830100840100"
KEYS = [
    "53158B019B8C013F8D010091019B8E010C8F010190011C",
    "53158B019A8C01018D010091019B8E01118F0101900110",
    "53158B019C8C01018D010091019B8E01118F0104900110",
    "53158B019D8C01018D010091019B8E01118F0102900110",
    "53158B019E8C013F8D013F91019B8E01118F0101900110",
]
VERIFIERS = [
    "53248B01808C013F8D01008E01068F010890010691010092010093010094010095010096015A",
    "53248B01818C013F8D01008E01088F010890010691010092010093010094010095010096015A",
]
CONTAINERS = [
    "530E8B035FC1028C013F8D013F91019B",
    "530E8B035FC1078C013F8D014091019B",
    "530E8B035FC1058C013F8D014091019B",
    "530E8B035FC1018C013F8D013F91019B",
    "530E8B035FC10A8C013F8D014091019B",
    "530E8B035FC10B8C013F8D014091019B",
    "530E8B035FC1068C013F8D014091019B",
    "530E8B035FC1038C01018D014191019B",
    "530E8B035FC1088C01018D014191019B",
    "530E8B035FC1098C01018D014191019B",
]


def _ext(ident: int, index: int = 0) -> str:
    return f"00CB3F{index:02X}055C032F{ident:04X}00"


def _exchanges(*, secured: bool = False, restricted: bool = False) -> dict[str, str]:
    """Unknown commands answer 6A82, which is what ends each listing on the card."""
    ex = {
        SELECT_PIV: f"{APT}|9000",
        _ext(inv.ID_VERSION): f"{VERSION}|9000",
        _ext(inv.ID_STATUS): f"{STATUS_SECURED if secured else STATUS}|9000",
        _ext(inv.ID_CONFIG): f"{CONFIG}|9000",
    }
    listings = ((inv.ID_KEY, KEYS), (inv.ID_VERIFIER, VERIFIERS), (inv.ID_CONTAINER, CONTAINERS))
    for ident, rows in listings:
        for index, row in enumerate(rows):
            ex[_ext(ident, index)] = "|6986" if restricted else f"{row}|9000"
    return ex


def test_extended_get_data_apdu_shape():
    assert get_data_extended_apdu(inv.ID_KEY, 2).to_bytes().hex().upper() == _ext(inv.ID_KEY, 2)
    with pytest.raises(ValueError):
        get_data_extended_apdu(inv.ID_KEY, 0xFF)  # P2 = FF addresses a standard object


def test_key_header_decodes_slot_mechanism_role_and_modes():
    k = inv.parse_key(bytes.fromhex(KEYS[1]))
    assert (k.ref, k.mechanism, k.role, k.attributes, k.admin_key) == (0x9A, 0x11, 0x01, 0x10, 0x9B)
    assert (k.slot_name, k.mechanism_name) == ("authentication", "ECC-P256")
    assert inv.role_names(k.role) == ["AUTHENTICATE"]
    assert inv.attribute_names(k.attributes) == ["IMPORTABLE"]
    assert (k.mode_contact, k.mode_contactless) == (0x01, 0x00)
    admin = inv.parse_key(bytes.fromhex(KEYS[0]))
    assert admin.mechanism_name == "AES-256"
    assert inv.attribute_names(admin.attributes) == [
        "PERMIT-EXTERNAL",
        "PERMIT-MUTUAL",
        "IMPORTABLE",
    ]
    assert inv.role_names(inv.parse_key(bytes.fromhex(KEYS[2])).role) == ["SIGN"]
    assert inv.role_names(inv.parse_key(bytes.fromhex(KEYS[3])).role) == ["KEY-ESTABLISH"]


def test_verifier_header_decodes_lengths_retries_and_rules():
    pin = inv.parse_verifier(bytes.fromhex(VERIFIERS[0]))
    assert (pin.ref, pin.name) == (0x80, "PIN")
    assert (pin.min_length, pin.max_length) == (6, 8)
    assert (pin.retries_contact, pin.retries_contactless) == (6, 0)
    assert pin.restrict_update is False  # the applet's FALSE byte is 0x5A, not 0x00
    puk = inv.parse_verifier(bytes.fromhex(VERIFIERS[1]))
    assert (puk.name, puk.min_length) == ("PUK", 8)


def test_container_header_decodes_three_byte_oid():
    chuid = inv.parse_container(bytes.fromhex(CONTAINERS[0]))
    assert (chuid.oid_hex, chuid.name, chuid.admin_key) == ("5FC102", "chuid", 0x9B)
    printed = inv.parse_container(bytes.fromhex(CONTAINERS[9]))
    assert (printed.name, printed.mode_contact, printed.mode_contactless) == ("printed", 0x01, 0x41)


def test_version_status_and_config_decode():
    ver = inv.parse_version(bytes.fromhex(VERSION))
    assert (ver.label, ver.version, ver.debug) == ("OpenFIPS201-P71D600-FIPS", "2.0.0", False)
    st = inv.parse_status(bytes.fromhex(STATUS))
    assert (st.state, st.secured, st.fips_mode, st.contactless) == (0x07, False, True, False)
    assert inv.parse_status(bytes.fromhex(STATUS_SECURED)).secured is True
    assert inv.describe_state(0x0F) == "SECURED"
    assert not any(inv.parse_config(bytes.fromhex(CONFIG)).to_dict().values())


@pytest.mark.parametrize(
    ("mode", "words"),
    [
        (0x00, "NEVER"),
        (0x01, "PIN"),
        (0x02, "PIN-ALWAYS"),
        (0x03, "PIN, PIN-ALWAYS"),
        (0x1F, "ALWAYS"),
        (0x3F, "ALWAYS"),  # the applet masks the extra bit
        (0x40, "NEVER, SM"),
        (0x41, "PIN, SM"),
        (0x5F, "ALWAYS, SM"),
        (0x60, "NEVER, VCI"),
        (0x61, "PIN, VCI"),
        (0x81, "PIN, USER-ADMIN"),
    ],
)
def test_describe_mode(mode, words):
    assert inv.describe_mode(mode) == words


def test_read_inventory_stops_at_the_first_missing_index(mock_connection):
    piv = PivApplet(CardSession(mock_connection("3B00", _exchanges(), [])))
    piv.select()
    result = inv.read_inventory(piv)
    assert [k.ref for k in result.keys] == [0x9B, 0x9A, 0x9C, 0x9D, 0x9E]
    assert [v.ref for v in result.verifiers] == [0x80, 0x81]
    assert len(result.containers) == 10
    assert [o.name for o in result.containers][:3] == ["chuid", "ccc", "auth-cert"]
    assert result.restricted is False


def test_read_inventory_reports_withheld_structure(mock_connection):
    piv = PivApplet(CardSession(mock_connection("3B00", _exchanges(restricted=True), [])))
    piv.select()
    result = inv.read_inventory(piv)
    assert (result.keys, result.verifiers, result.containers) == (None, None, None)
    assert result.restricted is True
    assert result.version is not None  # version, status and config still answer


def test_inventory_command_json_and_human(monkeypatch, mock_connection):
    wire_session(monkeypatch, mock_connection("3B00", _exchanges(), []))
    js, human = run_both_modes(["piv", "inventory"])
    assert js.exit_code == 0, js.output
    payload = json.loads(js.stdout)
    assert payload["version"]["label"] == "OpenFIPS201-P71D600-FIPS"
    assert payload["status"]["secured"] is False
    assert payload["restricted"] is False
    assert [k["ref"] for k in payload["keys"]] == ["9B", "9A", "9C", "9D", "9E"]
    assert payload["keys"][2]["roles"] == ["SIGN"]
    assert payload["keys"][1]["mode_contact"] == "PIN"
    assert payload["verifiers"][0]["name"] == "PIN"
    assert payload["containers"][1] == {
        "oid": "5FC107",
        "name": "ccc",
        "mode_contact": "ALWAYS",
        "mode_contact_raw": "3F",
        "mode_contactless": "NEVER, SM",
        "mode_contactless_raw": "40",
        "admin_key": "9B",
    }
    assert human.exit_code == 0, human.output
    assert "OpenFIPS201-P71D600-FIPS 2.0.0" in human.output
    assert "not finalized" in human.output
    assert "Key objects (5)" in human.output
    assert "Verifiers (2)" in human.output
    assert "Containers (10)" in human.output


def test_inventory_command_says_when_the_structure_is_withheld(monkeypatch, mock_connection):
    wire_session(monkeypatch, mock_connection("3B00", _exchanges(restricted=True), []))
    js, human = run_both_modes(["piv", "inventory"])
    assert json.loads(js.stdout)["restricted"] is True
    assert "restrict-enumeration" in human.output


def test_inventory_shows_finalized_state(monkeypatch, mock_connection):
    wire_session(monkeypatch, mock_connection("3B00", _exchanges(secured=True), []))
    result = run(["piv", "inventory"])
    assert result.exit_code == 0, result.output
    assert "SECURED, finalized" in result.output


def test_inventory_is_read_only_under_dry_run(monkeypatch, mock_connection):
    wire_session(monkeypatch, mock_connection("3B00", _exchanges(), []))
    result = run(["--dry-run", "--json", "piv", "inventory"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["keys"]
