"""Keyless facts about the PIV admin security domain: SELECT by AID plus the key
information template, never INITIALIZE UPDATE. On this chip an INITIALIZE UPDATE
that is not followed by a successful EXTERNAL AUTHENTICATE counts as a failed
authentication, so a status read must not send one."""

from __future__ import annotations

import json

from _cardfakes import ResponseAdapter, run, run_both_modes, wire_session

from cryptnox_id_cli.applets.piv import ssd
from cryptnox_id_cli.applets.piv.admin import SCP02, SCP03
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.pcsc import CardSession

SELECT_SSD = "00A4040009A0000001515350410100"
SELECT_ISD = "00A4040008A00000015100000000"
GET_E0 = "80CA00E000"
FCI_SSD = bytes.fromhex("6F118409A00000015153504101A5049F6501FF")
FCI_ISD = bytes.fromhex("6F108408A000000151000000A5049F6501FF")
# Captured from a D600 development card: one DES keyset, key version 1.
E0_DES = bytes.fromhex("E012C00401018010C00402018010C00403018010")
E0_AES_TWO_VERSIONS = bytes.fromhex(
    "E024C00401018810C00402018810C00403018810C00401028810C00402028810C00403028810"
)
E0_EXTENDED = bytes.fromhex("E008C0060101FF880020")

OK = (0x90, 0x00)


class _Dead:
    """A card that knows nothing; every scripted answer comes from the adapter."""

    def transmit(self, raw: bytes) -> Response:
        return Response(b"", 0x6A, 0x82)


def _conn(answers: dict[str, tuple[bytes, int, int]]) -> ResponseAdapter:
    return ResponseAdapter(_Dead(), answers=answers)


def _no_initialize_update(conn: ResponseAdapter) -> bool:
    return not any(frame.startswith("8050") for frame in conn.log)


def test_des_key_table_from_the_card_means_scp02():
    keys = ssd.parse_key_information(E0_DES)
    assert [(k.key_id, k.key_version, k.type_name, k.length) for k in keys] == [
        (1, 1, "DES", 16),
        (2, 1, "DES", 16),
        (3, 1, "DES", 16),
    ]
    info = ssd.SecurityDomainInfo(ssd.PIV_SSD_AID, tuple(keys), 0x9000)
    assert (info.scp_version, info.key_versions) == (SCP02, [1])


def test_aes_key_table_with_two_versions_means_scp03():
    keys = tuple(ssd.parse_key_information(E0_AES_TWO_VERSIONS))
    info = ssd.SecurityDomainInfo(ssd.PIV_SSD_AID, keys, 0x9000)
    assert (info.scp_version, info.key_versions) == (SCP03, [1, 2])
    assert len(info.keys_for(2)) == 3
    payload = info.to_dict()
    assert payload["scp_version"] == "SCP03"
    assert [v["version"] for v in payload["key_versions"]] == [1, 2]
    assert payload["key_versions"][0]["keys"][0] == {
        "key_id": 1,
        "key_version": 1,
        "type": "AES",
        "type_raw": "88",
        "length": 16,
    }


def test_extended_key_information_format():
    (key,) = ssd.parse_key_information(E0_EXTENDED)
    assert (key.key_type, key.length) == (0x88, 32)


def test_empty_key_table_has_no_scp_version():
    assert ssd.SecurityDomainInfo(ssd.PIV_SSD_AID, (), 0x6982).scp_version is None


def test_describe_reads_the_piv_domain_without_initialize_update():
    conn = _conn({SELECT_SSD: (FCI_SSD, *OK), GET_E0: (E0_DES, *OK)})
    info = ssd.describe_security_domain(CardSession(conn))
    assert info is not None
    assert (info.aid, info.key_versions, info.key_table_sw) == (ssd.PIV_SSD_AID, [1], 0x9000)
    assert _no_initialize_update(conn)


def test_describe_falls_back_to_the_isd():
    conn = _conn({SELECT_ISD: (FCI_ISD, *OK), GET_E0: (E0_DES, *OK)})
    info = ssd.describe_security_domain(CardSession(conn))
    assert info is not None and info.aid == ssd.ISD_AID


def test_describe_is_none_when_no_domain_selects():
    assert ssd.describe_security_domain(CardSession(_conn({}))) is None


def test_withheld_key_table_keeps_its_status_word():
    conn = _conn({SELECT_SSD: (FCI_SSD, *OK), GET_E0: (b"", 0x69, 0x82)})
    info = ssd.describe_security_domain(CardSession(conn))
    assert info is not None
    assert (info.keys, info.key_table_sw, info.scp_version) == ((), 0x6982, None)


def test_admin_status_lists_key_versions_without_authenticating(monkeypatch):
    conn = _conn({SELECT_SSD: (FCI_SSD, *OK), GET_E0: (E0_DES, *OK)})
    wire_session(monkeypatch, conn)
    js, human = run_both_modes(["piv", "admin", "status"])
    assert js.exit_code == 0, js.output
    payload = json.loads(js.stdout)
    assert (payload["aid"], payload["scp_version"]) == ("A00000015153504101", "SCP02")
    assert payload["key_versions"][0]["keys"][0]["type"] == "DES"
    assert human.exit_code == 0, human.output
    assert "SCP02" in human.output and "DES" in human.output
    assert _no_initialize_update(conn)


def test_admin_status_reports_a_withheld_key_table(monkeypatch):
    wire_session(monkeypatch, _conn({SELECT_SSD: (FCI_SSD, *OK), GET_E0: (b"", 0x69, 0x82)}))
    result = run(["piv", "admin", "status"])
    assert result.exit_code == 0, result.output
    assert "withheld (SW=6982)" in result.output


def test_admin_status_fails_clearly_when_nothing_selects(monkeypatch):
    wire_session(monkeypatch, _conn({}))
    result = run(["piv", "admin", "status"])
    assert result.exit_code != 0
    assert "No security domain answered" in result.output


def test_preperso_status_reports_the_domain_and_sends_no_initialize_update(monkeypatch):
    conn = _conn({SELECT_SSD: (FCI_SSD, *OK), GET_E0: (E0_DES, *OK)})
    wire_session(monkeypatch, conn)
    result = run(["--json", "factory", "piv", "preperso", "status"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["scp03_available"] is True
    assert payload["scp_version"] == "SCP02"
    assert payload["security_domain"]["key_versions"][0]["version"] == 1
    assert _no_initialize_update(conn)
