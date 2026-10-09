"""`piv admin keys`: the key table is read without authenticating; `--check-default`
spends exactly one authentication attempt on key version 1 and never searches."""

from __future__ import annotations

import json

import pytest
from _cardfakes import ResponseAdapter, run, wire_session

from cryptnox_id_cli.applets.piv.admin import SCP02, InitializeUpdateRejected
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.errors import Scp02Error

SELECT_SSD = "00A4040009A0000001515350410100"
GET_E0 = "80CA00E000"
FCI_SSD = bytes.fromhex("6F118409A00000015153504101A5049F6501FF")
E0_KVN1_DES = bytes.fromhex("E012C00401018010C00402018010C00403018010")
E0_KVN2_ONLY = bytes.fromhex("E012C00401028810C00402028810C00403028810")
OK = (0x90, 0x00)


class _Dead:
    def transmit(self, raw: bytes) -> Response:
        return Response(b"", 0x6A, 0x82)


def _conn(e0: bytes = E0_KVN1_DES) -> ResponseAdapter:
    return ResponseAdapter(_Dead(), answers={SELECT_SSD: (FCI_SSD, *OK), GET_E0: (e0, *OK)})


class _FakeAdmin:
    """Stands in for the channel: records the key version asked for, then succeeds,
    fails the cryptogram check, or has INITIALIZE UPDATE refused."""

    outcome = "ok"
    opened: list[int] = []

    def __init__(self, session) -> None:
        self.card = session
        self.scp_version = None

    def select(self) -> None:
        pass

    def open(self, keys, *, key_version: int = 0, security_level: int = 0x03) -> None:
        _FakeAdmin.opened.append(key_version)
        if _FakeAdmin.outcome == "wrong":
            raise Scp02Error("Card cryptogram mismatch - the SCP02 keys are wrong for this card.")
        if _FakeAdmin.outcome == "rejected":
            raise InitializeUpdateRejected("INITIALIZE UPDATE rejected (SW=6A88).")
        self.scp_version = SCP02


@pytest.fixture
def fake_admin(monkeypatch):
    _FakeAdmin.outcome = "ok"
    _FakeAdmin.opened = []
    monkeypatch.setattr(piv_cmd, "PivAdmin", _FakeAdmin)
    return _FakeAdmin


def _keys(monkeypatch, conn, *args: str) -> dict:
    wire_session(monkeypatch, conn)
    result = run(["--json", "piv", "admin", "keys", *args])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def test_table_alone_never_authenticates(monkeypatch, fake_admin):
    conn = _conn()
    payload = _keys(monkeypatch, conn)
    assert payload["key_versions"][0]["version"] == 1
    assert payload["default_key_check"] is None
    assert fake_admin.opened == []
    assert not any(frame.startswith("8050") for frame in conn.log)


def test_check_default_yes_is_one_completed_authentication(monkeypatch, fake_admin):
    payload = _keys(monkeypatch, _conn(), "--check-default")
    check = payload["default_key_check"]
    assert check["answers_to_default"] is True
    assert check["failed_authentication_counted"] is False
    assert check["scp_version"] == "SCP02"
    assert fake_admin.opened == [1]


def test_check_default_no_reports_the_counted_failure(monkeypatch, fake_admin):
    fake_admin.outcome = "wrong"
    payload = _keys(monkeypatch, _conn(), "--check-default")
    check = payload["default_key_check"]
    assert check["answers_to_default"] is False
    assert check["failed_authentication_counted"] is True
    assert fake_admin.opened == [1]  # one attempt, no search


def test_check_default_undetermined_when_initialize_update_is_refused(monkeypatch, fake_admin):
    fake_admin.outcome = "rejected"
    payload = _keys(monkeypatch, _conn(), "--check-default")
    check = payload["default_key_check"]
    assert check["answers_to_default"] is None
    assert "6A88" in check["detail"]


def test_check_skipped_when_key_version_1_is_absent(monkeypatch, fake_admin):
    payload = _keys(monkeypatch, _conn(E0_KVN2_ONLY), "--check-default")
    check = payload["default_key_check"]
    assert check["performed"] is False
    assert "key version 1" in check["reason"]
    assert fake_admin.opened == []


def test_dry_run_lists_the_table_and_skips_the_check(monkeypatch, fake_admin):
    wire_session(monkeypatch, _conn())
    result = run(["--dry-run", "--json", "piv", "admin", "keys", "--check-default"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["key_versions"]
    assert payload["default_key_check"] == {"performed": False, "reason": "dry-run"}
    assert fake_admin.opened == []


def test_human_output_states_the_verdict(monkeypatch, fake_admin):
    wire_session(monkeypatch, _conn())
    result = run(["piv", "admin", "keys", "--check-default"])
    assert result.exit_code == 0, result.output
    assert "YES" in result.output
    assert "replace the key before deployment" in result.output
    fake_admin.outcome = "wrong"
    wire_session(monkeypatch, _conn())
    result = run(["piv", "admin", "keys", "--check-default"])
    assert "One failed authentication is now counted" in result.output
    wire_session(monkeypatch, _conn())
    result = run(["piv", "admin", "keys"])
    assert "not checked (pass --check-default)" in result.output
