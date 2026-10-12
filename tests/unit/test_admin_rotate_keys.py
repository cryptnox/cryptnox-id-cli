"""`piv admin rotate-keys` and `piv admin delete-factory-keyset`: the PUT KEY /
DELETE KEY encoding, the guards, and the post-checks. Key check values are
GlobalPlatform known answers (the default test key's 3DES KCV is the familiar 8BAF47)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from _cardfakes import run, wire_session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptnox_id_cli.applets.piv import ssd
from cryptnox_id_cli.applets.piv.admin import SCP02, SCP03
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.secrets.resolver import DEFAULT_GP_KEY
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.scp03 import Scp03Keys

TEST_KEY = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
SELECT_SSD = "00A4040009A0000001515350410100"
GET_E0 = "80CA00E000"
FCI_SSD = bytes.fromhex("6F118409A00000015153504101A5049F6501FF")
E0_KVN1 = bytes.fromhex("E012C00401018010C00402018010C00403018010")
E0_KVN1_KVN2 = bytes.fromhex(
    "E024C00401018010C00402018010C00403018010C00401028010C00402028010C00403028010"
)
E0_KVN2_ONLY = bytes.fromhex("E012C00401028010C00402028010C00403028010")
OK = (0x90, 0x00)


# ------------------------------------------------------------------ encoding --- #
def test_kcv_known_answers():
    assert ssd.kcv_des(DEFAULT_GP_KEY).hex().upper() == "8BAF47"
    assert ssd.kcv_des(TEST_KEY).hex().upper() == "AD17A7"
    assert ssd.kcv_aes(DEFAULT_GP_KEY).hex().upper() == "504A77"
    assert ssd.kcv_aes(TEST_KEY).hex().upper() == "EDCC64"
    assert ssd.kcv(SCP02, TEST_KEY) == ssd.kcv_des(TEST_KEY)
    assert ssd.kcv(SCP03, TEST_KEY) == ssd.kcv_aes(TEST_KEY)


def test_put_key_scp03_layout_matches_the_vendor_bench():
    """[KVN] + 3 x (88 11 10 <AES-CBC(static DEK, key)> 03 <KCV>), P1 = version replaced,
    P2 = 81 (several keys from key ID 1)."""
    apdu, kcvs = ssd.put_key_apdu(
        SCP03, DEFAULT_GP_KEY, Scp03Keys.same(TEST_KEY), replace_version=1, new_version=1
    )
    assert apdu.to_bytes()[:4].hex().upper() == "80D80181"
    data = apdu.data
    assert data[0] == 1
    assert len(data) == 1 + 3 * 23
    enc = Cipher(algorithms.AES(DEFAULT_GP_KEY), modes.CBC(bytes(16))).encryptor()
    wrapped = enc.update(TEST_KEY) + enc.finalize()
    block = bytes.fromhex("881110") + wrapped + bytes([3]) + bytes.fromhex("EDCC64")
    assert data[1:] == block * 3
    assert kcvs == [bytes.fromhex("EDCC64")] * 3


def test_put_key_scp02_layout():
    """[KVN] + 3 x (80 10 <3DES-ECB(session DEK, key)> 03 <KCV>)."""
    apdu, kcvs = ssd.put_key_apdu(
        SCP02, DEFAULT_GP_KEY, Scp03Keys.same(TEST_KEY), replace_version=1, new_version=1
    )
    data = apdu.data
    assert data[0] == 1
    assert len(data) == 1 + 3 * 22
    block = data[1:23]
    assert block[:2].hex().upper() == "8010"
    assert block[18] == 3
    assert block[19:22].hex().upper() == "AD17A7"
    assert block[2:18] != TEST_KEY  # travels encrypted
    assert kcvs == [bytes.fromhex("AD17A7")] * 3


def test_put_key_add_variant_uses_p1_zero():
    apdu, _ = ssd.put_key_apdu(
        SCP02, DEFAULT_GP_KEY, Scp03Keys.same(TEST_KEY), replace_version=0, new_version=2
    )
    assert apdu.p1 == 0
    assert apdu.data[0] == 2


def test_delete_key_version_apdu():
    assert ssd.delete_key_version_apdu(2).to_bytes().hex().upper() == "80E4000003D20102"


# ------------------------------------------------------------------- doubles --- #
class _SeqConn:
    """A RawConnection answering each command from a list, the last entry sticking."""

    def __init__(self, answers: dict[str, list[tuple[bytes, int, int]]]) -> None:
        self._answers = {k.upper(): list(v) for k, v in answers.items()}
        self.log: list[str] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        key = bytes(apdu).hex().upper()
        self.log.append(key)
        seq = self._answers.get(key)
        if not seq:
            return [], 0x6A, 0x82
        data, sw1, sw2 = seq.pop(0) if len(seq) > 1 else seq[0]
        return list(data), sw1, sw2

    def get_atr(self) -> bytes:
        return b"\x3b\x00"

    def disconnect(self) -> None:
        pass


def _conn(*e0: bytes) -> _SeqConn:
    return _SeqConn({SELECT_SSD: [(FCI_SSD, *OK)], GET_E0: [(table, *OK) for table in e0]})


class _FakeAdmin:
    """The secure channel double: records what was opened and sent, answers PUT KEY with
    the echoed key version and check values (or a refusal) and DELETE KEY with 9000."""

    put_key_sw = 0x9000
    echo_kcvs = True
    opened: list[tuple[bytes, int]] = []
    sent: list[str] = []

    def __init__(self, session) -> None:
        self.card = session
        self.scp = SimpleNamespace(s_dek=bytes(16))
        self.scp_version = SCP02

    def open(self, keys, *, key_version: int = 0, security_level: int = 0x03) -> None:
        _FakeAdmin.opened.append((keys.enc, key_version))

    def forget_channel(self) -> None:
        self.scp = None

    def send(self, apdu, *, context=None) -> Response:
        _FakeAdmin.sent.append(apdu.to_bytes().hex().upper())
        if apdu.ins == 0xD8:
            if _FakeAdmin.put_key_sw != 0x9000:
                sw = _FakeAdmin.put_key_sw
                return Response(b"", sw >> 8, sw & 0xFF)
            echoed = ssd.kcv_des(TEST_KEY) * 3 if _FakeAdmin.echo_kcvs else bytes(9)
            return Response(bytes([apdu.data[0]]) + echoed, 0x90, 0x00)
        if apdu.ins == 0xE4:
            return Response(b"", 0x90, 0x00)
        return Response(b"", 0x6D, 0x00)


@pytest.fixture
def fake_admin(monkeypatch):
    _FakeAdmin.put_key_sw = 0x9000
    _FakeAdmin.echo_kcvs = True
    _FakeAdmin.opened = []
    _FakeAdmin.sent = []
    monkeypatch.setattr(piv_cmd, "PivAdmin", _FakeAdmin)
    return _FakeAdmin


def _set_keys(monkeypatch, prefix: str, key: bytes) -> None:
    for part in ("ENC", "MAC", "DEK"):
        monkeypatch.setenv(f"{prefix}_{part}", key.hex())


# --------------------------------------------------------------- rotate-keys --- #
def test_rotate_replaces_version_1_and_verifies(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03_NEW", TEST_KEY)
    conn = _conn(E0_KVN1_KVN2)
    wire_session(monkeypatch, conn)
    result = run(["--json", "--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["replaced_version"] == 1
    assert payload["new_key_kcvs"] == ["AD17A7"] * 3
    assert payload["card_kcvs_match"] is True
    assert payload["new_keys_authenticate"] is True
    assert payload["factory_keyset_unchanged"] is True
    assert payload["key_versions_after"] == [1, 2]
    # Opened once with the current keys, then once with the new ones, both on version 1.
    assert fake_admin.opened == [(DEFAULT_GP_KEY, 1), (TEST_KEY, 1)]
    assert len(fake_admin.sent) == 1
    assert fake_admin.sent[0].startswith("80D80181")


def test_rotate_dry_run_sends_nothing(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03_NEW", TEST_KEY)
    wire_session(monkeypatch, _conn(E0_KVN1))
    result = run(["--json", "piv", "admin", "rotate-keys", "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["new_key_kcvs"] == ["AD17A7"] * 3
    assert payload["scp_version"] == "SCP02"
    assert fake_admin.opened == [] and fake_admin.sent == []


def test_rotate_refuses_the_test_key_as_new_key(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03_NEW", DEFAULT_GP_KEY)
    wire_session(monkeypatch, _conn(E0_KVN1))
    result = run(["--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code != 0
    assert "publicly known test keys" in result.output
    assert fake_admin.sent == []


def test_rotate_refuses_without_key_version_1(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03_NEW", TEST_KEY)
    wire_session(monkeypatch, _conn(E0_KVN2_ONLY))
    result = run(["--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code != 0
    assert "nothing to replace" in result.output
    assert fake_admin.opened == []


def test_rotate_requires_the_new_keys(monkeypatch, fake_admin):
    monkeypatch.delenv("PIV_SCP03_NEW_ENC", raising=False)
    wire_session(monkeypatch, _conn(E0_KVN1))
    result = run(["--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code != 0
    assert "PIV_SCP03_NEW_ENC" in result.output


def test_rotate_stops_when_the_card_refuses_put_key(monkeypatch, fake_admin):
    fake_admin.put_key_sw = 0x6982
    _set_keys(monkeypatch, "PIV_SCP03_NEW", TEST_KEY)
    wire_session(monkeypatch, _conn(E0_KVN1))
    result = run(["--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code != 0
    assert "6982" in result.output
    assert len(fake_admin.opened) == 1  # no verification attempt with the new keys


def test_rotate_fails_loudly_when_the_card_echoes_other_kcvs(monkeypatch, fake_admin):
    fake_admin.echo_kcvs = False
    _set_keys(monkeypatch, "PIV_SCP03_NEW", TEST_KEY)
    wire_session(monkeypatch, _conn(E0_KVN1))
    result = run(["--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code != 0
    assert "post-check failed" in result.output


# --------------------------------------------------- delete-factory-keyset --- #
def test_delete_removes_version_2_and_verifies(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03", TEST_KEY)
    conn = _conn(E0_KVN1_KVN2, E0_KVN1)
    wire_session(monkeypatch, conn)
    result = run(
        [
            "--json",
            "piv",
            "admin",
            "delete-factory-keyset",
            "--i-understand-this-is-irreversible",
        ]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["deleted"] is True
    assert payload["verified"] is True
    assert payload["key_versions_after"] == [1]
    assert fake_admin.opened == [(TEST_KEY, 1)]
    assert fake_admin.sent == ["80E4000003D20102"]


def test_delete_refuses_while_the_test_key_is_in_use(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03", DEFAULT_GP_KEY)
    wire_session(monkeypatch, _conn(E0_KVN1_KVN2))
    result = run(["piv", "admin", "delete-factory-keyset", "--i-understand-this-is-irreversible"])
    assert result.exit_code != 0
    assert "rotate it first" in result.output
    assert fake_admin.sent == []


def test_delete_is_a_no_op_without_version_2(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03", TEST_KEY)
    wire_session(monkeypatch, _conn(E0_KVN1))
    result = run(
        ["--json", "piv", "admin", "delete-factory-keyset", "--i-understand-this-is-irreversible"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["deleted"] is False
    assert fake_admin.sent == []


def test_delete_needs_the_flag_when_not_interactive(monkeypatch, fake_admin):
    _set_keys(monkeypatch, "PIV_SCP03", TEST_KEY)
    wire_session(monkeypatch, _conn(E0_KVN1_KVN2))
    result = run(["--json", "piv", "admin", "delete-factory-keyset"])
    assert result.exit_code != 0
    assert "--i-understand-this-is-irreversible" in result.output
    assert fake_admin.sent == []


def test_delete_dry_run_sends_nothing(monkeypatch, fake_admin):
    wire_session(monkeypatch, _conn(E0_KVN1_KVN2))
    result = run(["--json", "piv", "admin", "delete-factory-keyset", "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["would_delete_version"] == 2
    assert len(payload["keys"]) == 3
    assert fake_admin.sent == [] and fake_admin.opened == []
