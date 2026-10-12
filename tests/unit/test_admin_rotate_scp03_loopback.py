"""`piv admin rotate-keys` and `delete-factory-keyset` over SCP03, end to end against a
loopback security domain: the real session (C-ENC + C-MAC), the static-DEK key
encryption and the key check values all run for real. The double keeps a key table,
answers INITIALIZE UPDATE / EXTERNAL AUTHENTICATE from its current keys, unwraps
every command, and processes PUT KEY and DELETE KEY as GlobalPlatform describes
them. It models the specification, not a vendor's security domain."""

from __future__ import annotations

import json

from _cardfakes import ResponseAdapter, run, wire_session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptnox_id_cli.applets.piv import ssd
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.secrets.resolver import DEFAULT_GP_KEY
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.scp03 import (
    Scp03Keys,
    _aes_cmac,
    _aes_ecb,
    _cryptogram,
    derive_session_keys,
)

NEW_KEY = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
FACTORY_KEY = bytes.fromhex("F0E1D2C3B4A5968778695A4B3C2D1E0F")
FCI_SSD = bytes.fromhex("6F118409A00000015153504101A5049F6501FF")
CARD_CHALLENGE = bytes.fromhex("C0C1C2C3C4C5C6C7")


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _sw(sw: int) -> Response:
    return Response(b"", sw >> 8, sw & 0xFF)


class LoopbackSecurityDomain:
    """An SCP03 (i=70) security domain with a key table, selectable by the PIV SSD AID."""

    def __init__(self, keysets: dict[int, Scp03Keys]) -> None:
        self.keysets = dict(keysets)
        self.pending: dict | None = None
        self.session: dict | None = None
        self.log: list[bytes] = []

    # -- plain commands ----------------------------------------------------- #
    def transmit(self, apdu: APDU | bytes) -> Response:
        raw = apdu.to_bytes() if isinstance(apdu, APDU) else bytes(apdu)
        self.log.append(raw)
        cla, ins, p1, p2 = raw[:4]
        if ins == 0xA4:  # SELECT ends any session
            self.pending = self.session = None
            aid = raw[5 : 5 + raw[4]]
            return Response(FCI_SSD, 0x90, 0x00) if aid == ssd.PIV_SSD_AID else _sw(0x6A82)
        if ins == 0x82:  # EXTERNAL AUTHENTICATE carries CLA 84 but is not yet wrapped
            return self._external_authenticate(raw)
        if cla & 0x04:
            return self._wrapped(raw)
        if ins == 0xCA and p2 == 0xE0:
            return Response(self._key_information(), 0x90, 0x00)
        if ins == 0x50:
            return self._initialize_update(p1, raw[5:13])
        return _sw(0x6D00)

    def _key_information(self) -> bytes:
        body = b"".join(
            bytes([0xC0, 0x04, kid, kvn, ssd.KEY_TYPE_AES, 0x10])
            for kvn in sorted(self.keysets)
            for kid in (1, 2, 3)
        )
        return bytes([0xE0, len(body)]) + body

    def _initialize_update(self, kvn: int, host_challenge: bytes) -> Response:
        kvn = kvn or min(self.keysets)
        keys = self.keysets.get(kvn)
        if keys is None:
            return _sw(0x6A88)
        s_enc, s_mac, _ = derive_session_keys(keys, host_challenge, CARD_CHALLENGE)
        card_cryptogram = _cryptogram(s_mac, 0x00, host_challenge, CARD_CHALLENGE)
        self.pending = {"kvn": kvn, "host": host_challenge, "s_enc": s_enc, "s_mac": s_mac}
        body = (
            bytes(10)
            + bytes([kvn, 0x03, 0x70])
            + CARD_CHALLENGE
            + card_cryptogram
            + bytes(3)  # sequence counter
        )
        return Response(body, 0x90, 0x00)

    def _external_authenticate(self, raw: bytes) -> Response:
        p = self.pending
        self.pending = None
        if p is None:
            return _sw(0x6985)
        host_recv, mac_recv = raw[5:13], raw[13:21]
        expected = _cryptogram(p["s_mac"], 0x01, p["host"], CARD_CHALLENGE)
        full = _aes_cmac(p["s_mac"], bytes(16) + raw[:5] + host_recv)
        if host_recv != expected or mac_recv != full[:8]:
            return _sw(0x6982)
        self.session = {**p, "chain": full, "counter": 1}
        return _sw(0x9000)

    # -- secured commands --------------------------------------------------- #
    def _wrapped(self, raw: bytes) -> Response:
        s = self.session
        if s is None:
            return _sw(0x6985)
        header, lc = raw[:5], raw[4]
        body = raw[5 : 5 + lc]
        data, mac = body[:-8], body[-8:]
        full = _aes_cmac(s["s_mac"], s["chain"] + header + data)
        if mac != full[:8]:
            return _sw(0x6988)
        s["chain"] = full
        if data:
            icv = _aes_ecb(s["s_enc"], s["counter"].to_bytes(16, "big"))
            plain = _aes_cbc_decrypt(s["s_enc"], icv, data)
            data = plain[: plain.rindex(b"\x80")]
        s["counter"] += 1
        ins, p1, p2 = raw[1], raw[2], raw[3]
        if ins == 0xD8:
            return self._put_key(p1, p2, data)
        if ins == 0xE4:
            return self._delete_key(data)
        return _sw(0x6D00)

    def _put_key(self, p1: int, p2: int, data: bytes) -> Response:
        if p2 != 0x81:
            return _sw(0x6A86)
        dek = self.keysets[self.session["kvn"]].dek  # type: ignore[index]
        new_version, off, keys = data[0], 1, []
        while off < len(data):
            key_type, block_len = data[off], data[off + 1]
            block = data[off + 2 : off + 2 + block_len]
            off += 2 + block_len
            kcv_len = data[off]
            check = data[off + 1 : off + 1 + kcv_len]
            off += 1 + kcv_len
            if key_type != ssd.KEY_TYPE_AES or block_len != 0x11 or block[0] != 0x10:
                return _sw(0x6A80)
            key = _aes_cbc_decrypt(dek, bytes(16), block[1:17])
            if ssd.kcv_aes(key) != check:
                return _sw(0x6982)  # nothing written
            keys.append(key)
        if len(keys) != 3:
            return _sw(0x6A80)
        if p1 == 0 and new_version in self.keysets:
            return _sw(0x6A80)
        if p1 and p1 not in self.keysets:
            return _sw(0x6A88)
        self.keysets.pop(p1, None)
        self.keysets[new_version] = Scp03Keys(*keys)
        echoed = bytes([new_version]) + b"".join(ssd.kcv_aes(k) for k in keys)
        return Response(echoed, 0x90, 0x00)

    def _delete_key(self, data: bytes) -> Response:
        if data[:2] != b"\xd2\x01":
            return _sw(0x6A80)
        version = data[2]
        if version not in self.keysets:
            return _sw(0x6A88)
        if version == self.session["kvn"]:  # type: ignore[index]
            return _sw(0x6985)
        del self.keysets[version]
        return _sw(0x9000)


def _domain() -> LoopbackSecurityDomain:
    return LoopbackSecurityDomain(
        {1: Scp03Keys.same(DEFAULT_GP_KEY), 2: Scp03Keys.same(FACTORY_KEY)}
    )


def _set_keys(monkeypatch, prefix: str, key: bytes) -> None:
    for part in ("ENC", "MAC", "DEK"):
        monkeypatch.setenv(f"{prefix}_{part}", key.hex())


def _wired(monkeypatch, domain: LoopbackSecurityDomain) -> None:
    wire_session(monkeypatch, ResponseAdapter(domain))


def test_rotate_keys_over_scp03(monkeypatch):
    domain = _domain()
    _wired(monkeypatch, domain)
    _set_keys(monkeypatch, "PIV_SCP03_NEW", NEW_KEY)
    result = run(["--json", "--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["scp_version"] == "SCP03"
    assert payload["new_key_kcvs"] == ["EDCC64"] * 3
    assert payload["card_kcvs_match"] is True
    assert payload["new_keys_authenticate"] is True
    assert payload["factory_keyset_unchanged"] is True
    assert payload["key_versions_after"] == [1, 2]
    assert domain.keysets[1] == Scp03Keys.same(NEW_KEY)
    assert domain.keysets[2] == Scp03Keys.same(FACTORY_KEY)
    put_keys = [f for f in domain.log if f[1] == 0xD8]
    assert len(put_keys) == 1
    assert put_keys[0][0] == 0x84  # wrapped
    assert not any(NEW_KEY in frame for frame in domain.log)  # never in clear on the wire


def test_rotate_keys_with_the_wrong_dek_writes_nothing(monkeypatch):
    domain = _domain()
    _wired(monkeypatch, domain)
    _set_keys(monkeypatch, "PIV_SCP03_NEW", NEW_KEY)
    monkeypatch.setattr(piv_cmd, "_key_encryption_key", lambda adm, keys: bytes(16))
    result = run(["--yes", "piv", "admin", "rotate-keys", "--default-keys"])
    assert result.exit_code != 0
    assert "6982" in result.output
    assert domain.keysets[1] == Scp03Keys.same(DEFAULT_GP_KEY)


def test_delete_factory_keyset_over_scp03(monkeypatch):
    domain = LoopbackSecurityDomain({1: Scp03Keys.same(NEW_KEY), 2: Scp03Keys.same(FACTORY_KEY)})
    _wired(monkeypatch, domain)
    _set_keys(monkeypatch, "PIV_SCP03", NEW_KEY)
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
    assert payload["verified"] is True
    assert payload["key_versions_after"] == [1]
    assert list(domain.keysets) == [1]
    deletes = [f for f in domain.log if f[1] == 0xE4]
    assert len(deletes) == 1 and deletes[0][0] == 0x84


def test_customer_flow_rotate_then_delete(monkeypatch):
    """The documented sequence on one card: rotate with the shipped keys, then drop the
    factory keyset with the new ones."""
    domain = _domain()
    _wired(monkeypatch, domain)
    _set_keys(monkeypatch, "PIV_SCP03_NEW", NEW_KEY)
    assert run(["--yes", "piv", "admin", "rotate-keys", "--default-keys"]).exit_code == 0
    _set_keys(monkeypatch, "PIV_SCP03", NEW_KEY)
    result = run(["piv", "admin", "delete-factory-keyset", "--i-understand-this-is-irreversible"])
    assert result.exit_code == 0, result.output
    assert domain.keysets == {1: Scp03Keys.same(NEW_KEY)}
