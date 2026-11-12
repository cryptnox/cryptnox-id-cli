# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""DESFire EV2 auth + secure-messaging tests (offline; the card is the final arbiter)."""

import pytest
from _cardfakes import QueueConn, run, wire_session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from cryptnox_id_cli.applets.mifare import desfire as df
from cryptnox_id_cli.applets.mifare import ev2
from cryptnox_id_cli.applets.mifare.desfire import DesfireTransport
from cryptnox_id_cli.transport.pcsc import CardSession

RNDA = bytes(range(0x00, 0x10))
RNDB = bytes(range(0x10, 0x20))
KEY = bytes(16)


def _cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def test_rot_left():
    assert ev2.rot_left(b"\x01\x02\x03") == b"\x02\x03\x01"


def test_sv_base_golden():
    # rnda[0:2] + (rnda[2:8]^rndb[0:6]) + rndb[6:16] + rnda[8:16], precomputed by hand.
    expected = "0001" + "121216161212" + "161718191A1B1C1D1E1F" + "08090A0B0C0D0E0F"
    assert ev2.build_sv_base(RNDA, RNDB).hex().upper() == expected


def test_session_key_derivation_layout():
    base = ev2.build_sv_base(RNDA, RNDB)
    ses_enc, ses_mac = ev2.derive_session_keys(KEY, RNDA, RNDB)
    assert ses_enc == _cmac(KEY, bytes.fromhex("A55A00010080") + base)
    assert ses_mac == _cmac(KEY, bytes.fromhex("5AA500010080") + base)
    assert ses_enc != ses_mac


def test_truncate_mac_takes_odd_bytes():
    full = bytes(range(16))
    assert ev2.truncate_mac(full) == bytes([1, 3, 5, 7, 9, 11, 13, 15])


def test_command_mac_layout():
    sess = ev2.Ev2Session(k_enc=bytes(16), k_mac=KEY, ti=bytes.fromhex("AABBCCDD"))
    payload = b"\x01\x02"
    expected = ev2.truncate_mac(
        _cmac(KEY, bytes([0x3D, 0x00, 0x00]) + bytes.fromhex("AABBCCDD") + payload)
    )
    assert sess.command_mac(0x3D, payload) == expected


class FakeEv2Card:
    """Implements the card side of AuthenticateEV2First for loopback testing."""

    def __init__(self, key: bytes, rndb: bytes, ti: bytes) -> None:
        self.key, self.rndb, self.ti = key, rndb, ti
        self.rnda: bytes | None = None

    def _cbc(self, data: bytes, *, encrypt: bool) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(b"\x00" * 16))
        op = cipher.encryptor() if encrypt else cipher.decryptor()
        return op.update(data) + op.finalize()

    def transmit(self, apdu):
        raw = bytes(apdu)
        cmd, body = raw[1], raw[5:-1] if len(raw) > 5 else b""
        if cmd == 0x71:
            return list(self._cbc(self.rndb, encrypt=True)), 0x91, 0xAF
        if cmd == 0xAF:
            plain = self._cbc(body, encrypt=False)
            rnda, rndb_rot = plain[:16], plain[16:]
            if rndb_rot != ev2.rot_left(self.rndb):
                return [], 0x91, 0xAE
            self.rnda = rnda
            final = self.ti + ev2.rot_left(rnda) + bytes(12)
            return list(self._cbc(final, encrypt=True)), 0x91, 0x00
        return [], 0x91, 0x1C

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


def test_authenticate_ev2_loopback():
    card = FakeEv2Card(KEY, RNDB, ti=bytes.fromhex("DEADBEEF"))
    session = ev2.authenticate_ev2_first(DesfireTransport(CardSession(card)), 0, KEY, rnda=RNDA)
    assert session.ti == bytes.fromhex("DEADBEEF")
    expected_enc, expected_mac = ev2.derive_session_keys(KEY, RNDA, RNDB)
    assert (session.k_enc, session.k_mac) == (expected_enc, expected_mac)


def test_authenticate_wrong_key_rejected_by_card():
    # With a wrong host key the card's RndB' check fails -> AUTHENTICATION_ERROR (0xAE).
    card = FakeEv2Card(bytes(range(16)), RNDB, ti=bytes(4))
    with pytest.raises(df.DesfireError) as exc:
        ev2.authenticate_ev2_first(DesfireTransport(CardSession(card)), 0, KEY, rnda=RNDA)
    assert exc.value.status == 0xAE


def test_authenticate_bad_card_proof_raises():
    # A card that accepts part 2 but returns a wrong RndA' must be refused host-side.
    class LyingCard(FakeEv2Card):
        def transmit(self, apdu):
            raw = bytes(apdu)
            if raw[1] == 0xAF:
                final = self.ti + bytes(16) + bytes(12)  # bogus RndA'
                return list(self._cbc(final, encrypt=True)), 0x91, 0x00
            return super().transmit(apdu)

    card = LyingCard(KEY, RNDB, ti=bytes(4))
    with pytest.raises(ev2.Ev2Error, match="proof mismatch"):
        ev2.authenticate_ev2_first(DesfireTransport(CardSession(card)), 0, KEY, rnda=RNDA)


def test_create_application_frame():
    conn = QueueConn([(b"", 0x91, 0x00)])
    DesfireTransport(CardSession(conn)).create_application(bytes.fromhex("CC0102"))
    assert conn.sent[0].hex().upper() == "90CA000005CC01020F8300"


def test_create_std_file_frame():
    conn = QueueConn([(b"", 0x91, 0x00)])
    DesfireTransport(CardSession(conn)).create_std_data_file(0x01, 32)
    # file 01, comm MAC (01), access E000 LE -> 00E0, size 32 LE -> 200000
    assert conn.sent[0].hex().upper() == "90CD00000701" + "01" + "00E0" + "200000" + "00"


def test_command_macked_length_error_surfaces_status():
    # A large WriteData the card rejects (LENGTH_ERROR 0x7E) must surface as a
    # DesfireError carrying that status, so the CLI can translate it to guidance.
    sess = ev2.Ev2Session(k_enc=bytes(16), k_mac=KEY, ti=bytes.fromhex("AABBCCDD"))
    conn = QueueConn([(b"", 0x91, 0x7E)])
    with pytest.raises(df.DesfireError) as exc:
        ev2.command_macked(
            DesfireTransport(CardSession(conn)), sess, df.CMD_WRITE_DATA, b"\x00" * 40
        )
    assert exc.value.status == df.STATUS_LENGTH_ERROR == 0x7E


def test_command_macked_roundtrip():
    sess = ev2.Ev2Session(k_enc=bytes(16), k_mac=KEY, ti=bytes.fromhex("AABBCCDD"))
    header = DesfireTransport.data_header(0x01, 0, 3)
    payload = header + b"\x0a\x0b\x0c"
    # Build the card's MACed OK response for the post-increment counter.
    resp_mac = ev2.truncate_mac(
        _cmac(KEY, b"\x00" + (1).to_bytes(2, "little") + bytes.fromhex("AABBCCDD"))
    )
    conn = QueueConn([(resp_mac, 0x91, 0x00)])
    out = ev2.command_macked(DesfireTransport(CardSession(conn)), sess, df.CMD_WRITE_DATA, payload)
    assert out == b""
    assert sess.cmd_ctr == 1
    sent = conn.sent[0]
    assert sent[1] == df.CMD_WRITE_DATA
    assert len(sent) == 5 + len(payload) + 8 + 1  # header5 + payload + MACt + Le


class ChainCard:
    """A card that accepts a command split across frames (0x91AF until it has the
    declared total), then replies with the final response MAC."""

    def __init__(self, total_len, resp_mac):
        self.total = total_len
        self.resp_mac = resp_mac
        self.recv = bytearray()
        self.frames: list[bytes] = []

    def transmit(self, apdu):
        raw = bytes(apdu)
        self.frames.append(raw)
        lc = raw[4]
        self.recv += raw[5 : 5 + lc]
        if len(self.recv) < self.total:
            return [], 0x91, 0xAF  # request the next command frame
        return list(self.resp_mac), 0x91, 0x00

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


class FullCard:
    """Mirrors the card side of CommMode.FULL so a write->read round-trip is exercised."""

    def __init__(self, k_enc, k_mac, ti):
        self.s = ev2.Ev2Session(k_enc=k_enc, k_mac=k_mac, ti=ti)
        self.store = bytearray(64)

    def transmit(self, apdu):
        raw = bytes(apdu)
        cmd, lc = raw[1], raw[4]
        body = raw[5 : 5 + lc]
        macked, mact = body[:-8], body[-8:]
        assert self.s.command_mac(cmd, macked) == mact  # command MAC must verify
        header = macked[:7]
        offset = int.from_bytes(header[1:4], "little")
        length = int.from_bytes(header[4:7], "little")
        if cmd == df.CMD_WRITE_DATA:
            enc = macked[7:]
            plain = ev2._aes_cbc_iv(
                self.s.k_enc, ev2._full_iv(self.s, (0xA5, 0x5A)), enc, encrypt=False
            )
            self.store[offset : offset + length] = plain[:length]
            self.s.cmd_ctr += 1
            return list(self.s.response_mac(0x00, b"")), 0x91, 0x00
        if cmd == df.CMD_READ_DATA:
            self.s.cmd_ctr += 1
            data = bytes(self.store[offset : offset + length])
            enc = ev2._aes_cbc_iv(
                self.s.k_enc, ev2._full_iv(self.s, (0x5A, 0xA5)), ev2._pad_full(data), encrypt=True
            )
            return list(enc + self.s.response_mac(0x00, enc)), 0x91, 0x00
        return [], 0x91, 0x1C

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


class ChangeKeyCard:
    """Decrypts the ChangeKey KeyData cryptogram so we can assert it carries NewKey||Ver."""

    def __init__(self, k_enc, k_mac, ti):
        self.s = ev2.Ev2Session(k_enc=k_enc, k_mac=k_mac, ti=ti)
        self.key_data = b""

    def transmit(self, apdu):
        raw = bytes(apdu)
        cmd, lc = raw[1], raw[4]
        macked, mact = raw[5 : 5 + lc][:-8], raw[5 : 5 + lc][-8:]
        assert self.s.command_mac(cmd, macked) == mact
        enc = macked[1:]  # header is the 1-byte key number; the rest is encrypted KeyData
        self.key_data = ev2._aes_cbc_iv(
            self.s.k_enc, ev2._full_iv(self.s, (0xA5, 0x5A)), enc, encrypt=False
        )
        self.s.cmd_ctr += 1
        return list(self.s.response_mac(0x00, b"")), 0x91, 0x00

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


def test_change_key_same_carries_newkey_and_version():
    ti = bytes.fromhex("AABBCCDD")
    plat = ev2.Ev2Session(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)
    card = ChangeKeyCard(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)
    new_key = bytes(range(16, 32))
    ev2.change_key_same(DesfireTransport(CardSession(card)), plat, 0, new_key, key_version=0x10)
    assert card.key_data[:16] == new_key  # NewKey
    assert card.key_data[16] == 0x10  # KeyVersion
    assert card.key_data[17] == 0x80  # EV2 padding starts here


@pytest.mark.parametrize("size", [16, 20])
def test_command_full_write_read_roundtrip(size):
    ti = bytes.fromhex("AABBCCDD")
    plat = ev2.Ev2Session(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)
    card = FullCard(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)
    dtx = DesfireTransport(CardSession(card))
    data = bytes(range(size))
    ev2.command_full(
        dtx, plat, df.CMD_WRITE_DATA, header=dtx.data_header(1, 0, size), plaintext=data
    )
    got = ev2.command_full(
        dtx, plat, df.CMD_READ_DATA, header=dtx.data_header(1, 0, size), response_len=size
    )
    assert got == data


def test_command_macked_chains_large_payload():
    sess = ev2.Ev2Session(k_enc=bytes(16), k_mac=KEY, ti=bytes.fromhex("AABBCCDD"))
    payload = bytes(range(40))
    full = payload + sess.command_mac(df.CMD_WRITE_DATA, payload)  # 40 + 8 = 48 bytes
    resp_mac = ev2.truncate_mac(
        _cmac(KEY, b"\x00" + (1).to_bytes(2, "little") + bytes.fromhex("AABBCCDD"))
    )
    card = ChainCard(len(full), resp_mac)
    out = ev2.command_macked(
        DesfireTransport(CardSession(card)), sess, df.CMD_WRITE_DATA, payload, max_frame=16
    )
    assert out == b""
    assert sess.cmd_ctr == 1
    assert bytes(card.recv) == full  # the card reassembled header+data+MAC exactly
    assert len(card.frames) == 3  # ceil(48 / 16)
    assert card.frames[0][1] == df.CMD_WRITE_DATA  # first frame: real opcode
    assert all(f[1] == 0xAF for f in card.frames[1:])  # continuations: 0xAF


def _ref_desfire_crc32(data: bytes) -> bytes:
    """Canonical reflected CRC32: poly 0xEDB88320, init 0xFFFFFFFF, NO final XOR, LE."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return crc.to_bytes(4, "little")


def test_desfire_crc32_definition():
    assert ev2.desfire_crc32(b"") == b"\xff\xff\xff\xff"  # init value, no final inversion
    for v in [b"", b"\x00", b"cryptnox", bytes(range(16)), bytes(range(16, 32))]:
        assert ev2.desfire_crc32(v) == _ref_desfire_crc32(v)


def test_change_key_cross_carries_xor_version_crc():
    ti = bytes.fromhex("AABBCCDD")
    plat = ev2.Ev2Session(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)
    card = ChangeKeyCard(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)
    old_key = bytes(16)  # current value of the target slot (e.g. factory zero)
    new_key = bytes(range(16, 32))
    ev2.change_key_cross(
        DesfireTransport(CardSession(card)), plat, 1, new_key, old_key, key_version=0x05
    )
    xored = bytes(a ^ b for a, b in zip(new_key, old_key, strict=True))
    assert card.key_data[:16] == xored  # NewKey XOR OldKey
    assert card.key_data[16] == 0x05  # KeyVersion
    assert card.key_data[17:21] == ev2.desfire_crc32(new_key)  # CRC32 over the NEW key
    assert card.key_data[21] == 0x80  # EV2 padding after the 21-byte cryptogram


def test_format_picc_sends_macked_fc():
    sess = ev2.Ev2Session(k_enc=bytes(16), k_mac=KEY, ti=bytes.fromhex("AABBCCDD"))
    resp_mac = ev2.truncate_mac(
        _cmac(KEY, b"\x00" + (1).to_bytes(2, "little") + bytes.fromhex("AABBCCDD"))
    )
    conn = QueueConn([(resp_mac, 0x91, 0x00)])
    ev2.format_picc(DesfireTransport(CardSession(conn)), sess)
    assert sess.cmd_ctr == 1
    sent = conn.sent[0]
    assert sent[1] == df.CMD_FORMAT_PICC == 0xFC
    assert sent[4] == 8  # Lc = just the 8-byte command MAC (no payload)
    assert len(sent) == 5 + 8 + 1  # header5 + MACt + Le


def test_pad_full_always_pads_including_block_aligned():
    # ISO 9797-1 method 2: a block-aligned input gets a WHOLE extra padding block.
    assert ev2._pad_full(b"") == b"\x80" + bytes(15)
    assert ev2._pad_full(bytes(16)) == bytes(16) + b"\x80" + bytes(15)
    assert len(ev2._pad_full(bytes(16))) == 32  # 16 -> 32, not left at 16 (the bug)
    assert ev2._pad_full(bytes(20)) == bytes(20) + b"\x80" + bytes(11)
    for n in [0, 1, 15, 16, 17, 31, 32, 48]:
        out = ev2._pad_full(bytes(n))
        assert len(out) % 16 == 0 and len(out) > n  # always grows, always block-aligned


def test_full_write_pads_block_aligned_payload_on_the_wire():
    # Regression for the 16-byte FULL write hang: a block-aligned plaintext must reach the
    # card as 32 ciphertext bytes (data + a full 0x80 pad block), never 16.
    ti = bytes.fromhex("AABBCCDD")
    plat = ev2.Ev2Session(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)
    card = ChangeKeyCard(k_enc=bytes(range(16)), k_mac=bytes(16), ti=ti)  # decrypts header[1:]
    ev2.command_full(
        DesfireTransport(CardSession(card)),
        plat,
        df.CMD_WRITE_DATA,
        header=b"\x01",
        plaintext=bytes(range(16)),
    )
    assert len(card.key_data) == 32  # 16 data + 16-byte pad block
    assert card.key_data[:16] == bytes(range(16))
    assert card.key_data[16] == 0x80 and card.key_data[17:] == bytes(15)


BARE_OK = (b"", 0x91, 0x00)
NEW_KEY = bytes(range(16, 32))


def _full_session() -> ev2.Ev2Session:
    return ev2.Ev2Session(k_enc=bytes(range(16)), k_mac=bytes(16), ti=bytes.fromhex("AABBCCDD"))


MACED_IN_FULL_MODE = [
    pytest.param(
        lambda t, s: ev2.command_full(
            t, s, df.CMD_READ_DATA, header=DesfireTransport.data_header(1, 0, 16), response_len=16
        ),
        id="ReadData",
    ),
    pytest.param(
        lambda t, s: ev2.command_full(
            t,
            s,
            df.CMD_WRITE_DATA,
            header=DesfireTransport.data_header(1, 0, 4),
            plaintext=bytes(4),
        ),
        id="WriteData",
    ),
    pytest.param(lambda t, s: ev2.change_file_settings(t, s, 1, bytes(3)), id="ChangeFileSettings"),
    pytest.param(
        lambda t, s: ev2.change_key_cross(t, s, 1, NEW_KEY, bytes(16)), id="ChangeKey-other-key"
    ),
]


@pytest.mark.parametrize("send", MACED_IN_FULL_MODE)
def test_full_mode_refuses_an_ok_that_carries_no_response_mac(send):
    # Of the FULL commands the CLI sends, only ChangeKey of the authenticated key ends the session.
    with pytest.raises(ev2.Ev2Error, match="response MAC missing"):
        send(DesfireTransport(CardSession(QueueConn([BARE_OK]))), _full_session())


def test_change_key_same_accepts_the_bare_ok_that_ends_the_session():
    conn = QueueConn([BARE_OK])
    ev2.change_key_same(DesfireTransport(CardSession(conn)), _full_session(), 0, NEW_KEY)
    assert conn.sent[0][1] == df.CMD_CHANGE_KEY


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        pytest.param(bytes(4), "response MAC missing", id="short"),
        pytest.param(bytes(8), "response MAC verification failed", id="wrong-mac"),
    ],
)
def test_change_key_same_still_checks_a_mac_the_card_sends(reply, message):
    conn = QueueConn([(reply, 0x91, 0x00)])
    with pytest.raises(ev2.Ev2Error, match=message):
        ev2.change_key_same(DesfireTransport(CardSession(conn)), _full_session(), 0, NEW_KEY)


class _OkWithoutMacAfterAuth(FakeEv2Card):
    """Authenticates for real, then answers every other command with a bare OK."""

    def transmit(self, apdu):
        if bytes(apdu)[1] in (ev2.CMD_AUTHENTICATE_EV2_FIRST, ev2.CMD_ADDITIONAL_FRAME):
            return super().transmit(apdu)
        return [], 0x91, 0x00


@pytest.mark.parametrize("json_mode", [True, False])
def test_full_read_without_a_response_mac_fails_and_writes_nothing(
    monkeypatch, tmp_path, json_mode
):
    wire_session(monkeypatch, _OkWithoutMacAfterAuth(bytes(16), RNDB, ti=bytes.fromhex("A1B2C3D4")))
    out = tmp_path / "file01.bin"
    args = ["mifare", "read", "--aid", "010203", "--file-id", "01", "--full", "--length", "16"]
    args += ["--zero-key", "--out", str(out)]
    result = run(["--json", *args] if json_mode else args)
    assert result.exit_code == ev2.Ev2Error.exit_code, result.output
    assert "ReadData (FULL): response MAC missing" in result.output
    assert not out.exists()


FULL_MODE_COMMANDS = [
    pytest.param(
        ["mifare", "write", "--aid", "010203", "--file-id", "01", "--data", "AABB", "--full"]
        + ["--zero-key"],
        "WriteData (FULL)",
        id="write",
    ),
    pytest.param(
        ["mifare", "keys", "change", "--aid", "010203", "--key-no", "1", "--zero-key"]
        + ["--new-key-env", "NEWK", "--auth-key-no", "0", "--auth-zero-key"],
        "ChangeKey (cross)",
        id="keys-change-other-key",
    ),
]


@pytest.mark.parametrize("json_mode", [True, False])
@pytest.mark.parametrize(("args", "context"), FULL_MODE_COMMANDS)
def test_full_mode_commands_fail_on_an_ok_without_a_response_mac(
    monkeypatch, args, context, json_mode
):
    monkeypatch.setenv("NEWK", NEW_KEY.hex())
    wire_session(monkeypatch, _OkWithoutMacAfterAuth(bytes(16), RNDB, ti=bytes.fromhex("A1B2C3D4")))
    result = run(["--yes", *(["--json"] if json_mode else []), *args])
    assert result.exit_code == ev2.Ev2Error.exit_code, result.output
    assert f"{context}: response MAC missing" in result.output


class _KeyChangingCard(FakeEv2Card):
    """Takes a same-key ChangeKey and answers a bare OK.

    ``relay`` answers in the card's place: ``"change"`` the ChangeKey, ``"change+auth"`` also
    the authentication after it.
    """

    def __init__(self, relay: str = "") -> None:
        super().__init__(bytes(16), RNDB, ti=bytes.fromhex("A1B2C3D4"))
        self.relay = relay
        self.change_answered = False

    def transmit(self, apdu):
        raw = bytes(apdu)
        forged_auth = self.relay == "change+auth" and self.change_answered
        if forged_auth and raw[1] == ev2.CMD_ADDITIONAL_FRAME:
            return [0] * 32, 0x91, 0x00
        if raw[1] in (ev2.CMD_AUTHENTICATE_EV2_FIRST, ev2.CMD_ADDITIONAL_FRAME):
            return super().transmit(apdu)
        if raw[1] == ev2.CMD_CHANGE_KEY and self.rnda is not None:
            self.change_answered = True
            if not self.relay:
                k_enc, k_mac = ev2.derive_session_keys(self.key, self.rnda, self.rndb)
                session = ev2.Ev2Session(k_enc=k_enc, k_mac=k_mac, ti=self.ti)
                key_data = raw[6 : 5 + raw[4] - 8]
                iv = ev2._full_iv(session, (0xA5, 0x5A))
                self.key = ev2._aes_cbc_iv(k_enc, iv, key_data, encrypt=False)[:16]
                self.rnda = None
        return [], 0x91, 0x00


SAME_KEY_CHANGE = ["--yes", "mifare", "keys", "change", "--aid", "010203", "--key-no", "0"]
SAME_KEY_CHANGE += ["--zero-key", "--new-key-env", "NEWK"]


@pytest.mark.parametrize("json_mode", [True, False])
def test_keys_change_of_the_authenticated_key_succeeds_on_a_bare_ok(monkeypatch, json_mode):
    monkeypatch.setenv("NEWK", NEW_KEY.hex())
    card = _KeyChangingCard()
    wire_session(monkeypatch, card)
    result = run([*(["--json"] if json_mode else []), *SAME_KEY_CHANGE])
    assert result.exit_code == 0, result.output
    assert card.key == NEW_KEY


@pytest.mark.xfail(strict=True, reason="a relayed bare OK is reported as a changed key")
@pytest.mark.parametrize("json_mode", [True, False])
@pytest.mark.parametrize("relay", ["change", "change+auth"])
def test_keys_change_of_the_authenticated_key_fails_when_the_card_kept_the_old_key(
    monkeypatch, relay, json_mode
):
    monkeypatch.setenv("NEWK", NEW_KEY.hex())
    card = _KeyChangingCard(relay)
    wire_session(monkeypatch, card)
    result = run([*(["--json"] if json_mode else []), *SAME_KEY_CHANGE])
    assert result.exit_code == ev2.Ev2Error.exit_code, result.output
    assert "the new key does not authenticate" in result.output
    assert '"changed"' not in result.output
    assert card.key == bytes(16)


def _card_side(
    k_enc: bytes = bytes(range(16)), k_mac: bytes = bytes(16), ti: bytes = b""
) -> ev2.Ev2Session:
    """The card's view of the first command after authentication."""
    return ev2.Ev2Session(k_enc=k_enc, k_mac=k_mac, ti=ti or bytes.fromhex("AABBCCDD"), cmd_ctr=1)


def _full_answer(card: ev2.Ev2Session, data: bytes) -> bytes:
    """A FULL-mode file's answer: E(data || padding) || MACt."""
    iv = ev2._full_iv(card, (0x5A, 0xA5))
    enc = ev2._aes_cbc_iv(card.k_enc, iv, ev2._pad_full(data), encrypt=True)
    return enc + card.response_mac(0x00, enc)


def _mac_answer(card: ev2.Ev2Session, data: bytes) -> bytes:
    """A MAC-mode file's answer to the same command: data || MACt."""
    return data + card.response_mac(0x00, data)


def _full_read(answer: bytes, length: int) -> bytes:
    conn = QueueConn([(answer, 0x91, 0x00)])
    header = DesfireTransport.data_header(1, 0, length)
    return ev2.command_full(
        DesfireTransport(CardSession(conn)),
        _full_session(),
        df.CMD_READ_DATA,
        header=header,
        response_len=length,
    )


@pytest.mark.parametrize(
    "data",
    [bytes.fromhex("04958CAA5C5E80"), bytes(4), bytes(range(16))],
    ids=["ends-in-80", "zeros", "block-aligned"],
)
def test_full_read_strips_exactly_the_padding(data):
    # AN12196 table 28: a UID ending in 0x80 is followed by the 0x80 that starts the padding.
    assert _full_read(_full_answer(_card_side(), data), len(data)) == data


@pytest.mark.parametrize(
    ("answer", "length", "message"),
    [
        pytest.param(
            _mac_answer(_card_side(), bytes(range(0x41, 0x51))),
            16,
            "not FULL-mode ciphertext",
            id="mac-mode-aligned",
        ),
        pytest.param(
            _mac_answer(_card_side(), bytes(range(0x41, 0x55))),
            20,
            "not FULL-mode ciphertext",
            id="mac-mode-unaligned",
        ),
        pytest.param(
            _full_answer(_card_side(), bytes(8)), 16, "expected 16 bytes, got 8", id="short"
        ),
    ],
)
def test_full_read_refuses_what_is_not_padded_ciphertext_of_the_length(answer, length, message):
    with pytest.raises(ev2.Ev2Error, match=message):
        _full_read(answer, length)


class _AnswersAfterAuth(FakeEv2Card):
    """Authenticates for real, then answers the next command with ``answer(card_side)``."""

    def __init__(self, answer, key: bytes) -> None:
        super().__init__(key, RNDB, ti=bytes.fromhex("A1B2C3D4"))
        self.answer = answer

    def transmit(self, apdu):
        if bytes(apdu)[1] in (ev2.CMD_AUTHENTICATE_EV2_FIRST, ev2.CMD_ADDITIONAL_FRAME):
            return super().transmit(apdu)
        if self.rnda is None:
            return [], 0x91, 0x00
        k_enc, k_mac = ev2.derive_session_keys(self.key, self.rnda, self.rndb)
        return list(self.answer(_card_side(k_enc, k_mac, self.ti))), 0x91, 0x00


@pytest.mark.parametrize("length", [16, 20])
def test_full_read_of_a_mac_mode_file_fails_and_writes_nothing(monkeypatch, tmp_path, length):
    data = bytes(range(0x41, 0x41 + length))
    wire_session(monkeypatch, _AnswersAfterAuth(lambda card: _mac_answer(card, data), bytes(16)))
    out = tmp_path / "file01.bin"
    args = ["--json", "mifare", "read", "--aid", "010203", "--file-id", "01", "--full"]
    result = run([*args, "--length", str(length), "--zero-key", "--out", str(out)])
    assert result.exit_code == ev2.Ev2Error.exit_code, result.output
    assert not out.exists()


VALUE_GET = ["--json", "mifare", "value", "get", "--aid", "010203", "--file-id", "03", "--zero-key"]


def test_value_get_reads_a_mac_mode_value_file(monkeypatch):
    value = (1234).to_bytes(4, "little", signed=True)
    wire_session(monkeypatch, _AnswersAfterAuth(lambda card: _mac_answer(card, value), bytes(16)))
    result = run(VALUE_GET)
    assert result.exit_code == 0, result.output
    assert '"value": 1234' in result.output


def test_value_get_of_a_full_mode_value_file_fails(monkeypatch):
    value = (1234).to_bytes(4, "little", signed=True)
    wire_session(monkeypatch, _AnswersAfterAuth(lambda card: _full_answer(card, value), bytes(16)))
    result = run(VALUE_GET)
    assert result.exit_code == 1, result.output
    assert "GetValue: expected 4 bytes, got 16" in result.output
