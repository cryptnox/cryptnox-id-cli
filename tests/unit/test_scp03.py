"""Offline SCP03 tests, including a full handshake against a simulated card."""

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import Scp03Error
from cryptnox_id_cli.transport.scp03 import (
    SL_CMAC_CENC,
    Scp03Keys,
    Scp03Session,
    _aes_cmac,
    _aes_ecb,
    _cryptogram,
    _kdf,
    _pad80,
    derive_session_keys,
    open_channel,
)

GP_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")


def test_kdf_lengths():
    k = bytes(16)
    assert len(_kdf(k, 0x04, bytes(16), 128)) == 16
    assert len(_kdf(k, 0x00, bytes(16), 64)) == 8
    assert len(_kdf(k, 0x04, bytes(16), 256)) == 32  # two CMAC blocks


def test_kdf_first_block_matches_cmac():
    k, ctx = bytes(16), bytes(16)
    block = b"\x00" * 11 + bytes([0x04]) + b"\x00" + (128).to_bytes(2, "big") + bytes([1]) + ctx
    assert _kdf(k, 0x04, ctx, 128) == _aes_cmac(k, block)


def test_session_keys_distinct():
    s_enc, s_mac, s_rmac = derive_session_keys(Scp03Keys.same(GP_KEY), bytes(8), bytes(8))
    assert len({s_enc, s_mac, s_rmac}) == 3
    assert all(len(k) == 16 for k in (s_enc, s_mac, s_rmac))


def test_pad80():
    assert _pad80(b"\x01\x02\x03") == b"\x01\x02\x03\x80" + b"\x00" * 12
    assert _pad80(bytes(16)) == bytes(16) + b"\x80" + b"\x00" * 15


def test_wrap_sets_sm_bit_and_appends_mac():
    sess = Scp03Session(bytes(16), bytes(16), bytes(16), SL_CMAC_CENC)
    wrapped = sess.wrap(APDU(0x00, 0xCB, 0x3F, 0xFF, data=bytes.fromhex("5C035FC109"), le=256))
    assert wrapped[0] == 0x04  # SM bit set on CLA 0x00
    assert wrapped[-1] == 0x00  # Le preserved
    body = wrapped[:-1]
    lc = body[4]
    assert (lc - 8) % 16 == 0  # encrypted data is block-aligned
    mac = body[-8:]
    full = _aes_cmac(bytes(16), b"\x00" * 16 + body[:-8])
    assert mac == full[:8]


def test_cenc_roundtrip():
    s_enc = bytes(range(16))
    sess = Scp03Session(s_enc, bytes(16), bytes(16), SL_CMAC_CENC)
    data = b"hello world"
    ct = sess._encrypt(data)
    assert len(ct) == 16
    icv = _aes_ecb(s_enc, (1).to_bytes(16, "big"))
    dec = Cipher(algorithms.AES(s_enc), modes.CBC(icv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    assert pt.startswith(data) and pt[len(data)] == 0x80


class FakeScp03Card:
    """A minimal SCP03 card that mirrors the spec, to exercise open_channel offline."""

    def __init__(self, keys: Scp03Keys, card_challenge: bytes) -> None:
        self.keys = keys
        self.card_challenge = card_challenge
        self.host_challenge = b""
        self.s_mac = b""

    def transmit(self, apdu):
        raw = apdu.to_bytes() if isinstance(apdu, APDU) else bytes(apdu)
        if raw[1] == 0x50:  # INITIALIZE UPDATE
            self.host_challenge = raw[5:13]
            _, self.s_mac, _ = derive_session_keys(
                self.keys, self.host_challenge, self.card_challenge
            )
            card_crypto = _cryptogram(self.s_mac, 0x00, self.host_challenge, self.card_challenge)
            body = b"\x00" * 10 + bytes([0x00, 0x03, 0x60]) + self.card_challenge + card_crypto
            return Response(body, 0x90, 0x00)
        if raw[1] == 0x82:  # EXTERNAL AUTHENTICATE
            host_recv, mac_recv = raw[5:13], raw[13:21]
            host_exp = _cryptogram(self.s_mac, 0x01, self.host_challenge, self.card_challenge)
            full = _aes_cmac(self.s_mac, b"\x00" * 16 + raw[0:5] + host_recv)
            ok = host_recv == host_exp and mac_recv == full[:8]
            return Response(b"", 0x90, 0x00) if ok else Response(b"", 0x69, 0x88)
        return Response(b"", 0x6D, 0x00)


def test_open_channel_loopback_succeeds():
    keys = Scp03Keys.same(GP_KEY)
    card = FakeScp03Card(keys, bytes.fromhex("1122334455667788"))
    sess = open_channel(card.transmit, keys, host_challenge=bytes.fromhex("AABBCCDDEEFF0011"))
    assert isinstance(sess, Scp03Session)
    assert len(sess.s_enc) == 16
    assert sess.mac_chaining != b"\x00" * 16  # advanced by EXTERNAL AUTHENTICATE


def test_open_channel_wrong_keys_raises():
    card = FakeScp03Card(Scp03Keys.same(GP_KEY), bytes(8))
    with pytest.raises(Scp03Error, match="cryptogram mismatch"):
        open_channel(card.transmit, Scp03Keys.same(bytes(16)), host_challenge=bytes(8))
