"""Offline SCP02 tests: primitive known-answers and a full handshake against a sim card.

The primitive tests recompute the expected values with an independent inline
implementation (cryptography primitives directly), so they pin the derivation-block
format, the retail-MAC algorithm and the encrypt-and-MAC ordering rather than just
echoing the module. The loopback exercises ``open_channel`` + ``wrap`` end to end.
"""

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import Scp02Error
from cryptnox_id_cli.transport.scp02 import (
    SL_C_MAC,
    SL_CMAC_CENC,
    Scp02Keys,
    Scp02Session,
    _pad80,
    _retail_mac,
    derive_session_keys,
    open_channel,
)

GP_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
ZERO_IV = b"\x00" * 8


# ----------------------------------------------------------- independent refs --- #
def _ref_des3_cbc(key16: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(TripleDES(key16 + key16[:8]), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _ref_des_cbc(key16: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(TripleDES(key16[:8] * 3), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _ref_derive(static: bytes, const: bytes, seq: bytes) -> bytes:
    # GP SCP02 E.4.1: 3DES-CBC(zero IV) over const(2) | seq(2) | 00*12.
    return _ref_des3_cbc(static, ZERO_IV, const + seq + b"\x00" * 12)


def _ref_retail_mac(s_mac: bytes, data: bytes, icv: bytes) -> bytes:
    # ISO 9797-1 MAC alg 3: single-DES CBC chain over all but the last block, 3DES final.
    padded = data + b"\x80"
    while len(padded) % 8:
        padded += b"\x00"
    iv = icv
    if len(padded) > 8:
        iv = _ref_des_cbc(s_mac, iv, padded[:-8])[-8:]
    return _ref_des3_cbc(s_mac, iv, padded[-8:])[-8:]


# --------------------------------------------------------------- primitives --- #
def test_pad80_always_adds_a_block_when_aligned():
    assert _pad80(b"\x01\x02\x03") == b"\x01\x02\x03\x80" + b"\x00" * 4
    assert _pad80(bytes(8)) == bytes(8) + b"\x80" + b"\x00" * 7  # aligned -> full extra block
    assert len(_pad80(bytes(16))) == 24


def test_session_key_derivation_matches_independent_ref():
    seq = bytes.fromhex("0042")
    s_enc, s_mac, s_dek = derive_session_keys(Scp02Keys.same(GP_KEY), seq)
    assert s_enc == _ref_derive(GP_KEY, b"\x01\x82", seq)
    assert s_mac == _ref_derive(GP_KEY, b"\x01\x01", seq)
    assert s_dek == _ref_derive(GP_KEY, b"\x01\x81", seq)
    assert len({s_enc, s_mac, s_dek}) == 3  # distinct constants -> distinct keys
    assert all(len(k) == 16 for k in (s_enc, s_mac, s_dek))


def test_retail_mac_matches_independent_ref():
    s_mac = bytes(range(16))
    for data in (b"", b"\x84\x82\x03\x00\x10" + bytes(8), bytes(40)):
        assert _retail_mac(s_mac, data, ZERO_IV) == _ref_retail_mac(s_mac, data, ZERO_IV)


# --------------------------------------------------------------- wrap shape --- #
def test_wrap_sets_sm_bit_mac_over_plaintext_and_encrypts():
    s_enc, s_mac = bytes(range(16)), bytes(range(16, 32))
    sess = Scp02Session(s_enc, s_mac, bytes(16), SL_CMAC_CENC)
    apdu = APDU(0x00, 0xDB, 0x3F, 0x00, data=bytes.fromhex("6A0A640388010164"))
    wrapped = sess.wrap(apdu)

    assert wrapped[0] == 0x04  # SM bit set on CLA 0x00
    lc = wrapped[4]
    body, mac = wrapped[5 : 5 + lc - 8], wrapped[5 + lc - 8 :]
    assert len(mac) == 8
    assert (len(body)) % 8 == 0 and len(body) == lc - 8  # block-aligned C-ENC
    # The C-MAC must be over the *plaintext* modified APDU (origLc+8) with the zero ICV.
    plain = apdu.data
    mac_input = bytes([0x04, 0xDB, 0x3F, 0x00, len(plain) + 8]) + plain
    assert mac == _ref_retail_mac(s_mac, mac_input, ZERO_IV)
    # And the body must be 3DES-CBC(S-ENC, zero IV) over 80-padded plaintext.
    assert body == _ref_des3_cbc(s_enc, ZERO_IV, _pad80(plain))


def test_wrap_cmac_only_leaves_data_plaintext():
    sess = Scp02Session(bytes(16), bytes(range(16)), bytes(16), SL_C_MAC)
    apdu = APDU(0x00, 0xCA, 0x00, 0x7E, data=b"\x01\x02\x03")
    wrapped = sess.wrap(apdu)
    lc = wrapped[4]
    assert wrapped[5 : 5 + lc - 8] == b"\x01\x02\x03"  # not encrypted at SL 0x01


def test_wrap_icv_chains_between_commands():
    s_mac = bytes(range(16))
    sess = Scp02Session(bytes(16), s_mac, bytes(16), SL_C_MAC)
    first = sess.wrap(APDU(0x00, 0xCA, 0x00, 0x7E, data=b"\xaa"))
    first_mac = first[-8:]
    # Second command's ICV = single-DES-ECB(S-MAC, previous C-MAC).
    icv2 = _ref_des_cbc(s_mac, ZERO_IV, first_mac)  # CBC of one block w/ zero IV == ECB
    second = sess.wrap(APDU(0x00, 0xCA, 0x00, 0x7F, data=b"\xbb"))
    mac_input = bytes([0x04, 0xCA, 0x00, 0x7F, 1 + 8]) + b"\xbb"
    assert second[-8:] == _ref_retail_mac(s_mac, mac_input, icv2)


def test_wrap_rejects_oversized_plaintext():
    sess = Scp02Session(bytes(16), bytes(16), bytes(16), SL_CMAC_CENC)
    with pytest.raises(Scp02Error, match="short APDUs only"):
        sess.wrap(APDU(0x00, 0xDB, 0x3F, 0x00, data=bytes(240)))


# ---------------------------------------------------------- full handshake --- #
class FakeScp02Card:
    """A minimal SCP02 card mirroring GP option i=0x55, to exercise open_channel offline."""

    def __init__(self, keys: Scp02Keys, seq: bytes, card_rand: bytes) -> None:
        self.keys = keys
        self.seq = seq
        self.card_challenge = seq + card_rand  # 8-byte challenge = seq(2) | random(6)
        self.host_challenge = b""
        self.s_enc = b""

    def _card_cryptogram(self) -> bytes:
        data = self.host_challenge + self.card_challenge
        return _ref_des3_cbc(self.s_enc, ZERO_IV, _pad80(data))[-8:]

    def transmit(self, apdu):
        raw = apdu.to_bytes() if isinstance(apdu, APDU) else bytes(apdu)
        if raw[1] == 0x50:  # INITIALIZE UPDATE
            self.host_challenge = raw[5:13]
            self.s_enc = _ref_derive(self.keys.enc, b"\x01\x82", self.seq)
            body = (
                bytes(10)  # key diversification data
                + bytes([0x00, 0x02])  # key info: version, SCP id = 0x02
                + self.seq
                + self.card_challenge[2:]  # 6-byte random
                + self._card_cryptogram()
            )
            assert len(body) == 28
            return Response(body, 0x90, 0x00)
        if raw[1] == 0x82:  # EXTERNAL AUTHENTICATE
            host_recv = raw[5:13]
            host_exp = _ref_des3_cbc(
                self.s_enc, ZERO_IV, _pad80(self.card_challenge + self.host_challenge)
            )[-8:]
            return Response(b"", 0x90, 0x00) if host_recv == host_exp else Response(b"", 0x69, 0x88)
        return Response(b"", 0x6D, 0x00)


def test_open_channel_loopback_succeeds():
    keys = Scp02Keys.same(GP_KEY)
    card = FakeScp02Card(keys, bytes.fromhex("0005"), bytes.fromhex("AABBCCDDEEFF"))
    sess = open_channel(card.transmit, keys, host_challenge=bytes.fromhex("1122334455667788"))
    assert isinstance(sess, Scp02Session)
    assert sess.icv is not None  # advanced by the EXTERNAL AUTHENTICATE C-MAC


def test_open_channel_wrong_keys_raise():
    card = FakeScp02Card(Scp02Keys.same(GP_KEY), bytes.fromhex("0001"), bytes(6))
    with pytest.raises(Scp02Error, match="cryptogram mismatch"):
        open_channel(card.transmit, Scp02Keys.same(bytes(16)), host_challenge=bytes(8))


def test_open_channel_reuses_init_response():
    keys = Scp02Keys.same(GP_KEY)
    card = FakeScp02Card(keys, bytes.fromhex("0007"), bytes.fromhex("010203040506"))
    host = bytes.fromhex("99AABBCCDDEEFF00")
    init = card.transmit(APDU(0x80, 0x50, 0x00, 0x00, data=host, le=256))
    calls = []

    def transmit(a):
        calls.append(a)
        return card.transmit(a)

    sess = open_channel(transmit, keys, host_challenge=host, init_response=init)
    assert isinstance(sess, Scp02Session)
    assert len(calls) == 1  # only EXTERNAL AUTHENTICATE, no second INITIALIZE UPDATE
