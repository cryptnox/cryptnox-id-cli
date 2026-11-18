# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""An SCP03 double that answers secured commands, and a PIV applet responder behind it.

Together they take ``piv perso`` commands past the secure channel: the double checks
each C-MAC and strips C-ENC, and the responder holds the slot key, so on-card
signatures verify.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from test_scp03 import GP_KEY, FakeScp03Card

from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.transport.scp03 import Scp03Keys, _aes_cmac, _aes_ecb, derive_session_keys
from cryptnox_id_cli.util import tlv

OK = (b"", 0x90, 0x00)


class UnwrappingScp03Card(FakeScp03Card):
    """FakeScp03Card that checks the C-MAC, strips C-ENC and answers secured commands.

    Secured commands go to ``on_secured(ins, p1, p2, body)`` and land decrypted in
    ``secured``; plain ones go to ``on_plain(raw)``. Each INITIALIZE UPDATE starts a
    fresh channel, as the applet requires per perso primitive.
    """

    def __init__(self, on_secured=None, on_plain=None, keys=None):
        super().__init__(keys or Scp03Keys.same(GP_KEY), bytes.fromhex("1122334455667788"))
        self.on_secured = on_secured or (lambda ins, p1, p2, body: OK)
        self.on_plain = on_plain or (lambda raw: (b"", 0x6D, 0x00))
        self.secured: list[tuple[int, int, int, bytes]] = []

    def transmit(self, apdu):
        raw = bytes(apdu)
        if raw[1] == 0x50:
            reply = super().transmit(raw)
            self._s_enc = derive_session_keys(self.keys, self.host_challenge, self.card_challenge)[
                0
            ]
            return reply
        if raw[:2] == b"\x84\x82":
            reply = super().transmit(raw)
            self._chain, self._counter = _aes_cmac(self.s_mac, bytes(16) + raw[:-8]), 1
            return reply
        if not raw[0] & 0x04:
            return self.on_plain(raw)
        start, lc = (7, int.from_bytes(raw[5:7], "big")) if raw[4] == 0 else (5, raw[4])
        data, mac = raw[start : start + lc - 8], raw[start + lc - 8 : start + lc]
        full = _aes_cmac(self.s_mac, self._chain + raw[:start] + data)
        if full[:8] != mac:
            return b"", 0x69, 0x88
        self._chain = full
        if data:
            icv = _aes_ecb(self._s_enc, self._counter.to_bytes(16, "big"))
            dec = Cipher(algorithms.AES(self._s_enc), modes.CBC(icv)).decryptor()
            data = (dec.update(data) + dec.finalize()).rstrip(b"\x00")[:-1]
        self._counter += 1
        self.secured.append((raw[1], raw[2], raw[3], data))
        return self.on_secured(raw[1], raw[2], raw[3], data)


def _body(raw: bytes) -> bytes:
    return raw[5 : 5 + raw[4]] if len(raw) > 5 else b""


class PivResponder:
    """Plain PIV answers (SELECT, VERIFY, GET DATA, GENERAL AUTHENTICATE) plus on-card
    GENERATE over the secured channel. Holds the slot key, so signatures verify."""

    def __init__(self, apt: bytes, *, pin=b"123456", status=None, objects=None, key=None):
        self.apt, self.pin, self.key = apt, pin, key
        self.status = status or {0x80: (0x6A, 0x88), 0x81: (0x6A, 0x88)}
        self.objects = objects or {}
        self.sign_sw: tuple[int, int] | None = None
        self.probe_sw = (0x69, 0x82)
        self.secured_sw: dict[int, tuple[int, int]] = {}

    def plain(self, raw: bytes):
        ins, body = raw[1], _body(raw)
        if ins == 0xA4:
            return (self.apt, 0x90, 0x00) if pivc.PIV_AID in raw else (b"", 0x6A, 0x82)
        if ins == 0x20:
            if not body:
                return (b"", *self.status[raw[3]])
            if self.pin is None:
                return b"", 0x6A, 0x88
            return OK if body[:8] == self.pin.ljust(8, b"\xff") else (b"", 0x63, 0xC2)
        if ins == 0xCB:
            oid = body[2 : 2 + body[1]]
            if oid[:2] == b"\x2f\x47":
                return b"", 0x69, 0x86
            value = self.objects.get(oid)
            return (tlv.build(0x53, value), 0x90, 0x00) if value else (b"", 0x6A, 0x82)
        if ins == 0x87:
            digest = tlv.find(tlv.parse(body), 0x81).value
            if digest == b"\x00":
                return (b"", *self.probe_sw)
            if self.sign_sw:
                return (b"", *self.sign_sw)
            alg = hashes.SHA256() if len(digest) == 32 else hashes.SHA384()
            sig = self.key.sign(digest, ec.ECDSA(utils.Prehashed(alg)))
            return tlv.build_constructed(0x7C, tlv.build(0x82, sig)), 0x90, 0x00
        return b"", 0x6D, 0x00

    def secured(self, ins: int, p1: int, p2: int, body: bytes):
        if ins in self.secured_sw:
            return (b"", *self.secured_sw[ins])
        if (ins, p1, p2) == (0x24, 0xFF, 0x80):
            self.pin = body.rstrip(b"\xff")
        if ins == 0x47:
            curve = ec.SECP256R1() if body[-1] == 0x11 else ec.SECP384R1()
            self.key = ec.generate_private_key(curve)
            point = self.key.public_key().public_numbers()
            raw = b"\x04" + point.x.to_bytes(curve.key_size // 8, "big")
            raw += point.y.to_bytes(curve.key_size // 8, "big")
            return tlv.build_constructed(0x7F49, tlv.build(0x86, raw)), 0x90, 0x00
        return OK
