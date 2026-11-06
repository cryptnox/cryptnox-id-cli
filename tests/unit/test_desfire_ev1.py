"""DESFire EV1 secure messaging for a 2K3DES PICC master key (AuthenticateISO).

The CMAC is checked against cryptography's own CMAC; the handshake, FormatPICC and
ChangeKey run against a card double that plays the card's side of the EV1 scheme.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import cmac as crypto_cmac
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from cryptnox_id_cli.applets.mifare import desfire as df
from cryptnox_id_cli.applets.mifare import ev1
from cryptnox_id_cli.applets.mifare.ev2 import desfire_crc32
from cryptnox_id_cli.cli.commands import mifare as mifare_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.transport.errors import CryptnoxError


def _cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    c = Cipher(TripleDES(key + key[:8]), modes.CBC(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def _rol(b: bytes) -> bytes:
    return b[1:] + b[:1]


@pytest.mark.parametrize("length", [0, 1, 7, 8, 9, 16, 23])
def test_cmac_matches_sp800_38b(length):
    key = os.urandom(16)
    data = os.urandom(length)
    reference = crypto_cmac.CMAC(TripleDES(key + key[:8]))
    reference.update(data)
    assert ev1.cmac(key, bytes(8), data) == reference.finalize()


@pytest.mark.parametrize(
    ("message", "mac"),
    [("", "bd2ebf9a3ba00361"), ("6bc1bee22e409f96", "4ff2ab813c53ce83")],
)
def test_cmac_known_answer_two_key_tdea(message, mac):
    """NIST SP 800-38B, two-key TDEA examples."""
    key = bytes.fromhex("4cf15134a2850dd58a3d10ba80570d38")
    assert ev1.cmac(key, bytes(8), bytes.fromhex(message)).hex() == mac


def test_session_key_for_des_and_2k3des():
    rnd_a = bytes(range(1, 9))
    rnd_b = bytes(range(0x11, 0x19))
    assert ev1.session_key(bytes(16), rnd_a, rnd_b) == bytes.fromhex(
        "01020304111213140102030411121314"
    )
    key = bytes(8) + b"\x01" * 8
    assert ev1.session_key(key, rnd_a, rnd_b) == bytes.fromhex("01020304111213140506070815161718")


class Card:
    """The card's side of AuthenticateISO, FormatPICC and ChangeKey (EV1 scheme)."""

    def __init__(self, key: bytes, *, rule: str = "spec", mac_settings: bool = True) -> None:
        self.key = key
        self.rule = rule
        self.mac_settings = mac_settings
        self.rnd_b = os.urandom(8)
        self.session: bytes | None = None
        self.iv = bytes(8)
        self.formatted = False
        self.new_key: bytes | None = None
        self._enc_b = b""

    def raw_command(self, cmd: int, data: bytes = b"", *, context=None) -> tuple[int, bytes]:
        if cmd == ev1.CMD_AUTHENTICATE_ISO:
            self._enc_b = _cbc(self.key, bytes(8), self.rnd_b, True)
            return df.STATUS_ADDITIONAL_FRAME, self._enc_b
        if cmd == df.CMD_ADDITIONAL_FRAME:
            plain = _cbc(self.key, self._enc_b, data, False)
            rnd_a, rnd_b_rot = plain[:8], plain[8:]
            if rnd_b_rot != _rol(self.rnd_b):
                return 0xAE, b""
            if self.rule == "3des":
                self.session = rnd_a[:4] + self.rnd_b[:4] + rnd_a[4:8] + self.rnd_b[4:8]
            else:
                self.session = ev1.session_key(self.key, rnd_a, self.rnd_b)
            self.iv = bytes(8)
            return df.STATUS_OK, _cbc(self.key, data[-8:], _rol(rnd_a), True)
        if cmd == df.CMD_GET_KEY_SETTINGS:
            self.iv = ev1.cmac(self.session, self.iv, bytes([cmd]))
            data = b"\x0f\x01"
            if not self.mac_settings:
                return df.STATUS_OK, data
            mac = ev1.cmac(self.session, self.iv, data + bytes([df.STATUS_OK]))
            self.iv = mac
            return df.STATUS_OK, data + mac
        if cmd == df.CMD_FORMAT_PICC:
            assert self.session is not None
            self.iv = ev1.cmac(self.session, self.iv, bytes([cmd]))
            self.formatted = True
            mac = ev1.cmac(self.session, self.iv, bytes([df.STATUS_OK]))
            return df.STATUS_OK, mac
        if cmd == df.CMD_CHANGE_KEY:
            assert self.session is not None
            key_no, cryptogram = data[0], data[1:]
            plain = _cbc(self.session, self.iv, cryptogram, False)
            body, crc = plain[:17], plain[17:21]
            if key_no != 0x80 or crc != desfire_crc32(bytes([cmd, key_no]) + body):
                return 0x1E, b""
            self.new_key = body[:16]
            return df.STATUS_OK, b""
        return 0x1C, b""


@pytest.mark.parametrize("key", [bytes(16), bytes(8) + b"\x02" * 8])
def test_authenticate_and_format(key):
    card = Card(key)
    session = ev1.authenticate_iso(card, 0, key)
    assert session.key == card.session
    ev1.format_picc_iso(card, session)
    assert card.formatted


def test_the_card_s_session_key_form_wins_over_the_host_s_guess():
    """Identical halves on the host, but the card derives the 2K3DES form."""
    card = Card(bytes(16), rule="3des")
    session = ev1.authenticate_iso(card, 0, bytes(16))
    assert session.key == card.session
    ev1.format_picc_iso(card, session)
    assert card.formatted


def test_no_session_key_form_matches_and_nothing_is_changed():
    card = Card(bytes(16))
    original = card.raw_command

    def corrupt(cmd, data=b"", *, context=None):
        status, out = original(cmd, data, context=context)
        if cmd == df.CMD_GET_KEY_SETTINGS:
            out = out[:-1] + bytes([out[-1] ^ 1])
        return status, out

    card.raw_command = corrupt
    with pytest.raises(CryptnoxError, match="nothing was changed"):
        ev1.authenticate_iso(card, 0, bytes(16))
    assert not card.formatted


def test_a_card_without_a_settings_mac_keeps_the_host_s_form():
    card = Card(bytes(16), mac_settings=False)
    session = ev1.authenticate_iso(card, 0, bytes(16))
    assert session.key == card.session


def test_a_wrong_key_is_refused_by_the_card():
    card = Card(bytes(16))
    with pytest.raises(df.DesfireError):
        ev1.authenticate_iso(card, 0, b"\x02" * 16)


def test_a_bad_response_mac_is_reported():
    card = Card(bytes(16))
    session = ev1.authenticate_iso(card, 0, bytes(16))
    session.iv = b"\xff" * 8
    with pytest.raises(CryptnoxError, match="MAC does not verify"):
        ev1.format_picc_iso(card, session)


def test_change_picc_key_to_aes():
    card = Card(bytes(16))
    new_key = os.urandom(16)
    ev1.change_picc_key_to_aes(card, ev1.authenticate_iso(card, 0, bytes(16)), new_key)
    assert card.new_key == new_key


def test_change_key_crc_covers_the_header():
    card = Card(bytes(16))
    session = ev1.authenticate_iso(card, 0, bytes(16))
    session.iv = bytes(8)
    card.iv = bytes(8)
    header = bytes([df.CMD_CHANGE_KEY, 0x80])
    body = bytes(16) + b"\x00"
    plain = body + desfire_crc32(header + body) + bytes(3)
    expected = _cbc(session.key, session.iv, plain, True)
    sent = []
    card.raw_command = lambda cmd, data=b"", context=None: (sent.append(data), (0, b""))[1]
    ev1.change_picc_key_to_aes(card, session, bytes(16))
    assert sent == [b"\x80" + expected]


# ------------------------------------------------------------------ CLI --- #


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Dtx:
    key_type = 0x00
    hw_major = 0x42
    sw_major = 0x02
    card: Card | None = None

    def get_version(self):
        hw = bytes([0x04, 0x01, 0x01, self.hw_major, 0x00, 0x18, 0x05])
        sw = bytes([0x04, 0x01, 0x01, self.sw_major, 0x00, 0x18, 0x05])
        return df.parse_version(hw + sw + bytes(14))

    def __init__(self, session) -> None:
        pass

    def select_application(self, aid) -> None:
        pass

    def get_key_settings(self):
        return 0x0F, self.key_type, 1

    def raw_command(self, cmd, data=b"", *, context=None):
        return self.card.raw_command(cmd, data, context=context)


@pytest.fixture
def wired(monkeypatch):
    def wire(key_type: int, card: Card):
        monkeypatch.setattr(AppContext, "open_session", lambda self: _Session())
        monkeypatch.setattr(_Dtx, "key_type", key_type)
        monkeypatch.setattr(_Dtx, "card", card)
        monkeypatch.setattr(mifare_cmd, "DesfireTransport", _Dtx)
        ev2: list = []
        monkeypatch.setattr(
            mifare_cmd, "authenticate_ev2_first", lambda dtx, no, key: ev2.append(key) or object()
        )
        monkeypatch.setattr(mifare_cmd, "format_picc", lambda dtx, s: ev2.append("format"))
        return ev2

    return wire


def _run(*args, **kw):
    return CliRunner().invoke(root, list(args), **kw)


FORMAT = ("mifare", "format", "--zero-key", "--i-understand-this-erases-all-applications")


def test_format_with_a_2k3des_picc_key(wired):
    card = Card(bytes(16))
    ev2 = wired(0x00, card)
    result = _run(*FORMAT)
    assert result.exit_code == 0, result.output
    assert card.formatted and ev2 == []


def test_format_with_an_aes_picc_key_keeps_the_ev2_path(wired):
    card = Card(bytes(16))
    ev2 = wired(0x80, card)
    result = _run(*FORMAT)
    assert result.exit_code == 0, result.output
    assert ev2 == [bytes(16), "format"] and not card.formatted


def test_format_refuses_a_3k3des_picc_key(wired):
    wired(0x40, Card(bytes(16)))
    result = _run(*FORMAT)
    assert result.exit_code != 0 and "3K3DES" in result.output


def test_picc_to_aes_changes_and_verifies(wired, monkeypatch):
    card = Card(bytes(16))
    ev2 = wired(0x00, card)
    new_key = os.urandom(16)
    monkeypatch.setenv("NEW_PICC_KEY", new_key.hex())
    result = _run(
        "--yes", "mifare", "keys", "picc-to-aes", "--zero-key", "--new-key-env", "NEW_PICC_KEY"
    )
    assert result.exit_code == 0, result.output
    assert card.new_key == new_key and ev2 == [new_key]


def test_picc_to_aes_asks_first(wired):
    card = Card(bytes(16))
    wired(0x00, card)
    result = _run("mifare", "keys", "picc-to-aes", "--zero-key", "--new-zero-key", input="n\n")
    assert result.exit_code != 0 and card.new_key is None
    assert "publicly known all-zero key" in result.output


def test_picc_to_aes_refuses_an_aes_picc_key(wired):
    wired(0x80, Card(bytes(16)))
    result = _run("--yes", "mifare", "keys", "picc-to-aes", "--zero-key", "--new-zero-key")
    assert result.exit_code != 0 and "already AES" in result.output


@pytest.mark.parametrize("extra", [[], ["--new-zero-key", "--new-key-env", "X"]])
def test_picc_to_aes_needs_one_new_key(extra):
    result = _run("mifare", "keys", "picc-to-aes", "--zero-key", *extra)
    assert result.exit_code == 2


def test_picc_to_aes_refuses_ev1_before_asking(wired, monkeypatch):
    card = Card(bytes(16))
    wired(0x00, card)
    monkeypatch.setattr(_Dtx, "hw_major", 0x01)
    monkeypatch.setattr(_Dtx, "sw_major", 0x01)
    result = _run("mifare", "keys", "picc-to-aes", "--zero-key", "--new-zero-key")
    assert result.exit_code != 0 and "EV1" in result.output
    assert card.new_key is None and "Replace the PICC master key?" not in result.output


@pytest.mark.parametrize("version", ["256", "-1"])
def test_picc_to_aes_key_version_is_one_byte(version):
    result = _run(
        "mifare", "keys", "picc-to-aes", "--zero-key", "--new-zero-key", "--key-version", version
    )
    assert result.exit_code == 2


def test_the_iso_handshake_is_redacted_in_the_transcript():
    from cryptnox_id_cli.secrets.redaction import Redactor

    r = Redactor()
    token = bytes(range(16))
    assert token.hex().upper() not in r.redact_command(b"\x90\xaf\x00\x00\x10" + token + b"\x00")
    enc_b = bytes(range(8))
    assert enc_b.hex().upper() not in r.redact_response(enc_b, 0x91, 0xAF, ins=0x1A)
