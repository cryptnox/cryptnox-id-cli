"""DESFire transport tests: native framing, 91AF frame chaining, parsers, errors."""

import pytest

from cryptnox_id_cli.applets.mifare import desfire
from cryptnox_id_cli.applets.mifare.desfire import (
    DesfireError,
    DesfireFrameTooLargeError,
    DesfireTransport,
)
from cryptnox_id_cli.transport.pcsc import CardSession


class QueueConn:
    """A RawConnection that returns queued (data, sw1, sw2) responses in order."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.sent: list[bytes] = []

    def transmit(self, apdu):
        self.sent.append(bytes(apdu))
        data, sw1, sw2 = self._responses.pop(0)
        return list(data), sw1, sw2

    def get_atr(self):
        return b""

    def disconnect(self):
        pass


def test_frame_encoding():
    assert DesfireTransport._frame(0x60).hex().upper() == "9060000000"
    assert (
        DesfireTransport._frame(0x5A, bytes.fromhex("010203")).hex().upper() == "905A00000301020300"
    )


def test_get_version_chains_three_frames():
    frames = [
        (bytes.fromhex("04810042001805"), 0x91, 0xAF),  # HW (storage 0x18 = 4K)
        (bytes.fromhex("04810142001805"), 0x91, 0xAF),  # SW
        (bytes.fromhex("0102030405060700112233445566"), 0x91, 0x00),  # UID/batch/prod
    ]
    conn = QueueConn(frames)
    version = DesfireTransport(CardSession(conn)).get_version()
    assert version.hw_vendor == 0x04
    assert version.storage_bytes == 4096
    assert version.uid.hex().upper() == "01020304050607"
    # Two GET_ADDITIONAL_FRAME (0xAF) commands were issued after the first.
    assert sum(1 for a in conn.sent if a[1] == 0xAF) == 2


def test_error_status_raises():
    conn = QueueConn([(b"", 0x91, 0xA0)])  # APPLICATION_NOT_FOUND
    with pytest.raises(DesfireError) as exc:
        DesfireTransport(CardSession(conn)).command(0x5A, bytes.fromhex("AABBCC"))
    assert exc.value.status == 0xA0


def test_parse_application_ids():
    aids = desfire.parse_application_ids(bytes.fromhex("010203AABBCC"))
    assert aids == [bytes.fromhex("010203"), bytes.fromhex("AABBCC")]


def test_status_name():
    assert desfire.status_name(0x00) == "OPERATION_OK"
    assert desfire.status_name(0xAE) == "AUTHENTICATION_ERROR"
    assert desfire.status_name(0x77) == "0x77"


def test_frame_rejects_oversized_data():
    # >255 bytes can't fit one short native frame; must be a clean error, not ValueError.
    with pytest.raises(DesfireFrameTooLargeError):
        DesfireTransport._frame(0x3D, b"\x00" * 256)


def test_create_value_file_frame():
    conn = QueueConn([(b"", 0x91, 0x00)])
    DesfireTransport(CardSession(conn)).create_value_file(0x01, 0, 1000, 100)
    sent = conn.sent[0]
    assert sent[1] == desfire.CMD_CREATE_VALUE_FILE
    body = sent[5:-1]
    assert body[0] == 0x01 and body[1] == 0x01  # file no, comm = MAC
    assert body[2:4] == b"\x00\x00"  # access 0x0000 (key-0 for all ops)
    assert body[4:8] == (0).to_bytes(4, "little", signed=True)  # lower
    assert body[8:12] == (1000).to_bytes(4, "little", signed=True)  # upper
    assert body[12:16] == (100).to_bytes(4, "little", signed=True)  # value
    assert body[16] == 0x00  # limited credit


def test_value_arg_and_parse_value():
    assert DesfireTransport.value_arg(0x01, 50).hex().upper() == "0132000000"
    assert desfire.parse_value(bytes.fromhex("64000000")) == 100
    assert desfire.parse_value((-5).to_bytes(4, "little", signed=True)) == -5
    with pytest.raises(ValueError):
        desfire.parse_value(b"\x01\x02")


def test_create_record_file_frames():
    conn = QueueConn([(b"", 0x91, 0x00)])
    DesfireTransport(CardSession(conn)).create_record_file(0x03, 8, 4)
    sent = conn.sent[0]
    assert sent[1] == desfire.CMD_CREATE_LINEAR_RECORD_FILE
    body = sent[5:-1]
    assert body[0] == 0x03 and body[1] == 0x01  # file no, comm = MAC
    assert body[2:4] == b"\x00\x00"  # access
    assert body[4:7] == (8).to_bytes(3, "little")  # record size
    assert body[7:10] == (4).to_bytes(3, "little")  # max records
    conn2 = QueueConn([(b"", 0x91, 0x00)])
    DesfireTransport(CardSession(conn2)).create_record_file(0x03, 8, 4, cyclic=True)
    assert conn2.sent[0][1] == desfire.CMD_CREATE_CYCLIC_RECORD_FILE
