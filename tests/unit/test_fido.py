"""FIDO CTAP client tests: framing, getInfo parsing, error decode, OS-block path."""

import cbor2
import pytest

from cryptnox_id_cli.applets.fido import constants as c
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client, describe_get_info
from cryptnox_id_cli.applets.fido.errors import CtapStatusError, describe_ctap
from cryptnox_id_cli.transport import elevation
from cryptnox_id_cli.transport.errors import CardAccessDeniedError
from cryptnox_id_cli.transport.pcsc import CardSession

# The real Cryptnox card's AAGUID, observed live over the ACR1252 (elevated).
AAGUID = bytes.fromhex("1d1b4e3376a147fb97a014b10d0933f1")


class QueueConn:
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


def _info_payload() -> bytes:
    info = {
        c.INFO_VERSIONS: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
        c.INFO_EXTENSIONS: ["credProtect", "hmac-secret"],
        c.INFO_AAGUID: AAGUID,
        c.INFO_OPTIONS: {"rk": True, "clientPin": False, "credMgmt": True},
        c.INFO_MAX_MSG_SIZE: 860,
        c.INFO_PIN_UV_AUTH_PROTOCOLS: [1, 2],
    }
    return b"\x00" + cbor2.dumps(info)


def test_ctap_msg_framing():
    conn = QueueConn([(b"U2F_V2", 0x90, 0x00), (b"\x00", 0x90, 0x00)])
    ctap = Ctap2Client(CardSession(conn))
    assert ctap.select() == "U2F_V2"
    ctap.command(c.CTAP_GET_INFO)
    select_apdu, msg_apdu = conn.sent
    assert select_apdu.hex().upper() == "00A4040008A0000006472F000100"
    assert msg_apdu.hex().upper() == "80100000010400"  # 80 10 00 00 Lc=01 [04] Le=00


def test_get_info_parsing():
    conn = QueueConn([(_info_payload(), 0x90, 0x00)])
    info = describe_get_info(Ctap2Client(CardSession(conn)).get_info())
    assert info["versions"] == ["U2F_V2", "FIDO_2_0", "FIDO_2_1"]
    assert info["aaguid"] == "1d1b4e33-76a1-47fb-97a0-14b10d0933f1"
    assert info["cryptnox_aaguid"] is True
    assert info["max_msg_size"] == 860
    assert info["options"]["clientPin"] is False
    assert info["pin_uv_auth_protocols"] == [1, 2]


def test_pin_retries():
    conn = QueueConn([(b"\x00" + cbor2.dumps({0x03: 8, 0x04: False}), 0x90, 0x00)])
    retries, power_cycle = Ctap2Client(CardSession(conn)).pin_retries()
    assert retries == 8 and power_cycle is False
    # The request encodes protocol 1 + subcommand getPinRetries.
    sent = conn.sent[0]
    assert sent[:4].hex().upper() == "80100000"
    assert cbor2.loads(sent[6:-1]) == {1: 1, 2: 1}


def test_ctap_error_raises_with_message():
    conn = QueueConn([(b"\x31", 0x90, 0x00)])  # CTAP2_ERR_PIN_INVALID
    with pytest.raises(CtapStatusError) as exc:
        Ctap2Client(CardSession(conn)).get_info()
    assert exc.value.status == 0x31
    assert "PIN is invalid" in str(exc.value)


def test_describe_ctap_known_and_unknown():
    assert describe_ctap(0x32)[0] == "CTAP2_ERR_PIN_BLOCKED"
    assert describe_ctap(0xEE)[0] == "CTAP_ERR_0xEE"


def test_os_block_surfaces_as_access_denied():
    class DenyConn(QueueConn):
        def transmit(self, apdu):
            raise CardAccessDeniedError("simulated", hresult=0x80100027)

    with pytest.raises(CardAccessDeniedError):
        Ctap2Client(CardSession(DenyConn([]))).select()


def test_fido_elevation_status_non_windows(monkeypatch):
    monkeypatch.setattr(elevation, "is_windows", lambda: False)
    assert elevation.fido_elevation_status() == ("ok", "")


def test_fido_elevation_status_elevated(monkeypatch):
    monkeypatch.setattr(elevation, "is_windows", lambda: True)
    monkeypatch.setattr(elevation, "is_elevated", lambda: True)
    severity, message = elevation.fido_elevation_status()
    assert severity == "ok"
    assert "elevated" in message.lower() and elevation.FIDO_REQUIREMENT in message


def test_fido_elevation_status_not_elevated_warns(monkeypatch):
    monkeypatch.setattr(elevation, "is_windows", lambda: True)
    monkeypatch.setattr(elevation, "is_elevated", lambda: False)
    severity, message = elevation.fido_elevation_status()
    assert severity == "warn"
    assert "NOT elevated" in message and "Administrator" in message


def test_fido_elevation_status_unknown_is_note(monkeypatch):
    monkeypatch.setattr(elevation, "is_windows", lambda: True)
    monkeypatch.setattr(elevation, "is_elevated", lambda: None)
    severity, message = elevation.fido_elevation_status()
    assert severity == "note" and "Could not confirm" in message


def test_elevation_messages_explain_the_reason():
    # The warning must say WHY admin is needed, not just that it is.
    assert "WebAuthn" in elevation.FIDO_REQUIREMENT
    assert "SCARD_E_NO_ACCESS" in elevation.FIDO_REQUIREMENT
    assert "WebAuthn" in elevation.FIDO_WINDOWS_MESSAGE


def test_relaunch_command_module_form(monkeypatch):
    monkeypatch.setattr(elevation.sys, "frozen", False, raising=False)
    monkeypatch.setattr(elevation.sys, "argv", ["cryptnox-id", "fido", "info"])
    program, prefix, user_args = elevation.relaunch_command()
    assert prefix == ["-m", "cryptnox_id_cli"]
    assert user_args == ["fido", "info"]
    assert program == elevation.sys.executable


def test_relaunch_command_frozen_form(monkeypatch):
    monkeypatch.setattr(elevation.sys, "frozen", True, raising=False)
    monkeypatch.setattr(elevation.sys, "argv", ["cryptnox-id.exe", "fido", "ping"])
    program, prefix, user_args = elevation.relaunch_command()
    assert prefix == []
    assert user_args == ["fido", "ping"]


def test_relaunch_elevated_non_windows_returns_none(monkeypatch):
    monkeypatch.setattr(elevation, "is_windows", lambda: False)
    assert elevation.relaunch_elevated(["--json"]) is None


def test_ctap_command_encodes_canonical_cbor():
    # CTAP2 requires canonical CBOR (sorted map keys); out-of-order input must be
    # re-ordered on the wire, else a strict authenticator returns MISSING_PARAMETER.
    conn = QueueConn([(b"\x00", 0x90, 0x00)])
    Ctap2Client(CardSession(conn)).command(0x06, {0x05: b"ee", 0x02: 3, 0x01: 1})
    body = conn.sent[0][5:-1]  # strip header(5) + Le(1) -> [cmd][cbor]
    cbor = body[1:]
    assert cbor == cbor2.dumps(cbor2.loads(cbor), canonical=True)
    # the first map key encoded is the smallest (0x01), proving keys were sorted
    assert cbor[1] == 0x01


def test_reset_sends_bare_ctap_reset():
    conn = QueueConn([(b"\x00", 0x90, 0x00)])  # status OK, no payload
    Ctap2Client(CardSession(conn)).reset()
    sent = conn.sent[0]
    assert sent[:5].hex().upper() == "8010000001"  # CTAP msg, Lc=1
    assert sent[5] == c.CTAP_RESET  # the only data byte is the reset opcode
    assert sent[6] == 0x00  # Le, no CBOR params
