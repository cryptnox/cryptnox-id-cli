"""Cardholder PIN/PUK lifecycle wire format: CHANGE REFERENCE DATA (INS 24) and
RESET RETRY COUNTER (INS 2C). Both bodies are current||new, each 0xFF-padded to 8.
No admin channel: the cardholder proves the current secret in-band."""

from __future__ import annotations

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.transport.pcsc import CardSession


class _DictConn:
    """Minimal RawConnection: maps command-APDU hex -> '<dataHex>|<swHex>'."""

    def __init__(self, exchanges: dict[str, str]) -> None:
        self._exchanges = {k.upper(): v for k, v in exchanges.items()}
        self.sent: list[str] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        key = bytes(apdu).hex().upper()
        self.sent.append(key)
        spec = self._exchanges.get(key)
        if spec is None:
            return [], 0x6A, 0x80
        data_hex, sw_hex = spec.split("|")
        data = list(bytes.fromhex(data_hex)) if data_hex else []
        sw = bytes.fromhex(sw_hex)
        return data, sw[0], sw[1]

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B8580018073C821100E")

    def disconnect(self) -> None:  # pragma: no cover - nothing to release
        pass


def test_change_pin_wire_format():
    apdu = "002400801031323334ffffffff35363738ffffffff"
    conn = _DictConn({apdu: "|9000"})
    resp = PivApplet(CardSession(conn)).change_reference(b"1234", b"5678", c.REF_PIV_PIN)
    assert resp.ok
    assert conn.sent == [apdu.upper()]


def test_change_puk_uses_ref_81():
    apdu = "002400811031323334353637383837363534333231"
    conn = _DictConn({apdu: "|9000"})
    resp = PivApplet(CardSession(conn)).change_reference(b"12345678", b"87654321", c.REF_PUK)
    assert resp.ok
    assert conn.sent == [apdu.upper()]


def test_unblock_pin_wire_format():
    apdu = "002c008010313233343536373830303030ffffffff"
    conn = _DictConn({apdu: "|9000"})
    resp = PivApplet(CardSession(conn)).unblock_pin(b"12345678", b"0000", c.REF_PIV_PIN)
    assert resp.ok
    assert conn.sent == [apdu.upper()]


def test_wrong_current_pin_surfaces_retry_counter():
    # 63C2 == two retries remain; the applet method just relays it.
    apdu = "002400801031323334ffffffff35363738ffffffff"
    conn = _DictConn({apdu: "|63C2"})
    resp = PivApplet(CardSession(conn)).change_reference(b"1234", b"5678", c.REF_PIV_PIN)
    assert not resp.ok
    assert resp.sw == 0x63C2
