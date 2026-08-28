"""PIV SELECT must survive the 6700 the multi-applet card returns for the first
case-4 ISO SELECT issued right after a DESFire native-command session (seen on a
contactless reader). The identical SELECT sent as case-3 (no Le) is accepted."""

from __future__ import annotations

from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.transport.errors import AppletNotFoundError
from cryptnox_id_cli.transport.pcsc import CardSession

# The APT (tag 61) the real OpenFIPS201 applet returns from SELECT.
_APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230"
    "315F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
_SELECT_CASE4 = "00A404000BA00000030800001000010000"  # data + Le=00
_SELECT_CASE3 = "00A404000BA000000308000010000100"  # data, no Le


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
            return [], 0x6A, 0x82
        data_hex, sw_hex = spec.split("|")
        data = list(bytes.fromhex(data_hex)) if data_hex else []
        sw = bytes.fromhex(sw_hex)
        return data, sw[0], sw[1]

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B8580018073C821100E")

    def disconnect(self) -> None:  # pragma: no cover - nothing to release
        pass


def test_select_retries_case3_when_case4_returns_6700():
    conn = _DictConn({_SELECT_CASE4: "|6700", _SELECT_CASE3: f"{_APT}|9000"})
    apt = PivApplet(CardSession(conn)).select()
    assert apt.label == "OpenFIPS201"
    # It must actually fall back to the case-3 (no-Le) form, not just succeed.
    assert conn.sent == [_SELECT_CASE4, _SELECT_CASE3]


def test_select_does_not_retry_when_case4_succeeds():
    conn = _DictConn({_SELECT_CASE4: f"{_APT}|9000"})
    apt = PivApplet(CardSession(conn)).select()
    assert apt.label == "OpenFIPS201"
    assert conn.sent == [_SELECT_CASE4]  # no second attempt


def test_select_absent_applet_still_raises_not_found():
    # A card without PIV answers 6A82; the 6700 retry must not mask that.
    apt_conn = _DictConn({})
    try:
        PivApplet(CardSession(apt_conn)).select()
    except AppletNotFoundError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected AppletNotFoundError for an absent PIV applet")
