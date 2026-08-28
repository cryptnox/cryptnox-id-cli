"""Read-only client for the Cryptnox Genuineness / attestation applet."""

from __future__ import annotations

from dataclasses import dataclass

from cryptnox_id_cli.applets.genuine import constants as c
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import AppletNotFoundError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession


@dataclass
class GenuinenessInfo:
    """The 4-byte GET INFO blob, kept raw (the applet's field layout is not
    documented here — we report what the card returns and never guess a verdict
    from it)."""

    raw: bytes

    @property
    def hex(self) -> str:
        return self.raw.hex().upper()

    def to_dict(self) -> dict[str, object]:
        return {"raw": self.hex}


class GenuinenessApplet:
    def __init__(self, session: CardSession) -> None:
        self.session = session

    # -- selection ---------------------------------------------------------- #
    def select(self) -> None:
        """SELECT the applet. Raises AppletNotFoundError on 6A82 (also returned on a
        contactless interface, where this contact-only applet does not answer)."""
        resp = self.session.transmit(
            APDU(0x00, 0xA4, 0x04, 0x00, data=c.GENUINE_AID, le=256), context="SELECT GENUINE"
        )
        # Same multi-applet quirk as PIV: the first case-4 ISO SELECT after a DESFire
        # native session is rejected with 6700; retry once as case-3 (no Le).
        if resp.sw == 0x6700:
            resp = self.session.transmit(
                APDU(0x00, 0xA4, 0x04, 0x00, data=c.GENUINE_AID), context="SELECT GENUINE (no Le)"
            )
        # 6A82 = AID not found (card manager). 6D00 = INS A4 not supported by whatever
        # applet happens to be selected (e.g. U2F left selected by a preceding FIDO probe):
        # the genuineness AID is not selectable there, indistinguishable from absent. A real
        # genuineness applet answers its own SELECT with 9000, so neither can be a present one.
        if resp.sw in (0x6A82, 0x6D00):
            raise AppletNotFoundError("Genuineness applet not found on this card/interface.")
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context="SELECT GENUINE")

    def try_select(self) -> bool:
        try:
            self.select()
            return True
        except AppletNotFoundError:
            return False

    # -- open (no-auth) reads ----------------------------------------------- #
    def get_info(self) -> GenuinenessInfo | None:
        resp = self.session.transmit(
            APDU(0x80, c.INS_GET_INFO, 0x00, 0x00, le=256), context="GENUINE GET INFO"
        )
        return GenuinenessInfo(resp.data) if resp.ok else None

    def get_cert(self, which: int = c.CERT_LEAF) -> bytes | None:
        """Read a stored DER certificate (CERT_LEAF / CERT_INTERMEDIATE). Free-read —
        works even on a fused card. Returns None when absent or unreadable."""
        resp = self.session.transmit(
            APDU(0x80, c.INS_GET_CERT, which, 0x00, le=65536), context="GENUINE GET CERT"
        )
        return resp.data if (resp.ok and resp.data) else None

    def attest(self, nonce: bytes) -> bytes:
        """ATTEST a host nonce: the card returns ECDSA(SHA-256) over
        ``ATTEST_LABEL || nonce`` signed by the on-card device private key."""
        resp = self.session.transmit(
            APDU(0x80, c.INS_ATTEST, 0x00, 0x00, data=nonce), context="GENUINE ATTEST"
        )
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context="GENUINE ATTEST")
        return resp.data
