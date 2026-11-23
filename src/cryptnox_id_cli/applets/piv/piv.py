# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Read-only PIV applet operations over a :class:`CardSession`."""

from __future__ import annotations

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv import objects as obj
from cryptnox_id_cli.applets.piv.apt import APTInfo, parse_apt
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import AppletNotFoundError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession


class PivApplet:
    """Thin, read-only PIV client. PIN and PUK commands live in :mod:`.verifier`."""

    def __init__(self, session: CardSession) -> None:
        self.session = session
        self._apt: APTInfo | None = None

    # -- selection ---------------------------------------------------------- #
    def select(self) -> APTInfo:
        resp = self.session.transmit(
            APDU(0x00, c.INS_SELECT, 0x04, 0x00, data=c.PIV_AID, le=256), context="SELECT PIV"
        )
        # On the multi-applet card, the first case-4 ISO SELECT issued right after a
        # DESFire native-command session is rejected with 6700 ("wrong length"); the
        # identical SELECT sent as case-3 (no Le) is accepted and still returns the
        # FCI. The composite StateDetector probes DESFire first, so without this the
        # PIV applet is mis-reported as Unknown over a contactless reader. Retry once
        # without Le. See docs/troubleshooting.md.
        if resp.sw == 0x6700:
            resp = self.session.transmit(
                APDU(0x00, c.INS_SELECT, 0x04, 0x00, data=c.PIV_AID), context="SELECT PIV (no Le)"
            )
        if resp.sw == 0x6A82:
            raise AppletNotFoundError("PIV applet not found on this card.")
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context="SELECT PIV")
        self._apt = parse_apt(resp.data)
        return self._apt

    def try_select(self) -> APTInfo | None:
        try:
            return self.select()
        except AppletNotFoundError:
            return None

    @property
    def apt(self) -> APTInfo | None:
        return self._apt

    # -- data objects ------------------------------------------------------- #
    def get_data(self, oid: bytes) -> Response:
        return self.session.transmit(obj.get_data_apdu(oid), context="GET DATA")

    def get_data_extended(self, ident: int, index: int = 0) -> Response:
        """Vendor GET DATA (``2F47xx``): version, status, config, structure listing."""
        return self.session.transmit(
            obj.get_data_extended_apdu(ident, index), context=f"GET DATA 2F{ident:04X}"
        )

    def read_object(self, oid: bytes) -> bytes | None:
        """Return the unwrapped object content, or None if absent (6A82)."""
        resp = self.get_data(oid)
        if resp.sw == 0x6A82:
            return None
        if not resp.ok:
            # Access-gated objects (e.g. PIN-protected) may return 6982 — surface as absent-ish.
            if resp.sw in (0x6982, 0x6983):
                return None
            raise StatusWordError(resp.sw1, resp.sw2, context="GET DATA")
        return obj.unwrap(oid, resp.data)

    def object_present(self, oid: bytes) -> bool:
        """True if the object holds content (or exists but is access-gated).

        Two distinct "absent" cases per SP 800-73 4.1.1 (same clause in -4 and
        -5): a container never created at pre-personalization returns 6A82,
        while a created-but-unused container returns a zero-length object
        (9000). Both count as absent, and so does a read that failed.
        """
        return self.object_state(oid) is True

    def object_state(self, oid: bytes) -> bool | None:
        """Like :meth:`object_present`, but ``None`` when the read failed, so the
        object may exist."""
        resp = self.get_data(oid)
        if resp.sw in (0x6982, 0x6983):  # exists but access-gated still counts
            return True
        if resp.sw == 0x6A82:
            return False
        if not resp.ok:
            return None
        return bool(obj.unwrap(oid, resp.data))
