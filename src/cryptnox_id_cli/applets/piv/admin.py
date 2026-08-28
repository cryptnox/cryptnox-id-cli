"""PIV administrative access over the OpenFIPS201 admin secure channel.

The PIV admin channel is the secure channel of the Security Domain the applet is
associated with: out of the box the ISD, or -- after extradition -- a dedicated PIV
admin SSD. We open the channel against the *selected PIV applet* (which handles
INITIALIZE UPDATE / EXTERNAL AUTHENTICATE), then send admin commands wrapped
(C-MAC + C-ENC).

The Security Domain may speak **SCP03** (e.g. the A484 / 180KB fleet) or **SCP02**
(the A27F / D321 / 110KB fleet, whose PIV admin SSD is an SCP02 domain). We auto-detect
from the INITIALIZE UPDATE response -- ``keyInfo[1]`` (``body[11]``) is ``0x03`` for
SCP03 and ``0x02`` for SCP02 -- and open the matching channel. Both sessions expose the
same ``wrap()`` / ``unwrap()`` contract, so the rest of this module is SCP-agnostic.
"""

from __future__ import annotations

import os

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv.objects import get_data_apdu, object_by_name
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import Scp03Error
from cryptnox_id_cli.transport.pcsc import CardSession
from cryptnox_id_cli.transport.scp02 import Scp02Keys, Scp02Session
from cryptnox_id_cli.transport.scp02 import open_channel as open_channel_scp02
from cryptnox_id_cli.transport.scp03 import Scp03Keys, Scp03Session
from cryptnox_id_cli.transport.scp03 import open_channel as open_channel_scp03

#: ``keyInfo[1]`` byte values that select the SCP version (GP INITIALIZE UPDATE response).
SCP02 = 0x02
SCP03 = 0x03

_SCP_LABELS = {SCP02: "SCP02", SCP03: "SCP03"}


def scp_label(value: object) -> str:
    """Human-readable SCP version label. ``value`` is untyped at the call sites
    (loosely-typed probe dicts, optional session attributes), so narrow here
    instead of duplicating the isinstance check at every caller."""
    return _SCP_LABELS.get(value, "unknown") if isinstance(value, int) else "unknown"


def _as_scp02_keys(keys: Scp03Keys | Scp02Keys) -> Scp02Keys:
    return keys if isinstance(keys, Scp02Keys) else Scp02Keys(keys.enc, keys.mac, keys.dek)


def _as_scp03_keys(keys: Scp03Keys | Scp02Keys) -> Scp03Keys:
    return keys if isinstance(keys, Scp03Keys) else Scp03Keys(keys.enc, keys.mac, keys.dek)


class PivAdmin:
    def __init__(self, session: CardSession) -> None:
        self.card = session
        self.scp: Scp03Session | Scp02Session | None = None
        #: which SCP the open channel uses, set by :meth:`open` (``SCP02``/``SCP03``).
        self.scp_version: int | None = None

    def select(self) -> None:
        resp = self.card.transmit(
            APDU(0x00, c.INS_SELECT, 0x04, 0x00, data=c.PIV_AID, le=256), context="SELECT PIV"
        )
        if not resp.ok:
            raise Scp03Error(f"SELECT PIV failed (SW={resp.sw_hex()}).")

    def initialize_update_probe(self, key_version: int = 0) -> dict[str, object]:
        """Read-only probe: INITIALIZE UPDATE only (auth not completed).

        Reports the SCP version from ``keyInfo[1]`` so the caller can tell an SCP02 card
        (28-byte body) from an SCP03 one (29/32-byte body)."""
        resp = self.card.transmit(
            APDU(0x80, 0x50, key_version, 0x00, data=bytes(8), le=256),
            context="INITIALIZE UPDATE (probe)",
        )
        if not resp.ok:
            raise Scp03Error(f"INITIALIZE UPDATE not supported / failed (SW={resp.sw_hex()}).")
        b = resp.data
        scp_id = b[11] if len(b) > 11 else None
        # SCP03 puts the i-param at body[12]; SCP02 body[12:14] is the sequence counter.
        scp_i = b[12] if (scp_id == SCP03 and len(b) > 12) else None
        return {
            "supported": (scp_id == SCP03 and len(b) >= 29) or (scp_id == SCP02 and len(b) >= 28),
            "scp_version": scp_id,
            "key_version": b[10] if len(b) > 10 else None,
            "scp_id": scp_id,
            "scp_i": scp_i,
            "key_diversification": b[0:10].hex().upper(),
        }

    def open(
        self,
        keys: Scp03Keys | Scp02Keys,
        *,
        key_version: int = 0,
        security_level: int = 0x03,
    ) -> None:
        """Open the admin secure channel, auto-detecting SCP02 vs SCP03.

        One INITIALIZE UPDATE is issued; the SCP version is read from ``body[11]`` and the
        matching channel is opened (reusing that response, no second INITIALIZE UPDATE).
        ``keys`` may be either key triple -- the default GP key applies to both -- and is
        adapted to the detected version.
        """
        host_challenge = os.urandom(8)
        resp = self.card.transmit(
            APDU(0x80, 0x50, key_version, 0x00, data=host_challenge, le=256),
            context="INITIALIZE UPDATE",
        )
        if not resp.ok:
            raise Scp03Error(f"INITIALIZE UPDATE rejected (SW={resp.sw_hex()}).")
        body = resp.data
        if len(body) < 12:
            raise Scp03Error(f"INITIALIZE UPDATE response too short ({len(body)} bytes).")

        if body[11] == SCP02:
            self.scp = open_channel_scp02(
                self.card.transmit,
                _as_scp02_keys(keys),
                key_version=key_version,
                security_level=security_level,
                host_challenge=host_challenge,
                init_response=resp,
            )
            self.scp_version = SCP02
        elif body[11] == SCP03:
            self.scp = open_channel_scp03(
                self.card.transmit,
                _as_scp03_keys(keys),
                key_version=key_version,
                security_level=security_level,
                host_challenge=host_challenge,
                init_response=resp,
            )
            self.scp_version = SCP03
        else:
            raise Scp03Error(
                f"Unsupported admin secure channel (keyInfo SCP id = {body[11]:#04x}; "
                "expected 0x02 or 0x03)."
            )

    def send(self, apdu: APDU, *, context: str | None = None) -> Response:
        if self.scp is None:
            raise Scp03Error("secure channel not open")
        wrapped = self.scp.wrap(apdu)
        return self.scp.unwrap(self.card.transmit(wrapped, context=context))

    def send_chained(
        self,
        ins: int,
        p1: int,
        p2: int,
        data: bytes,
        *,
        block_size: int = 200,
        context: str | None = None,
    ) -> Response:
        """Send a large command via ISO command chaining (CLA bit 0x10 on all but the
        final block). Each block is its own SCP03-wrapped short APDU; the applet
        buffers the chained object and processes it on the final block."""
        if self.scp is None:
            raise Scp03Error("secure channel not open")
        blocks = [data[i : i + block_size] for i in range(0, len(data), block_size)] or [b""]
        resp: Response | None = None
        for index, block in enumerate(blocks):
            final = index == len(blocks) - 1
            cla = 0x00 if final else 0x10  # chaining bit on non-final blocks
            label = f"{context} [{index + 1}/{len(blocks)}]" if context else None
            resp = self.scp.unwrap(
                self.card.transmit(self.scp.wrap(APDU(cla, ins, p1, p2, data=block)), context=label)
            )
            if not final and not resp.ok:
                return resp
        if resp is None:  # unreachable: send() always transmits at least one block
            raise RuntimeError("no APDU blocks were sent")
        return resp

    def self_test_read(self) -> Response:
        """Harmless wrapped GET DATA (Printed Info) proving the C-MAC+C-ENC path."""
        obj = object_by_name("printed")
        if obj is None:  # unreachable: "printed" is a built-in object name
            raise RuntimeError("PIV object table is missing 'printed'")
        return self.send(get_data_apdu(obj.oid), context="GET DATA (admin self-test)")
