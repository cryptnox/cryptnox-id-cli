# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What this tool reads from the card itself, to set beside what the service asserts.

Every read here is key-free. The relay policy expects the card manager to be
the selected applet when an operation starts, so each reader that selects the
PIV applet says whether it leaves it selected or re-reads the CPLC last.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptnox_id_cli.applets.piv import inventory as inventory_mod
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.cli.commands.info import _read_cplc
from cryptnox_id_cli.cli.commands.piv.primitives import SLOT_CERT_OBJECT, _read_cert_der
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote.policy import PIV_SSD_AID
from cryptnox_id_cli.state.detector import StateDetector
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.pcsc import CardSession, RawConnection
from cryptnox_id_cli.util import tlv

#: How the two builds are named to the holder, by the service's ``piv_variant`` value.
BUILD_NAMES = {"fips": "FIPS-mode build", "fipsoff": "build with FIPS mode off"}
ATTESTATION_CONTAINER = "attestation-cert"  # 5FC120, the one container the service writes


@dataclass
class Card:
    reader: str | None
    conn: RawConnection
    session: CardSession
    atr: str
    cplc_uid: str | None
    ic_serial: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "reader": self.reader,
            "atr": self.atr,
            "cplc_uid": self.cplc_uid,
            "ic_serial": self.ic_serial,
        }


def open_card(app: AppContext) -> Card:
    """Open the reader and read the card's identity. Leaves the card manager selected."""
    session = app.open_session()
    cplc = _read_cplc(session)
    return Card(
        reader=session.reader_name or app.resolved_reader,
        conn=session.raw_connection,
        session=session,
        atr=session.atr.hex().upper(),
        cplc_uid=cplc["uid"] if cplc else None,
        ic_serial=cplc["ic_serial"] if cplc else None,
    )


def ssd_key_versions(session: CardSession) -> list[int] | None:
    """Key versions the PIV security domain holds, read key-free.

    ``None`` when the security domain is absent. The key information template
    lists one ``C0`` entry per key: id, version, type, length.
    """
    selected = session.transmit(APDU(0x00, 0xA4, 0x04, 0x00, data=PIV_SSD_AID, le=256))
    if not selected.ok:
        return None
    info = session.transmit(APDU(0x80, 0xCA, 0x00, 0xE0, le=256))
    if not info.ok:
        return []
    versions: set[int] = set()
    for node in tlv.parse(info.data):
        if node.tag != 0xE0:
            continue
        for entry in tlv.parse(node.value, recurse=False):
            if entry.tag == 0xC0 and len(entry.value) >= 2:
                versions.add(entry.value[1])
    return sorted(versions)


def piv_build(session: CardSession) -> dict[str, object] | None:
    """The PIV applet's own account of its build, read key-free.

    ``None`` when there is no applet to ask or it does not answer the vendor
    reads. ``fips_mode`` is the applet's FIPS flag: true for the FIPS-mode
    build, false for the build with FIPS mode off. Leaves the PIV applet
    selected; callers re-read the CPLC when the card manager must be selected.
    """
    piv = PivApplet(session)
    try:
        piv.select()
        version = inventory_mod.read_version(piv)
        status = inventory_mod.read_status(piv)
    except CryptnoxError:
        return None
    if version is None and status is None:
        return None
    return {
        "label": version.label if version else None,
        "version": version.version if version else None,
        "fips_mode": status.fips_mode if status else None,
    }


def build_matches(requested: str, build: object) -> bool | None:
    """Whether the applet on the card is the requested build. ``None`` when unreadable."""
    if not isinstance(build, dict) or not isinstance(build.get("fips_mode"), bool):
        return None
    return build["fips_mode"] == (requested == "fips")


def build_text(build: object) -> str:
    if not isinstance(build, dict):
        return "not readable"
    flag = build.get("fips_mode")
    name = "not reported" if flag is None else BUILD_NAMES["fips" if flag else "fipsoff"]
    label = " ".join(str(v) for v in (build.get("label"), build.get("version")) if v)
    return f"{name} ({label})" if label else name


def inventory(card: Card) -> dict[str, object]:
    """What the PIV function and its neighbours hold right now, read locally.

    Ends by re-reading the CPLC so the card manager is the selected applet
    again, which is what the relay policy assumes at the start of an operation.
    """
    state = StateDetector(
        card.session, probe_fido=True, probe_desfire=False, probe_genuine=True
    ).detect()
    build = piv_build(card.session)
    ssd = ssd_key_versions(card.session)
    _read_cplc(card.session)
    return {
        "piv_state": state.piv.label,
        "piv_build": build,
        "piv_objects": sorted(name for name, present in state.piv_objects.items() if present),
        "piv_ssd_key_versions": ssd,
        "fido_state": state.fido.label,
        "genuineness_state": state.genuine.label,
    }


def read_certificates(card: Card, slot: int) -> tuple[bytes | None, bytes | None]:
    """The slot's certificate and the attestation container, read locally.

    Leaves the card manager selected afterwards.
    """
    piv = PivApplet(card.session)
    slot_cert = attestation = None
    try:
        piv.select()
        slot_object = SLOT_CERT_OBJECT.get(slot)
        slot_cert = _read_cert_der(piv, slot_object) if slot_object else None
        attestation = _read_cert_der(piv, ATTESTATION_CONTAINER)
    except CryptnoxError:
        # An applet that is absent, unselectable or refusing the read simply has
        # no certificate to report; the operation goes ahead either way.
        pass
    _read_cplc(card.session)
    return slot_cert, attestation


def piv_finalized(card: Card) -> bool:
    """Whether the PIV applet reports itself finalized, read key-free.

    Leaves the card manager selected afterwards.
    """
    piv = PivApplet(card.session)
    try:
        piv.select()
        status = inventory_mod.read_status(piv)
    except CryptnoxError:
        status = None
    _read_cplc(card.session)
    return bool(status is not None and status.secured)
