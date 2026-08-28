"""``info`` — detect the card and its applets."""

from __future__ import annotations

import contextlib

import click
from rich.console import Console

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.output.render import state_style
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import CardState
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.pcsc import CardSession


def _read_cplc(session: CardSession) -> dict[str, str] | None:
    """Best-effort CPLC read (card serial / production data) via the ISD."""
    with contextlib.suppress(Exception):
        sel = session.transmit(
            APDU(0x00, 0xA4, 0x04, 0x00, data=bytes.fromhex("A000000151000000"), le=256)
        )
        if not sel.ok:
            return None
        cplc = session.transmit(APDU(0x80, 0xCA, 0x9F, 0x7F, le=256))
        if not cplc.ok or not cplc.data:
            return None
        raw = cplc.data
        body = raw[3:] if (len(raw) >= 3 and raw[0] == 0x9F and raw[1] == 0x7F) else raw
        serial = body[12:16].hex().upper() if len(body) >= 16 else None
        # Card UID: IC fabrication date || IC serial number || IC batch identifier
        # (CPLC body[10:18], 8 bytes). This is the canonical Cryptnox card UID (cf.
        # CPLCData.kt) — distinct from the bare 4-byte serial above and the value
        # diversified for the per-card PIV-SSD KVN 2 key.
        uid = body[10:18].hex().upper() if len(body) >= 18 else None
        return {"raw": raw.hex().upper(), "ic_serial": serial or "", "uid": uid or ""}
    return None


@click.command("info")
@click.pass_obj
def command(app: AppContext) -> None:
    """Detect the inserted card and which applets/functions are present."""
    with app.open_session() as session:
        state: CardState = StateDetector(session).detect()
        cplc = _read_cplc(session)

    payload = state.to_dict()
    payload["reader"] = app.resolved_reader
    payload["cplc"] = cplc

    def human(c: Console) -> None:
        c.print(f"[bold]Reader:[/bold] {app.resolved_reader}")
        c.print(f"[bold]ATR:[/bold]    {state.atr_hex or '-'}")
        if cplc and cplc.get("ic_serial"):
            c.print(f"[bold]Serial:[/bold] {cplc['ic_serial']} (CPLC)")
        if cplc and cplc.get("uid"):
            c.print(f"[bold]UID:[/bold]    {cplc['uid']} (CPLC)")
        c.print("")

        table = app.out.table("Function", "State", "Details", title="Applets / functions")
        # PIV
        piv_detail = ""
        if state.piv_apt:
            piv_detail = state.piv_apt.label or ""
            if state.piv_pin and state.piv_pin.configured:
                tries = state.piv_pin.retries
                piv_detail += f", PIN {tries} tries" if tries is not None else ", PIN set"
        table.add_row("PIV", state_style(state.piv.label), piv_detail or "-")
        # FIDO
        fido_detail = ", ".join(state.fido_versions) if state.fido_versions else ""
        table.add_row("FIDO2", state_style(state.fido.label), fido_detail or "-")
        # DESFire
        desfire_detail = "-"
        if state.desfire_version:
            dv = state.desfire_version
            desfire_detail = f"EV2 {dv.get('storage_bytes')} B, UID {dv.get('uid')}"
        table.add_row("MIFARE DESFire", state_style(state.desfire.label), desfire_detail)
        # Genuineness / attestation applet
        genuine_detail = state.genuine_leaf_subject or "-"
        table.add_row("Genuineness", state_style(state.genuine.label), genuine_detail)
        c.print(table)

        if state.piv_objects:
            present = [n for n, v in state.piv_objects.items() if v]
            shown = ", ".join(present) if present else "none"
            c.print(f"\n[dim]PIV objects present:[/dim] {shown}")
        if state.notes:
            c.print("")
            for note in state.notes:
                c.print(f"[yellow]*[/yellow] {note}")

    app.out.result(payload, human)
