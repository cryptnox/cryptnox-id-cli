"""``doctor`` — environment and per-applet diagnostics."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import DesfireState, FidoState, GenuinenessState, PivState
from cryptnox_id_cli.transport.elevation import is_elevated, is_windows
from cryptnox_id_cli.transport.errors import CryptnoxError, NoCardError
from cryptnox_id_cli.transport.pcsc import connect, pick_reader, reader_states

_STATUS_STYLE = {
    "ok": "[green]ok[/green]",
    "warn": "[yellow]warn[/yellow]",
    "fail": "[red]fail[/red]",
    "info": "[blue]info[/blue]",
}


@click.command("doctor")
@click.pass_obj
def command(app: AppContext) -> None:
    """Run diagnostics: PC/SC service, reader, card, and per-applet reachability."""
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    infos = None
    try:
        infos = reader_states()
        add("PC/SC service", "ok", f"{len(infos)} reader(s) detected")
    except CryptnoxError as exc:
        add("PC/SC service", "fail", str(exc))

    reader_name = None
    if infos is not None:
        try:
            reader_name = pick_reader(app.reader)
            add("Reader (Cryptnox/ACS-first)", "ok", reader_name)
        except CryptnoxError as exc:
            add("Reader (Cryptnox/ACS-first)", "fail", str(exc))

    if reader_name:
        try:
            session = app.make_session(connect(reader_name))
        except NoCardError as exc:
            add("Card present", "fail", str(exc))
        except CryptnoxError as exc:
            add("Card connection", "fail", str(exc))
        else:
            try:
                add("Card present", "ok", f"ATR {session.atr.hex().upper()}")
                st = StateDetector(session).detect()

                if st.piv == PivState.NOT_PRESENT:
                    add("PIV applet", "warn", "not present")
                elif st.piv == PivState.UNKNOWN:
                    add("PIV applet", "warn", "state unknown")
                else:
                    add("PIV applet", "ok", f"selectable ({st.piv.label})")

                if st.fido == FidoState.BLOCKED_BY_OS:
                    add(
                        "FIDO2 applet",
                        "warn",
                        "blocked by OS; run from an Administrator terminal to manage FIDO2",
                    )
                elif st.fido in (FidoState.SELECTABLE, FidoState.PERSONALIZED):
                    add("FIDO2 applet", "ok", st.fido.label)
                elif st.fido == FidoState.NOT_PRESENT:
                    add("FIDO2 applet", "warn", "not present on this interface")
                else:
                    add("FIDO2 applet", "warn", st.fido.label)

                if st.desfire == DesfireState.REACHABLE:
                    add("DESFire (contactless)", "ok", "reachable")
                elif st.desfire == DesfireState.NEEDS_CONTACTLESS_READER:
                    add(
                        "DESFire (contactless)",
                        "warn",
                        "needs a contactless reader (the contact interface cannot reach it)",
                    )
                elif st.desfire == DesfireState.NO_ANSWER_CONTACTLESS:
                    add(
                        "DESFire (contactless)",
                        "warn",
                        "no answer on this contactless interface - re-present the card; "
                        "the reader must pass native DESFire APDUs",
                    )
                else:
                    add("DESFire (contactless)", "warn", st.desfire.label)

                if st.genuine == GenuinenessState.PERSONALIZED:
                    add("Genuineness applet", "ok", "personalized (run `genuine verify` to prove)")
                elif st.genuine == GenuinenessState.PRESENT:
                    add("Genuineness applet", "warn", "present but not personalized (no leaf cert)")
                elif st.genuine == GenuinenessState.NEEDS_CONTACT_READER:
                    add("Genuineness applet", "info", "contact-only; unreachable over contactless")
                elif st.genuine == GenuinenessState.NOT_PRESENT:
                    add("Genuineness applet", "info", "not present on this card")
                else:
                    add("Genuineness applet", "warn", st.genuine.label)
            finally:
                session.disconnect()

    if is_windows():
        elev = is_elevated()
        if elev is True:
            add("Windows elevation", "ok", "Administrator (FIDO2 reachable)")
        elif elev is False:
            add(
                "Windows elevation",
                "info",
                "not elevated; FIDO2 needs admin (Windows reserves CTAP PC/SC access "
                "for the WebAuthn API). `fido` will offer to relaunch via UAC.",
            )
        else:
            add("Windows elevation", "info", "could not determine elevation")

    has_fail = any(c["status"] == "fail" for c in checks)
    payload = {"checks": checks, "ok": not has_fail}

    def human(c: Console) -> None:
        table = app.out.table("Check", "Status", "Detail", title="Diagnostics")
        for ch in checks:
            table.add_row(ch["check"], _STATUS_STYLE.get(ch["status"], ch["status"]), ch["detail"])
        c.print(table)
        if has_fail:
            c.print("\n[red]Some checks failed.[/red]")
        else:
            c.print(
                "\n[green]No blocking issues.[/green] "
                "[dim](FIDO/DESFire warnings are normal on a contact / non-elevated setup)[/dim]"
            )

    app.out.result(payload, human)
    if has_fail:
        sys.exit(2)
