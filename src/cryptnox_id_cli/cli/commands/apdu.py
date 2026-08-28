"""``apdu`` — low-level APDU access (DEVELOPERS ONLY)."""

from __future__ import annotations

import json as _json
from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import describe_sw
from cryptnox_id_cli.util.hexutil import from_hex

_WARN = "low-level APDU use can change card state - use with care."


@click.group("apdu")
def command() -> None:
    """Send raw APDUs. DEVELOPERS ONLY - secrets are redacted in logs."""


def _dry_run(app: AppContext, commands: list[bytes]) -> None:
    """Honor the global --dry-run: show the (redacted) APDUs without transmitting."""
    shown = [app.redactor.redact_command(c) for c in commands]

    def human(c: Console) -> None:
        for s in shown:
            c.print(f"[yellow]dry-run:[/yellow] would send {s}")

    app.out.result({"dry_run": True, "would_send": shown}, human)


def _ins(command_bytes: bytes) -> int:
    """The command INS, so response redaction can apply the same INS-aware policy
    as the transcript layer (GENERAL AUTHENTICATE responses can carry key material)."""
    return command_bytes[1] if len(command_bytes) >= 2 else -1


def _show(app: AppContext, command_bytes: bytes, resp_data: bytes, sw1: int, sw2: int) -> None:
    info = describe_sw(sw1, sw2)
    payload = {
        "command": app.redactor.redact_command(command_bytes),
        "sw": info.sw_hex(),
        "sw_name": info.name,
        "sw_message": info.message,
        "data": app.redactor.redact_response_data(resp_data, ins=_ins(command_bytes)),
    }

    def human(c: Console) -> None:
        c.print(f"SW:   [bold]{info.sw_hex()}[/bold]  {info.name} - {info.message}")
        c.print(f"Data: {payload['data'] or '-'}")

    app.out.result(payload, human)


@command.command("send")
@click.option("--hex", "hex_", required=True, metavar="HEX", help="Full command APDU as hex.")
@click.pass_obj
def send(app: AppContext, hex_: str) -> None:
    """Send a raw command APDU."""
    app.out.warn(_WARN)
    raw = from_hex(hex_)
    if app.dry_run:
        _dry_run(app, [bytes(raw)])
        return
    with app.open_session() as session:
        resp = session.transmit(bytes(raw))
    _show(app, bytes(raw), resp.data, resp.sw1, resp.sw2)


@command.command("select")
@click.option("--aid", required=True, metavar="HEX", help="Applet AID as hex.")
@click.pass_obj
def select(app: AppContext, aid: str) -> None:
    """SELECT an applet by AID."""
    app.out.warn(_WARN)
    apdu = APDU(0x00, 0xA4, 0x04, 0x00, data=from_hex(aid), le=256)
    if app.dry_run:
        _dry_run(app, [apdu.to_bytes()])
        return
    with app.open_session() as session:
        resp = session.transmit(apdu)
    _show(app, apdu.to_bytes(), resp.data, resp.sw1, resp.sw2)


@command.command("transcript")
@click.option("--file", "file_", required=True, type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def transcript(app: AppContext, file_: str) -> None:
    """Replay a JSON array of hex command APDUs."""
    app.out.warn(_WARN)
    # utf-8-sig, not utf-8: PowerShell 5.1's `Set-Content -Encoding utf8` writes a BOM by
    # default, and json.loads rejects it ("Unexpected UTF-8 BOM"). Decoding as utf-8-sig
    # strips a BOM when present and is identical to utf-8 when it is not.
    entries = _json.loads(Path(file_).read_text(encoding="utf-8-sig"))
    if app.dry_run:
        cmds = [from_hex(e if isinstance(e, str) else str(e.get("apdu", ""))) for e in entries]
        _dry_run(app, [bytes(c) for c in cmds])
        return
    results = []
    with app.open_session() as session:
        for entry in entries:
            hexstr = entry if isinstance(entry, str) else str(entry.get("apdu", ""))
            raw = from_hex(hexstr)
            resp = session.transmit(bytes(raw))
            info = describe_sw(resp.sw1, resp.sw2)
            results.append(
                {
                    "command": app.redactor.redact_command(bytes(raw)),
                    "sw": info.sw_hex(),
                    "data": app.redactor.redact_response_data(resp.data, ins=_ins(bytes(raw))),
                }
            )

    def human(c: Console) -> None:
        table = app.out.table("#", "Command", "SW", "Data", title="APDU transcript")
        for i, r in enumerate(results):
            table.add_row(str(i), r["command"], r["sw"], r["data"] or "-")
        c.print(table)

    app.out.result({"results": results}, human)
