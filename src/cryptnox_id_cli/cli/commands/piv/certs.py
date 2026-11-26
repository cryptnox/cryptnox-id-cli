# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv certs``: list, export and inspect the slot certificates."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import x509util

from .primitives import SLOT_CERT_OBJECT, _read_cert_der, _select, _slot_ref


# ------------------------------------------------------------------ certs --- #
@click.group("certs")
def certs() -> None:
    """Inspect and export PIV certificates."""


@certs.command("list")
@click.pass_obj
def certs_list(app: AppContext) -> None:
    """List certificate slots and summarise any certificate found."""
    with app.open_session() as session:
        piv = _select(session)
        out = []
        for ref, obj_name in SLOT_CERT_OBJECT.items():
            der = _read_cert_der(piv, obj_name)
            entry: dict[str, object] = {
                "slot": f"{ref:02X}",
                "object": obj_name,
                "present": der is not None,
            }
            if der is not None:
                try:
                    entry["certificate"] = x509util.describe_certificate(der)
                except Exception as exc:  # noqa: BLE001 - report parse failure, don't crash
                    entry["error"] = f"parse failed: {exc}"
            out.append(entry)

    def human(c: Console) -> None:
        table = app.out.table("Slot", "Object", "Present", "Subject", "Expires")
        for e in out:
            raw = e.get("certificate")
            cert = raw if isinstance(raw, dict) else {}
            table.add_row(
                str(e["slot"]),
                str(e["object"]),
                "[green]yes[/green]" if e["present"] else "[dim]no[/dim]",
                "[red]unreadable[/red]" if "error" in e else escape(str(cert.get("subject", "-"))),
                str(cert.get("not_after", "-")),
            )
        c.print(table)
        for e in out:
            if "error" in e:
                c.print(f"[red]{e['slot']}:[/red] {escape(str(e['error']))}")

    app.out.result({"certificates": out}, human)


@certs.command("export")
@click.option("--slot", required=True, help="Slot hex, e.g. 9A.")
@click.option("--out", "out_", required=True, type=click.Path(dir_okay=False))
@click.option("--der", is_flag=True, help="Write DER instead of PEM.")
@click.pass_obj
def certs_export(app: AppContext, slot: str, out_: str, der: bool) -> None:
    """Export a slot's certificate (PEM by default). Certificates are not secret."""
    ref = _slot_ref(slot)
    obj_name = SLOT_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(f"slot {slot} has no certificate container")
    with app.open_session() as session:
        cert_der = _read_cert_der(_select(session), obj_name)
    if cert_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No certificate in slot {slot}.[/yellow]"),
        )
        return
    data = cert_der if der else x509util.to_pem(cert_der)
    Path(out_).write_bytes(data)
    fmt = "DER" if der else "PEM"
    app.out.result(
        {"present": True, "slot": slot, "out": out_, "format": fmt},
        lambda c: c.print(f"[green]Wrote {fmt} certificate to {out_}[/green]"),
    )


@certs.command("inspect")
@click.option("--slot", required=True, help="Slot hex, e.g. 9A.")
@click.pass_obj
def certs_inspect(app: AppContext, slot: str) -> None:
    """Show certificate details for a slot."""
    ref = _slot_ref(slot)
    obj_name = SLOT_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(f"slot {slot} has no certificate container")
    with app.open_session() as session:
        cert_der = _read_cert_der(_select(session), obj_name)
    if cert_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No certificate in slot {slot}.[/yellow]"),
        )
        return
    desc = x509util.describe_certificate(cert_der)

    def human(c: Console) -> None:
        for key, value in desc.items():
            c.print(f"  {key}: {escape(str(value))}")

    app.out.result({"present": True, "slot": slot, "certificate": desc}, human)
