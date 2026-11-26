# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso`` commands that build and write PIV data objects."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.applets.piv.objects import object_by_name
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import piv_objects
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys
from cryptnox_id_cli.transport.errors import describe_sw

from ..primitives import (
    _exit_if_refused,
    _write_standard,
)


def _emit_object(app: AppContext, name: str, data: bytes, out_: str | None) -> None:
    if out_:
        Path(out_).write_bytes(data)
    app.out.result(
        {
            "object": name,
            "length": len(data),
            "out": out_,
            "hex": None if out_ else data.hex().upper(),
        },
        lambda c: c.print(
            f"[green]{name}[/green] ({len(data)} bytes) -> {out_}"
            if out_
            else f"{name} ({len(data)} bytes): {data.hex().upper()}"
        ),
    )


@click.command("generate-chuid")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write object bytes to FILE.")
@click.pass_obj
def perso_generate_chuid(app: AppContext, out_: str | None) -> None:
    """Generate a minimal CHUID object (unsigned, dev/test)."""
    _emit_object(app, "chuid", piv_objects.generate_chuid(), out_)


@click.command("generate-ccc")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write object bytes to FILE.")
@click.pass_obj
def perso_generate_ccc(app: AppContext, out_: str | None) -> None:
    """Generate a minimal Card Capability Container object (dev/test)."""
    _emit_object(app, "ccc", piv_objects.generate_ccc(), out_)


@click.command("generate-discovery")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write object bytes to FILE.")
@click.pass_obj
def perso_generate_discovery(app: AppContext, out_: str | None) -> None:
    """Generate the Discovery object (7E)."""
    _emit_object(app, "discovery", piv_objects.generate_discovery(), out_)


@click.command("write-object")
@click.option("--object", "object_name", required=True, help="Object name, e.g. chuid.")
@click.option("--file", "file_", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_write_object(app: AppContext, object_name: str, file_: str, default_keys: bool) -> None:
    """Write a data object's content into its container (PUT DATA over SCP03)."""
    obj = object_by_name(object_name)
    if obj is None:
        raise click.BadParameter(f"unknown object {object_name!r}")
    app.out.warn(f"overwrites the {object_name} container's current content (admin channel write).")
    data = Path(file_).read_bytes()
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        adm = PivAdmin(session)
        adm.select()
        adm.open(keys)
        resp = adm.send(perso_mod.put_data_apdu(obj.oid, data), context=f"PUT DATA {object_name}")
    info = describe_sw(resp.sw1, resp.sw2)
    app.out.result(
        {"object": object_name, "written": resp.ok, "sw": info.sw_hex()},
        lambda c: c.print(
            f"[green]Wrote {object_name}.[/green]"
            if resp.ok
            else f"[red]Write failed:[/red] {info.message} (SW={info.sw_hex()})"
        ),
    )
    _exit_if_refused(resp.ok)


@click.command("write-standard-objects")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_write_standard_objects(app: AppContext, default_keys: bool) -> None:
    """Generate and write the standard data objects (CHUID, CCC) into their containers."""
    app.out.warn(
        "overwrites the current content of the chuid and ccc containers (admin channel write)."
    )
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        results = _write_standard(PivAdmin(session), keys, ("chuid", "ccc"))

    def human(c: Console) -> None:
        for r in results:
            mark = "[green]ok[/green]" if r["ok"] else f"[red]{r['sw']}[/red]"
            c.print(f"  {mark}  {r['object']}")

    app.out.result({"objects": results}, human)
    _exit_if_refused(all(r["ok"] for r in results))
