# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv objects``: list and read PIV data objects."""

from __future__ import annotations

import contextlib

import click
from rich.console import Console

from cryptnox_id_cli.applets.piv import verifier
from cryptnox_id_cli.applets.piv.objects import PIV_OBJECTS, object_by_name
from cryptnox_id_cli.cli.context import AppContext

from .primitives import PIN_INPUT, _select, _verifier_value


def _write_private(path: str, data: bytes) -> None:
    """Write ``data`` readable by the owner only; card objects can hold personal data."""
    import os

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


# ---------------------------------------------------------------- objects --- #
@click.group("objects")
def objects() -> None:
    """List and read PIV data objects."""


@objects.command("list")
@click.pass_obj
def objects_list(app: AppContext) -> None:
    """List PIV data objects and whether each is present."""
    with app.open_session() as session:
        piv = _select(session)
        rows = [
            {
                "name": o.name,
                "oid": o.oid_hex,
                "present": piv.object_present(o.oid),
                "mandatory": o.mandatory,
                "pin_protected": o.pin_protected,
            }
            for o in PIV_OBJECTS
        ]

    def human(c: Console) -> None:
        table = app.out.table("Object", "OID", "Present", "Mandatory", "PIN")
        for r in rows:
            table.add_row(
                str(r["name"]),
                str(r["oid"]),
                "[green]yes[/green]" if r["present"] else "[dim]no[/dim]",
                "yes" if r["mandatory"] else "-",
                "yes" if r["pin_protected"] else "-",
            )
        c.print(table)

    app.out.result({"objects": rows}, human)


@contextlib.contextmanager
def _transcript_hold(session):
    """Withhold the session's APDU transcript lines, then emit them re-masked.

    Lets the caller register a response payload with ``session.redactor`` after
    receiving it but before the lines reach the --apdu-log file or the --verbose
    trace, so PIN-gated cardholder data keeps the transcript's "secrets redacted"
    promise. (A first-class hook on CardSession would be the durable home for
    this; until then the emit seam is intercepted here.)
    """
    held: list[str] = []
    original = session._emit
    session._emit = held.append
    try:
        yield
    finally:
        session._emit = original
        for line in held:
            original(session.redactor.mask(line))


@objects.command("read")
@click.option("--object", "object_name", required=True, help="Object name, e.g. chuid.")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write raw bytes to FILE.")
@click.pass_obj
def objects_read(app: AppContext, object_name: str, out_: str | None) -> None:
    """Read a PIV data object (prints hex, or writes raw bytes with --out).

    PIN-gated objects (printed, fingerprints, facial) need the PIN verified
    first — without it, GET DATA returns 6982 and the object reads back as
    absent even when populated. Only prompts/consumes a PIN for those objects.
    """
    obj = object_by_name(object_name)
    if obj is None:
        names = ", ".join(o.name for o in PIV_OBJECTS)
        raise click.BadParameter(f"unknown object {object_name!r}. Known: {names}")
    if obj.pin_protected and app.dry_run:
        raise click.ClickException(
            f"--dry-run: reading '{obj.name}' verifies the PIV PIN first, and a wrong PIN "
            "spends a try, so it refuses to run (nothing was sent to the card). Run it "
            "without --dry-run to read it."
        )
    secret = _verifier_value(app, PIN_INPUT) if obj.pin_protected else None
    with app.open_session() as session:
        piv = _select(session)
        if secret is not None:
            verifier.require_pin(piv, secret)
            # PIN-gated content (printed, fingerprints, facial) is cardholder data
            # the applet itself protects; it must not land in the "secrets redacted"
            # APDU transcript. Hold the GET DATA lines, register the payload, then
            # release them masked. Stdout still shows the content - the user asked
            # for it; the promise being kept is about --apdu-log/--verbose.
            with _transcript_hold(session):
                val = piv.read_object(obj.oid)
                shown = None if val is None else val.hex().upper()
                session.redactor.register(val)
        else:
            val = piv.read_object(obj.oid)
            shown = None if val is None else app.redactor.mask(val.hex().upper())
    if val is None:
        app.out.result(
            {"name": obj.name, "present": False},
            lambda c: c.print(f"Object {obj.name}: [yellow]not present[/yellow]"),
        )
        return
    if out_:
        _write_private(out_, val)
    payload = {
        "name": obj.name,
        "present": True,
        "length": len(val),
        "hex": None if out_ else shown,
        "out": out_,
    }

    def human(c: Console) -> None:
        if out_:
            c.print(f"[green]Wrote {len(val)} bytes to {out_}[/green]")
        else:
            c.print(f"{obj.name} ({len(val)} bytes): {payload['hex']}")

    app.out.result(payload, human)
