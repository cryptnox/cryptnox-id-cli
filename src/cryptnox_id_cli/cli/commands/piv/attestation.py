# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv export-attestation`` and ``piv verify-attestation``: the key-attestation leaf."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli import trust
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import x509util
from cryptnox_id_cli.crypto.attestation import verify_attestation_chain
from cryptnox_id_cli.util.hexutil import to_hex

from .primitives import _csr_spki, _read_cert_der, _select, _slot_ref

# ------------------------------------------------------------ attestation --- #
# The factory/issuance-time PIV key-attestation leaf lives in the retired-slot-95
# certificate container (5FC120). Only slot 9C is attested in v1.
ATTESTATION_CERT_OBJECT = {0x9C: "attestation-cert"}


@click.command("export-attestation")
@click.option("--slot", default="9C", show_default=True, help="Attested slot (9C in v1).")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write the chain to FILE.")
@click.option("--der", is_flag=True, help="Write the leaf as DER (no chain) instead of PEM.")
@click.pass_obj
def export_attestation(app: AppContext, slot: str, out_: str | None, der: bool) -> None:
    """Export the on-card key-attestation leaf (PEM chain incl. bundled intermediates)."""
    ref = _slot_ref(slot)
    obj_name = ATTESTATION_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(
            f"slot {slot} carries no attestation certificate", param_hint="--slot"
        )
    with app.open_session() as session:
        leaf_der = _read_cert_der(_select(session), obj_name)
    if leaf_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No attestation certificate in slot {slot}.[/yellow]"),
        )
        return
    inter_ders: list[bytes] = []
    if der:
        data = leaf_der
    else:
        # Export the leaf's own chain, not the whole trust store: the bundled pool holds
        # sibling CAs that have nothing to do with this leaf. path_ders is [leaf, ...issuers].
        roots, pool = trust.load_anchors()
        path = verify_attestation_chain(leaf_der, pool, roots).path_ders
        # path is [leaf, ...issuers, anchor]; drop the leaf and the pinned root — a relying
        # party already holds the root, and shipping it invites trusting it from the file.
        inter_ders = [d for d in path[1:] if d not in set(roots)]
        data = b"".join([x509util.to_pem(leaf_der), *(x509util.to_pem(d) for d in inter_ders)])
    fmt = "DER" if der else "PEM"
    if out_:
        Path(out_).write_bytes(data)
    payload = {
        "present": True,
        "slot": slot,
        "format": fmt,
        "out": out_,
        "intermediates_bundled": len(inter_ders),
    }

    def human(c: Console) -> None:
        if out_:
            extra = f" (+{len(inter_ders)} intermediate)" if inter_ders else ""
            c.print(f"[green]Wrote {fmt} attestation to {escape(out_)}{extra}[/green]")
        else:
            c.print(to_hex(data) if der else data.decode())

    app.out.result(payload, human)


@click.command("verify-attestation")
@click.option("--slot", default="9C", show_default=True, help="Attested slot (9C in v1).")
@click.option(
    "--csr",
    "csr_file",
    type=click.Path(exists=True, dir_okay=False),
    help="Also check the attested key matches this CSR's public key.",
)
@click.pass_obj
def verify_attestation(app: AppContext, slot: str, csr_file: str | None) -> None:
    """Validate the on-card attestation chain against the pinned Cryptnox root."""
    ref = _slot_ref(slot)
    obj_name = ATTESTATION_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(
            f"slot {slot} carries no attestation certificate", param_hint="--slot"
        )
    csr_spki = _csr_spki(csr_file) if csr_file else None
    roots, inter_ders = trust.load_anchors()
    with app.open_session() as session:
        leaf_der = _read_cert_der(_select(session), obj_name)
    if leaf_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No attestation certificate in slot {slot}.[/yellow]"),
        )
        return
    result = verify_attestation_chain(leaf_der, inter_ders, roots, csr_spki=csr_spki)
    leaf_desc = x509util.describe_certificate(leaf_der)
    payload = {"present": True, "slot": slot, "leaf": leaf_desc, **result.to_dict()}

    def human(c: Console) -> None:
        verdict = "[green]verified[/green]" if result.verified else "[red]NOT verified[/red]"
        c.print(f"Attestation (slot {slot}): {verdict}")
        c.print(f"  subject: {escape(str(leaf_desc['subject']))}")
        if result.chain:
            c.print(f"  chain:   {escape(' -> '.join(result.chain))}")
        if result.csr_match is not None:
            mark = "[green]yes[/green]" if result.csr_match else "[red]no[/red]"
            c.print(f"  CSR key match: {mark}")
        for reason in result.reasons:
            c.print(f"  [yellow]-[/yellow] {escape(reason)}")

    app.out.result(payload, human)
