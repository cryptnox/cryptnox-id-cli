"""``genuine`` — inspect and verify the Cryptnox genuineness applet.

Read-only. ``genuine info`` reports what the applet stores; ``genuine verify`` runs
the two KDF-free genuineness checks — a live ATTEST (proof the card holds the device
private key) and the certificate chain to a pinned Cryptnox root. It deliberately
does NOT attempt the ISD / PIV-SSD key-diversification checks: those need the
per-card HSM-derived secret this tool has no access to.
"""

from __future__ import annotations

import secrets

import click
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from rich.console import Console

from cryptnox_id_cli import trust
from cryptnox_id_cli.applets.genuine import constants as gc
from cryptnox_id_cli.applets.genuine.genuine import GenuinenessApplet
from cryptnox_id_cli.applets.genuine.verify import verify_genuineness
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import x509util
from cryptnox_id_cli.transport.errors import AppletNotFoundError

_ISD_SSD_NOTE = (
    "Not checked: ISD / PIV-SSD key genuineness (KDF-derived per-card keys) - this "
    "tool has no HSM/KDF access. Genuineness here is the applet ATTEST + cert chain."
)


@click.group("genuine")
def command() -> None:
    """Manage the Cryptnox genuineness / attestation applet (read-only)."""


def _load_dir_anchors(path: str) -> tuple[list[bytes], list[bytes]]:
    """Load extra pinned anchors from a directory of PEM files, classified like the
    bundled store: self-issued CA -> root, other CA -> intermediate."""
    import pathlib

    roots: list[bytes] = []
    inters: list[bytes] = []
    for entry in sorted(pathlib.Path(path).iterdir()):
        if not entry.is_file() or entry.suffix.lower() not in (".pem", ".crt", ".cer"):
            continue
        raw = entry.read_bytes()
        try:
            certs = x509.load_pem_x509_certificates(raw)
        except ValueError:
            try:
                certs = [x509.load_der_x509_certificate(raw)]
            except ValueError:
                continue
        for cert in certs:
            try:
                is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            except x509.ExtensionNotFound:
                is_ca = False
            if not is_ca:
                continue
            der = cert.public_bytes(serialization.Encoding.DER)
            (roots if cert.issuer == cert.subject else inters).append(der)
    return roots, inters


@command.command("info")
@click.pass_obj
def info(app: AppContext) -> None:
    """Report the genuineness applet's state (SELECT + GET INFO + GET CERT)."""
    with app.open_session() as session:
        gen = GenuinenessApplet(session)
        try:
            gen.select()
        except AppletNotFoundError:
            app.out.result(
                {"present": False},
                lambda c: c.print(
                    "[yellow]Genuineness applet not found[/yellow] "
                    "(it is contact-only — absent over a contactless reader)."
                ),
            )
            return
        blob = gen.get_info()
        leaf_der = gen.get_cert(gc.CERT_LEAF)
        issuer_der = gen.get_cert(gc.CERT_INTERMEDIATE)

    leaf = x509util.describe_certificate(leaf_der) if leaf_der else None
    issuer = x509util.describe_certificate(issuer_der) if issuer_der else None
    payload = {
        "present": True,
        "personalized": leaf is not None,
        "info": blob.hex if blob else None,
        "leaf": leaf,
        "issuer": issuer,
    }

    def human(c: Console) -> None:
        c.print("[bold]Genuineness applet[/bold]")
        c.print(f"  AID:  {gc.GENUINE_AID.hex().upper()}")
        if blob:
            c.print(f"  Info: {blob.hex}")
        if leaf:
            c.print(f"  Device leaf: {leaf['subject']}")
            c.print(f"    issuer:  {leaf['issuer']}")
            c.print(f"    serial:  {leaf['serial']}")
            c.print(f"    expires: {leaf['not_after']}")
        else:
            c.print("  [yellow]No device leaf certificate (applet not personalized).[/yellow]")
        c.print(f"\n[dim]{_ISD_SSD_NOTE}[/dim]")
        c.print("[dim]Run `genuine verify` to prove the device key and the chain.[/dim]")

    app.out.result(payload, human)


@command.command("verify")
@click.option("--nonce", "nonce_hex", help="Challenge as hex (default: 32 random bytes).")
@click.option(
    "--anchors",
    "anchors_dir",
    type=click.Path(exists=True, dir_okay=True, file_okay=False),
    help="Directory of extra pinned CA PEMs (e.g. a dev genuineness CA) for chain anchoring.",
)
@click.pass_obj
def verify(app: AppContext, nonce_hex: str | None, anchors_dir: str | None) -> None:
    """Prove genuineness: live ATTEST + certificate chain to a pinned Cryptnox root."""
    if nonce_hex:
        try:
            nonce = bytes.fromhex(nonce_hex)
        except ValueError as exc:
            raise click.BadParameter("nonce must be hex", param_hint="--nonce") from exc
    else:
        nonce = secrets.token_bytes(gc.ATTEST_NONCE_LEN)

    roots, inters = trust.load_anchors()
    if anchors_dir:
        extra_roots, extra_inters = _load_dir_anchors(anchors_dir)
        roots += extra_roots
        inters += extra_inters

    with app.open_session() as session:
        gen = GenuinenessApplet(session)
        try:
            gen.select()
        except AppletNotFoundError:
            app.out.result(
                {"present": False, "genuine": False},
                lambda c: c.print(
                    "[yellow]Genuineness applet not found[/yellow] "
                    "(contact-only — use a contact reader)."
                ),
            )
            return
        leaf_der = gen.get_cert(gc.CERT_LEAF)
        issuer_der = gen.get_cert(gc.CERT_INTERMEDIATE)
        signature: bytes | None = None
        if leaf_der is not None:
            try:
                signature = gen.attest(nonce)
            except AppletNotFoundError:  # pragma: no cover - defensive
                signature = None

    result = verify_genuineness(
        leaf_der=leaf_der,
        nonce=nonce,
        signature=signature,
        card_issuer_der=issuer_der,
        roots=roots,
        intermediates=inters,
    )
    payload = {"present": True, **result.to_dict()}

    def human(c: Console) -> None:
        verdict = "[green]GENUINE[/green]" if result.genuine else "[red]NOT proven[/red]"
        c.print(f"Genuineness: {verdict}")
        pop = "[green]valid[/green]" if result.attested else "[red]invalid[/red]"
        c.print(f"  proof of possession (ATTEST): {pop}  [dim]{result.attest_detail}[/dim]")
        if result.leaf_subject:
            c.print(f"  device leaf: {result.leaf_subject}")
        if result.chain is not None:
            cv = "[green]verified[/green]" if result.chain.verified else "[red]not verified[/red]"
            c.print(f"  certificate chain: {cv}")
            if result.chain.chain:
                c.print(f"    {' -> '.join(result.chain.chain)}")
            for reason in result.chain.reasons:
                c.print(f"    [yellow]-[/yellow] {reason}")
        for note in result.notes:
            c.print(f"  [yellow]*[/yellow] {note}")
        c.print(f"\n[dim]{_ISD_SSD_NOTE}[/dim]")

    app.out.result(payload, human)
