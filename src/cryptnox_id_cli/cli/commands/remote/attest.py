# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``remote attest``: a key generated on the card through the service, and its
attestation certificate checked locally.

The command runs in four steps that this module keeps apart: consent (what the
operation replaces), the relay, the local verification of what came back, and
the report.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import attest_verify as av
from cryptnox_id_cli.transport.errors import CryptnoxError

from .card import Card, open_card, piv_finalized, read_certificates
from .render import pem_lines, print_channel, print_checks, print_header, print_result, warn_channel
from .run import (
    cross_check,
    endpoint,
    exit_if_unverified,
    relay_info,
    relay_operation,
    warn_contactless_reader,
)

ATTEST_ALGORITHMS = ("ECCP256", "ECCP384", "RSA2048", "RSA3072", "RSA4096")


def parse_slot(value: str) -> int:
    try:
        slot = int(value, 16)
    except ValueError:
        raise click.BadParameter(f"not a hex slot: {value!r}", param_hint="--slot") from None
    if slot not in (0x9A, 0x9C, 0x9D, 0x9E) and not 0x82 <= slot <= 0x95:
        raise click.BadParameter(
            "slot must be 9A, 9C, 9D, 9E or a retired slot 82 to 95", param_hint="--slot"
        )
    return slot


def check_out_path(path: str) -> None:
    """Refuse a --out the run could not write before an operation is spent on the card."""
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.is_dir() or not os.access(parent, os.W_OK):
        raise CryptnoxError(f"--out {path}: the directory does not exist or is not writable")
    if target.exists() and not os.access(target, os.W_OK):
        raise CryptnoxError(f"--out {path} is not writable")


def verdict(verification: av.AttestVerification | None) -> bool | None:
    """True when every binding holds, False when one fails, None when one could not be checked."""
    if verification is None:
        return False
    if verification.verified:
        return True
    bindings = (
        verification.chain_verified,
        verification.serial_number_matches_card,
        verification.slot_matches,
        verification.trust_model_matches,
        verification.public_key_matches_card,
    )
    return False if any(b is False for b in bindings) else None


def _consent(app: AppContext, card: Card, slot_ref: int, slot_hex: str) -> bool:
    """Say what the operation replaces and obtain consent; True when the applet is finalized."""
    slot_cert, container_before = read_certificates(card, slot_ref)
    occupied = []
    if slot_cert is not None:
        occupied.append(f"slot {slot_hex} holds a certificate")
    if container_before is not None:
        occupied.append("the attestation container holds a certificate")
    finalized = piv_finalized(card)
    if finalized:
        # A finalized card is one in use: say what is lost before anything is sent.
        app.out.warn(
            f"the PIV applet on this card is finalized. remote attest generates a new key "
            f"in slot {slot_hex}: THE KEY NOW IN SLOT {slot_hex} IS OVERWRITTEN and cannot "
            "be recovered; a certificate issued for it stops matching the slot. Nothing "
            "can be added to a finalized applet, so the slot must already have a key "
            "object for the algorithm, and the key attestation is stored on the card only "
            "if the applet has an attestation container; otherwise it is returned (keep "
            "it with --out)."
        )
    if occupied:
        app.out.warn(
            "remote attest replaces the key in the slot and the certificate in the "
            "attestation container: " + "; ".join(occupied) + "."
        )
    if (occupied or finalized) and not app.yes:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                f"remote attest on a finalized applet overwrites the key in slot {slot_hex}; "
                "pass --yes to confirm."
                if finalized
                else "remote attest would overwrite existing material; pass --yes to confirm."
            )
        question = (
            f"Overwrite the key in slot {slot_hex}?" if finalized else "Continue and overwrite?"
        )
        if not click.confirm(question, default=False):
            raise click.Abort()
    return finalized


@dataclass
class _Outcome:
    """What the local verification made of the service's answer."""

    pem: str | None = None
    verification: av.AttestVerification | None = None
    identifiers: dict[str, bool | None] = field(default_factory=dict)
    written_to: str | None = None
    not_stored: bool = False


def _verify(
    app: AppContext,
    result: dict[str, object],
    slot_ref: int,
    cplc_uid: str | None,
    container_after: bytes | None,
    out_: str | None,
) -> _Outcome:
    """Verify the returned certificate, write it to --out, and say when the card holds no copy."""
    outcome = _Outcome()
    pem = result.get("attestation_cert_pem")
    if isinstance(pem, str) and pem.strip():
        outcome.pem = pem
        try:
            leaf_der = av.leaf_from_pem(pem)
        except ValueError as exc:
            raise CryptnoxError(f"the service returned an unreadable certificate: {exc}") from exc
        outcome.verification = av.verify_returned_attestation(
            leaf_der, slot=slot_ref, cplc_uid=cplc_uid, on_card_der=container_after
        )
        outcome.identifiers = av.check_reported_identifiers(result, leaf_der)
        if out_:
            try:
                Path(out_).write_bytes(pem.encode("utf-8"))
                outcome.written_to = out_
            except OSError as exc:
                app.out.warn(
                    f"the certificate could not be written to {out_} ({exc}); it is in the "
                    "result below and, without --json, printed in full."
                )
    # A finalized applet without an attestation container: the certificate exists only in
    # the service's answer, so it must not scroll away.
    outcome.not_stored = result.get("attestation_stored") is False and bool(outcome.pem)
    if outcome.not_stored:
        app.out.warn(
            "the applet has no attestation container and none can be added to a finalized "
            "applet: the key attestation is not stored on the card, so the certified key "
            "cannot be compared with a certificate on the card (reported as unchecked). "
            + (
                f"It was written to {outcome.written_to}."
                if outcome.written_to
                else "It is printed below; keep it."
            )
        )
    return outcome


def _checks(
    card_info: dict[str, object],
    result: dict[str, object],
    outcome: _Outcome,
    container_after: bytes | None,
    out_: str | None,
) -> dict[str, object]:
    checks = cross_check(card_info, result)
    checks["attestation_returned"] = outcome.verification is not None
    checks["attestation_verified"] = verdict(outcome.verification)
    # The service's own word that it stored nothing leaves nothing to compare with.
    checks["attestation_container_written"] = (
        None if result.get("attestation_stored") is False else container_after is not None
    )
    if out_:
        checks["certificate_written_to_out"] = outcome.written_to is not None
    # What the service says it signed, against the certificate it returned.
    checks.update(outcome.identifiers)
    return checks


def _print_attestation(
    c: Console,
    slot_hex: str,
    outcome: _Outcome,
    checks: dict[str, object],
    key_authenticated: object,
) -> None:
    verification = outcome.verification
    c.print("\n[bold]Key attestation[/bold] (checked locally)")
    if verification is None:
        c.print("  [red]the service returned no certificate[/red]")
    else:
        if checks["attestation_verified"] is True:
            label = "[green]verified[/green]"
        elif checks["attestation_verified"] is False:
            label = "[red]NOT verified[/red]"
        else:
            label = "[yellow]not fully checked[/yellow]"
        c.print(f"  {label}  {escape(verification.subject)}")
        c.print(f"  chain: {' -> '.join(escape(n) for n in verification.chain)}")
        for text, value in (
            ("serial number is this card", verification.serial_number_matches_card),
            (f"attests slot {slot_hex}", verification.slot_matches),
            ("trust model is server-driven", verification.trust_model_matches),
            ("key equals the card's stored certificate", verification.public_key_matches_card),
        ):
            if value is True:
                mark = "[green]yes[/green]"
            elif value is False:
                mark = "[red]NO[/red]"
            else:
                mark = "[dim]unchecked[/dim]"
            c.print(f"  {text}: {mark}")
        for reason in verification.reasons:
            c.print(f"  [yellow]-[/yellow] {escape(reason)}")
        if outcome.written_to:
            c.print(f"  PEM written to {escape(outcome.written_to)}")
    if key_authenticated is True:
        mark = "[green]yes[/green]"
    elif key_authenticated is False:
        mark = "[red]NO[/red]"
    else:
        mark = "[dim]not reported[/dim]"
    c.print(f"  public key authenticated by the card's channel (service's claim): {mark}")
    c.print("  [dim]On-card generation is the service's claim; the relay cannot witness it.[/dim]")


def _warn_key_origin(app: AppContext, key_authenticated: object) -> None:
    if key_authenticated is False:
        app.out.warn(
            "the public key the service certified was received over a channel whose answers "
            "the card does not authenticate; something between the service and the card "
            "could have substituted it, so this attestation is weaker."
        )
    elif key_authenticated is not True:
        app.out.warn(
            "the service did not say whether the public key it certified reached it "
            "authenticated by the card. A service without the hardened channel receives it "
            "over a channel whose answers the card does not authenticate, so treat this "
            "attestation as the weaker kind."
        )


@click.command("attest")
@click.option("--slot", default="9C", show_default=True, help="Slot to generate the key in.")
@click.option(
    "--algorithm",
    default="ECCP256",
    show_default=True,
    type=click.Choice(ATTEST_ALGORITHMS, case_sensitive=False),
    help="Key algorithm.",
)
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write the leaf PEM here.")
@click.pass_context
def attest(ctx: click.Context, slot: str, algorithm: str, out_: str | None) -> None:
    """Generate a key on the card through the service and receive its attestation.

    The service generates the key in the slot, signs a key-attestation certificate
    for it and stores that certificate in the card's attestation container. The
    slot's previous key and the container's previous certificate are replaced.
    Afterwards the certificate is verified locally: chain to the pinned anchors,
    subject serial number against the card's CPLC UID, attested slot against the
    request, trust model, and the certified key against the certificate read
    back from the card. That the key was generated on the card is the service's
    claim; the relay cannot witness it.
    """
    app: AppContext = ctx.obj
    op = "attest"
    slot_ref = parse_slot(slot)
    slot_hex = f"{slot_ref:02X}"
    url, _production = endpoint(op)
    params: dict[str, object] = {"slot": slot_hex, "algorithm": algorithm.upper()}
    if out_:
        check_out_path(out_)

    card = open_card(app)
    try:
        warn_contactless_reader(app, card, refused=True)
        if _consent(app, card, slot_ref, slot_hex):
            # The service overwrites a key on a finalized applet only for a client that says
            # the card holder agreed. Sent after the warning above, never before.
            params["replace_key"] = True
        app.out.note(f"remote {op} via {url}")
        report = relay_operation(app, ctx, card, op, params, url)
        _slot_after, container_after = read_certificates(card, slot_ref)
    finally:
        card.conn.disconnect()

    outcome = _verify(app, report.result, slot_ref, card.cplc_uid, container_after, out_)
    card_info = card.to_dict()
    checks = _checks(card_info, report.result, outcome, container_after, out_)
    if any(value is False for value in outcome.identifiers.values()):
        app.out.warn(
            "the identifiers the service reports for the certificate do not match the "
            "certificate it returned; report this to Cryptnox support."
        )
    key_authenticated = report.result.get("public_key_authenticated")
    relayed = relay_info(report)
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "slot": slot_hex,
        "algorithm": algorithm.upper(),
        "card": card_info,
        "result": report.result,
        "verification": outcome.verification.to_dict() if outcome.verification else None,
        "verified_locally": checks,
        "out": outcome.written_to,
        "relay": relayed,
    }

    def human(c: Console) -> None:
        print_header(c, op, url, card_info, relayed)
        print_channel(c, report.result, expected=True)
        print_result(c, {k: v for k, v in report.result.items() if k != "attestation_cert_pem"})
        _print_attestation(c, slot_hex, outcome, checks, key_authenticated)
        print_checks(c, checks)
        if (outcome.not_stored or (out_ and outcome.written_to is None)) and outcome.pem:
            c.print("\n[bold]Key attestation certificate[/bold] (not stored on the card)")
            c.print(escape(pem_lines(outcome.pem)))

    app.out.result(payload, human)
    warn_channel(app, report.result)
    _warn_key_origin(app, key_authenticated)
    exit_if_unverified(app, checks)
