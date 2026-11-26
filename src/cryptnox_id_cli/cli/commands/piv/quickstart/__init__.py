# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv quickstart``: the command."""

from __future__ import annotations

import click

from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.pcsc import CardSession

from ..primitives import (
    PUK_INPUT,
    _slot_ref,
    _verifier_value,
)
from .facts import _collect_quickstart_facts
from .options import _check_certificate_options, _resolve_algorithm
from .plan import _plan_for_profile, _refuse_missing_rsa_object
from .preflight import _confirm_plan, _pre_flight_pin, _vet_plan
from .report import _show_dry_run, _show_result
from .steps import _export_kept_public_key, _Run, _run_steps


def _state_after(session: CardSession, ref: int, mech: int) -> str:
    try:
        _, state = _collect_quickstart_facts(session, ref, mech)
    except CryptnoxError:
        return "unknown"
    return state


@click.command("quickstart")
@click.option(
    "--slot",
    default="9C",
    show_default=True,
    help="Key slot hex. Certificate modes need a SIGN-role slot (9C on this applet).",
)
@click.option(
    "--algorithm",
    default="ECCP256",
    show_default=True,
    help="ECCP256, ECCP384, RSA2048, RSA3072 or RSA4096. Default ECCP256, except RSA2048 "
    "for --profile ms-logon or ms-logon-nfc with --slot 9A, the Windows shape (Windows "
    "does not enumerate EC keys). The slot must have a key object for it: among the "
    "built-in profiles, RSA only on the 9A of those two.",
)
@click.option("--subject", default="CN=Cryptnox Dev Card", show_default=True)
@click.option("--days", default=365, show_default=True, type=int)
@click.option(
    "--cert-mode",
    type=click.Choice(["self-signed", "csr", "none"]),
    default="self-signed",
    show_default=True,
    help="self-signed: sign on-card and import. csr: write a CSR for an external CA. "
    "none: keys/objects only.",
)
@click.option(
    "--csr-out",
    type=click.Path(dir_okay=False),
    help="Where to write the CSR (required with --cert-mode csr).",
)
@click.option(
    "--cert-out",
    type=click.Path(dir_okay=False),
    help="Also write the self-signed certificate PEM to FILE.",
)
@click.option(
    "--public-out", type=click.Path(dir_okay=False), help="Also write the public-key PEM to FILE."
)
@click.option(
    "--include-preperso",
    is_flag=True,
    help="If the PIV structure is missing, lay it down first from --profile. Cards ship "
    "without it; once laid down it can be extended but not changed.",
)
@click.option(
    "--profile",
    "profile_name",
    default="cryptnox-default",
    show_default=True,
    help="Built-in pre-perso profile used by --include-preperso (e.g. ms-logon for a "
    "SIGN-capable 9A / Windows logon card; ms-logon-nfc for logon over NFC, on the "
    "applet build with FIPS mode off).",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the publicly known GlobalPlatform TEST keys for the admin channel, and "
    "the same published value for the PIV management key (9B) if the card needs it "
    "(fine for dev/eval, never for deployment).",
)
@click.option(
    "--dry-run", "dry_run", is_flag=True, help="Detect, plan and show the steps; write nothing."
)
@click.pass_obj
def quickstart(
    app: AppContext,
    slot: str,
    algorithm: str,
    subject: str,
    days: int,
    cert_mode: str,
    csr_out: str | None,
    cert_out: str | None,
    public_out: str | None,
    include_preperso: bool,
    profile_name: str,
    default_keys: bool,
    dry_run: bool,
) -> None:
    """One-shot personalization: a blank or part-done card -> usable by standard
    PIV tooling (yubico-piv-tool, OpenSC).

    Chains [preperso] -> PIN -> PUK -> key -> certificate -> CHUID/CCC ->
    smoke-test over one card connection, skipping whatever is already done, and
    ends with the commands to verify the result. Contact reader required.
    """
    import sys

    ref = _slot_ref(slot)
    alg, mech, windows_rsa_shape = _resolve_algorithm(app, profile_name, ref, algorithm)
    keyimport.validate_slot_mechanism(ref, mech)
    profile = prof_mod.builtin(profile_name)  # validates the name early (exit 8 on typo)
    _check_certificate_options(ref, cert_mode, csr_out, cert_out)

    with app.open_session() as session:
        facts, state_before = _collect_quickstart_facts(session, ref, mech)
        _refuse_missing_rsa_object(facts, alg, ref, windows_rsa_shape)
        steps = _plan_for_profile(facts, ref, mech, cert_mode, include_preperso, profile)
        _vet_plan(app, session, steps, facts, profile, ref, mech, csr_out)
        if dry_run or app.dry_run:
            _show_dry_run(app, steps, state_before)
            return

        keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
        steps, pin = _pre_flight_pin(app, session, steps)
        _confirm_plan(app, steps, profile)
        sets_puk = any(s.run and s.step == "set-puk" for s in steps)
        puk = _verifier_value(app, PUK_INPUT.new) if sets_puk else None
        run = _Run(
            app=app,
            session=session,
            adm=PivAdmin(session),
            keys=keys,
            slot=slot,
            ref=ref,
            mech=mech,
            alg=alg,
            profile=profile,
            cert_mode=cert_mode,
            subject=subject,
            days=days,
            csr_out=csr_out,
            cert_out=cert_out,
            public_out=public_out,
            default_keys=default_keys,
            pin=pin,
            puk=puk,
        )
        executed, failed = _run_steps(run, steps)
        if public_out and run.outputs["public_key"] is None and not failed:
            _export_kept_public_key(run, public_out)
        state_after = _state_after(session, ref, mech)

    _show_result(run, executed, state_before, state_after, failed)
    if failed:
        sys.exit(6)
