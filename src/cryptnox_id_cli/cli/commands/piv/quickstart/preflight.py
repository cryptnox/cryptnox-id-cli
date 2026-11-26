# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What quickstart checks and asks before it writes to the card."""

from __future__ import annotations

import click

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv import verifier
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.pcsc import CardSession

from ..primitives import (
    PIN_INPUT,
    PUK_INPUT,
    _key_template,
    _refuse_on_fips_mode_build,
    _select,
    _verifier_value,
)
from .plan import CardFacts, PlannedStep, _apply_pin_truth


def _vet_plan(
    app: AppContext,
    session: CardSession,
    steps: list[PlannedStep],
    facts: CardFacts,
    profile: prof_mod.PivProfile,
    ref: int,
    mech: int,
    csr_out: str | None,
) -> None:
    """The refusals and warnings that come before the plan is shown or run."""
    import os

    if steps[0].run:
        if not profile.fips_mode:
            # Before the plan is shown: a dry run must not promise what the card refuses.
            _refuse_on_fips_mode_build(session, profile)
        for warning in (profile.piv_auth_warning(), profile.contactless_pin_warning()):
            if warning:
                app.out.warn(warning)
    by_step = {s.step: s for s in steps}
    if by_step["certificate"].run and facts.other_cert:
        app.out.warn(
            f"the certificate step replaces the {facts.other_cert} certificate now in "
            f"slot {ref:02X}."
        )
    if by_step["certificate"].run and facts.listing_withheld:
        app.out.warn(
            "this card withholds its key listing, so quickstart cannot check before "
            f"writing that the key in slot {ref:02X} can sign."
        )
    _, _, new_role, _ = _key_template(ref, mech, profile)
    if steps[1].run and not preperso_mod.key_signs(new_role, mech):
        app.out.warn(
            f"the key object quickstart adds to slot {ref:02X} gets the role "
            f"{prof_mod.role_name(new_role)} from profile '{profile.name}' and cannot sign; "
            "it is permanent."
        )

    if csr_out and not by_step["certificate"].run:
        raise CryptnoxError(
            f"slot {ref:02X} already has a certificate for this key, so quickstart keeps the "
            f"key and makes no CSR. For a CSR on that key use `{CLI_NAME} piv perso "
            f"generate-csr --slot {ref:02X}`."
        )
    # A dry run must not prompt, so only a value already given can be refused this early.
    for step, source in (("set-pin", PIN_INPUT.new), ("set-puk", PUK_INPUT.new)):
        if by_step[step].run and source.env_var in os.environ:
            _verifier_value(app, source)


def _pre_flight_pin(
    app: AppContext, session: CardSession, steps: list[PlannedStep]
) -> tuple[list[PlannedStep], bytes]:
    """The PIN, and the plan as a VERIFY corrects it: the probe cannot tell a set PIN from
    a valueless one."""
    run_set = {s.step for s in steps if s.run}
    pin = _verifier_value(app, PIN_INPUT.new if "set-pin" in run_set else PIN_INPUT)
    if "set-pin" in run_set:
        return steps, pin
    outcome = verifier.verify(_select(session), pin)
    if outcome.verdict in (verifier.Verdict.WRONG, verifier.Verdict.NO_RETRY_LIMIT):
        spent = "This pre-flight check consumed one retry"
        if run_set & {"certificate", "smoke-test"}:
            spent += ", which the certificate or smoke-test step would have used otherwise"
        raise CryptnoxError(
            f"the PIN is set and the provided PIN does not match ({outcome.status_text}). "
            f"{spent}. Provide the card's PIN (CRYPTNOX_PIV_PIN or the prompt) and re-run."
        )
    empty = outcome.verdict is verifier.Verdict.NO_VALUE
    if not (outcome.ok or empty):
        raise outcome.error("VERIFY PIN (quickstart pre-flight)")
    if empty:
        app.out.warn(
            "the PIN verifier exists but holds no value (structure loaded without "
            "personalization), so the provided PIN will be SET; the PUK likewise."
        )
    return _apply_pin_truth(steps, empty), pin


def _confirm_plan(app: AppContext, steps: list[PlannedStep], profile: prof_mod.PivProfile) -> None:
    """Say what will run, and ask before anything is written."""
    to_run = [s.step for s in steps if s.run]
    if to_run:
        app.out.warn(f"quickstart will run: {', '.join(to_run)}")
    else:
        app.out.warn("quickstart has nothing left to run on this card.")
    if steps[0].run:
        app.out.warn(
            f"--include-preperso lays down the applet structure from profile "
            f"'{profile.name}'; it cannot be changed or removed afterwards."
        )
    if to_run and not app.yes and not click.confirm("Proceed?", default=False):
        raise click.Abort()
