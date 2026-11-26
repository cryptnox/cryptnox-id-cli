# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv pin`` and ``piv puk``: cardholder PIN and PUK status, verification and changes."""

from __future__ import annotations

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.applets.piv import verifier
from cryptnox_id_cli.cli.context import AppContext

from .primitives import (
    PIN_INPUT,
    PUK_INPUT,
    _exit_if_refused,
    _select,
    _styled_status,
    _verifier_value,
)


# -------------------------------------------------------------------- pin --- #
@click.group("pin")
def pin() -> None:
    """PIN/PUK status and verification."""


@pin.command("status")
@click.pass_obj
def pin_status(app: AppContext) -> None:
    """Show PIN and PUK status (non-decrementing query)."""
    with app.open_session() as session:
        probe = verifier.status(_select(session))

    def human(c: Console) -> None:
        for label, st in (("PIN (80)", probe.pin), ("PUK (81)", probe.puk)):
            if st is None:
                continue
            c.print(f"  {label}: {_styled_status(st, 'green')}")
        note = probe.note
        if note:
            c.print(f"[yellow]*[/yellow] {escape(note[0].upper() + note[1:])}")

    app.out.result(probe.to_dict(), human)


@pin.command("verify")
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def pin_verify(app: AppContext, pin_value: str | None) -> None:
    """Verify the PIV PIN. A wrong PIN consumes one retry."""
    app.out.warn("a wrong PIN decrements the retry counter.")
    secret = _verifier_value(app, PIN_INPUT, pin_value)
    with app.open_session() as session:
        outcome = verifier.verify(_select(session), secret)
    _show_outcome(app, "PIN", outcome)


def _show_outcome(app: AppContext, label: str, outcome: verifier.Outcome) -> None:
    """Print a cardholder PIN or PUK command's result, then exit 6 when the card refused."""
    verb = outcome.op.value.verb

    def human(c: Console) -> None:
        if outcome.ok:
            c.print(f"[green]{label} {verb}.[/green]")
            return
        c.print(f"[red]{label} not {verb}:[/red] {escape(outcome.message)} (SW={outcome.sw_hex})")
        if outcome.recovery:
            c.print(f"  [red]{escape(outcome.recovery)}[/red]")
        if outcome.hint:
            c.print(f"  [yellow]{escape(outcome.hint)}[/yellow]")

    app.out.result(outcome.payload(), human)
    _exit_if_refused(outcome.ok)


@pin.command("change")
@click.option("--old-pin", help="(discouraged) current PIN on the CLI; prefer prompt/env.")
@click.option("--new-pin", help="(discouraged) new PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def pin_change(app: AppContext, old_pin: str | None, new_pin: str | None) -> None:
    """Change the PIV PIN (cardholder). A wrong current PIN consumes one retry."""
    app.out.warn("a wrong current PIN decrements the retry counter.")
    old = _verifier_value(app, PIN_INPUT.current, old_pin)
    new = _verifier_value(app, PIN_INPUT.new, new_pin)
    with app.open_session() as session:
        outcome = verifier.change(_select(session), verifier.PIN, old, new)
    _show_outcome(app, "PIN", outcome)


@pin.command("unblock")
@click.option("--puk", "puk_value", help="(discouraged) PUK on the CLI; prefer prompt/env.")
@click.option("--new-pin", help="(discouraged) new PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def pin_unblock(app: AppContext, puk_value: str | None, new_pin: str | None) -> None:
    """Set a new PIN and reset its retry counter using the PUK (RESET RETRY COUNTER).

    Works on a PIN that is not blocked too, so it doubles as a test that the PUK is
    right. A correct PUK also resets the PUK's own retry counter.
    """
    app.out.warn("a wrong PUK decrements the PUK counter; a blocked PUK is unrecoverable.")
    puk = _verifier_value(app, PUK_INPUT, puk_value)
    new = _verifier_value(app, PIN_INPUT.new, new_pin)
    with app.open_session() as session:
        outcome = verifier.unblock(_select(session), puk, new)
    _show_outcome(app, "PIN", outcome)


@click.group("puk")
def puk() -> None:
    """PUK operations (the unblocking secret for the PIN)."""


@puk.command("change")
@click.option("--old-puk", help="(discouraged) current PUK on the CLI; prefer prompt/env.")
@click.option("--new-puk", help="(discouraged) new PUK on the CLI; prefer prompt/env.")
@click.pass_obj
def puk_change(app: AppContext, old_puk: str | None, new_puk: str | None) -> None:
    """Change the PIV PUK (cardholder). A wrong current PUK consumes one retry."""
    app.out.warn("a wrong current PUK decrements the retry counter.")
    old = _verifier_value(app, PUK_INPUT.current, old_puk)
    new = _verifier_value(app, PUK_INPUT.new, new_puk)
    with app.open_session() as session:
        outcome = verifier.change(_select(session), verifier.PUK, old, new)
    _show_outcome(app, "PUK", outcome)
