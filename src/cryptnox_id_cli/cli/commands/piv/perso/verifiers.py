# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso set-pin`` and ``set-puk``."""

from __future__ import annotations

import click

from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import verifier
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys
from cryptnox_id_cli.transport.errors import describe_sw

from ..primitives import (
    PIN_INPUT,
    PUK_INPUT,
    _exit_if_refused,
    _SecretInput,
    _set_verifier,
    _verifier_value,
)


def _set_verifier_value(
    app: AppContext, ref: int, source: _SecretInput, pin_value: str | None, default_keys: bool
) -> None:
    label = source.what
    app.out.warn(f"replaces the current {label} without needing its value (admin channel write).")
    padded = verifier.pad(_verifier_value(app, source.new, pin_value))
    app.redactor.register(padded)
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        resp = _set_verifier(PivAdmin(session), keys, ref, padded, label=label)
    info = describe_sw(resp.sw1, resp.sw2)
    app.out.result(
        {"ref": f"{ref:02X}", "set": resp.ok, "sw": info.sw_hex()},
        lambda c: c.print(
            f"[green]{label} set.[/green]"
            if resp.ok
            else f"[red]{label} not set:[/red] {info.message} (SW={info.sw_hex()})"
        ),
    )
    _exit_if_refused(resp.ok)


@click.command("set-pin")
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_set_pin(app: AppContext, pin_value: str | None, default_keys: bool) -> None:
    """Set the initial PIV PIN value (CHANGE REFERENCE DATA ADMIN over SCP03)."""
    _set_verifier_value(app, pivc.REF_PIV_PIN, PIN_INPUT, pin_value, default_keys)


@click.command("set-puk")
@click.option("--puk", "pin_value", help="(discouraged) PUK on the CLI; prefer prompt/env.")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_set_puk(app: AppContext, pin_value: str | None, default_keys: bool) -> None:
    """Set the initial PIV PUK value (CHANGE REFERENCE DATA ADMIN over SCP03)."""
    _set_verifier_value(app, pivc.REF_PUK, PUK_INPUT, pin_value, default_keys)
