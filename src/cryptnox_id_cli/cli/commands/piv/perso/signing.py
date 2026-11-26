# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""On-card signing for the perso commands, and ``piv perso smoke-test``."""

from __future__ import annotations

import click

from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import keyimport, verifier
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.cli.context import AppContext

from ..primitives import (
    PIN_INPUT,
    _sign_with_session,
    _slot_ref,
    _verifier_value,
)


def _resolve_asym_mech(algorithm: str) -> int:
    mech = perso_mod.ALGORITHMS.get(algorithm.upper())
    if mech is None or mech not in pivc.SUPPORTED_ALGORITHMS:
        raise click.BadParameter(f"algorithm {algorithm!r} not supported by this applet")
    return mech


def _sign_on_card(
    app: AppContext,
    ref: int,
    mech: int,
    pin_value: str | None,
    build,
    *,
    pin_bytes: bytes | None = None,
):
    """Verify PIN, then run ``build(signer)`` where signer computes an on-card
    signature over a digest via GENERAL AUTHENTICATE.

    For RSA mechanisms the card performs a raw private-key operation over a full
    modulus-length block, so the digest is EMSA-PKCS1-v1_5 encoded here first; the
    resulting command exceeds a short APDU and goes out via ISO command chaining.
    """
    if pin_bytes is not None:
        verifier.check_length(pin_bytes, PIN_INPUT.what)
        pin = pin_bytes
    else:
        pin = _verifier_value(app, PIN_INPUT, pin_value)
    with app.open_session() as session:
        return _sign_with_session(session, ref, mech, pin, build)


@click.command("smoke-test")
@click.option("--slot", default="9C", show_default=True, help="A SIGN-capable slot.")
@click.option("--algorithm", default="ECCP256", show_default=True)
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def perso_smoke_test(app: AppContext, slot: str, algorithm: str, pin_value: str | None) -> None:
    """Fast post-perso check: verify the PIN and perform one on-card signature."""
    import os

    ref = _slot_ref(slot)
    mech = _resolve_asym_mech(algorithm)
    # Digest size must match the mechanism's hash (SHA-256=32, SHA-384=48); a fixed 32-byte
    # challenge makes the card reject ECCP384 with 6A80. Mirror the import/quickstart paths.
    digest = os.urandom(keyimport.digest_for_mechanism(mech).digest_size)
    signature = _sign_on_card(app, ref, mech, pin_value, lambda s: s(digest))
    app.out.result(
        {"slot": slot, "pin_verified": True, "signed": True, "signature_len": len(signature)},
        lambda c: c.print(
            f"[green]Smoke test OK[/green]: PIN verified and slot {slot} produced a "
            f"{len(signature)}-byte signature."
        ),
    )
