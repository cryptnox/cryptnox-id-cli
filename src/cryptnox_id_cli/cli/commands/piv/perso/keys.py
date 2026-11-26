# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso generate-key`` and ``create-key-object``."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import inventory as inventory_mod
from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys
from cryptnox_id_cli.transport.errors import CryptnoxError

from ..primitives import (
    _ALGORITHM_NAMES,
    _FINALIZED_NO_NEW_KEYS,
    _SIGNING_SLOTS,
    SLOT_CERT_OBJECT,
    _certificate_mechanism,
    _create_key_object,
    _generate_key_on_card,
    _read_cert_der,
    _select,
    _send_create_key,
    _slot_ref,
)
from .signing import _resolve_asym_mech


@click.command("generate-key")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option(
    "--algorithm",
    default="ECCP256",
    show_default=True,
    help="ECCP256/ECCP384/RSA2048/RSA3072/RSA4096.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the publicly known GlobalPlatform TEST keys for the admin channel, and "
    "the same published value for the PIV management key (9B) if the card needs it "
    "(fine for dev/eval, never for deployment).",
)
@click.option(
    "--out", "out_", type=click.Path(dir_okay=False), help="Write public-key PEM to FILE."
)
@click.option(
    "--create-key-object",
    is_flag=True,
    help="If the slot has no key object for this (slot, algorithm) pair, create one "
    "first (PUT DATA ADMIN, non-finalized cards only) - same dev/eval fallback as "
    "`import-key --create-key-object`. The object is permanent, also if the chip then "
    "refuses the key size.",
)
@click.pass_obj
def perso_generate_key(
    app: AppContext,
    slot: str,
    algorithm: str,
    default_keys: bool,
    out_: str | None,
    create_key_object: bool,
) -> None:
    """Generate a key pair ON-CARD; the private key never leaves the card.

    Replaces the slot's key for this algorithm IRREVERSIBLY. When the slot's
    certificate is for that key, or cannot be matched to a key, this asks for
    confirmation first (``--yes`` skips); a key without a certificate cannot be
    detected and is replaced without a prompt.
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    ref = _slot_ref(slot)
    alg = algorithm.upper()
    mech = perso_mod.ALGORITHMS.get(alg)
    if mech is None or mech not in pivc.SUPPORTED_ALGORITHMS:
        raise click.BadParameter(f"algorithm {algorithm!r} not supported by this applet")
    try:
        keyimport.validate_slot_mechanism(ref, mech)
    except CryptnoxError as exc:
        raise click.BadParameter(str(exc)) from exc
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        # Same rule quickstart applies: a certificate marks the slot as in use, so a
        # certified key is never replaced silently - the old private key is destroyed
        # irreversibly and every copy of that certificate goes orphan.
        cert_name = SLOT_CERT_OBJECT.get(ref)
        cert_der = _read_cert_der(_select(session), cert_name) if cert_name else None
        cert_mech = _certificate_mechanism(cert_der) if cert_der is not None else None
        # A certificate for the slot's key of another algorithm leaves this key alone.
        if cert_der is not None and cert_mech in (None, mech):
            app.out.warn(
                f"slot {slot} already holds a certificate; generating a new key DESTROYS "
                "the current private key irreversibly and orphans that certificate."
            )
            if not app.yes and not click.confirm(
                f"Replace the certified key in slot {slot}?", default=False
            ):
                raise click.Abort()
        elif cert_mech is not None:
            app.out.note(
                f"slot {slot}'s certificate is for its {_ALGORITHM_NAMES.get(cert_mech)} key, "
                "which this leaves alone; a certificate for the new key would replace it."
            )
        adm = PivAdmin(session)
        if create_key_object:
            _select(session)
            probe = session.transmit(keyimport.probe_apdu(ref, mech), context=f"probe {slot}")
            if probe.sw == 0x6A86:
                _create_key_object(app, adm, keys, ref, mech, False, slot)
        generated = _generate_key_on_card(
            app, adm, keys, ref, mech, label=slot, default_keys=default_keys
        )
    public_key = generated.public_key
    pem = perso_mod.public_key_pem(public_key)
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(der).hexdigest().upper()
    if out_:
        Path(out_).write_bytes(pem)
    payload = {
        "slot": slot,
        "algorithm": alg,
        "public_key_sha256": fingerprint,
        "out": out_,
        "public_key_pem": None if out_ else pem.decode(),
        "generate_path": generated.path,
        "management_key_auth": generated.management_key_auth,
    }
    how = "on-card, via the PIV management key" if generated.management_key_auth else "on-card"

    def human(c: Console) -> None:
        c.print(f"[green]Generated {alg} key in slot {slot}[/green] ({how}).")
        c.print(f"  Public key SHA-256: {fingerprint}")
        if out_:
            c.print(f"  Public key PEM -> {out_}")
        else:
            c.print(pem.decode().rstrip())

    app.out.result(payload, human)


@click.command("create-key-object")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option("--algorithm", required=True, help="ECCP256/ECCP384/RSA2048/RSA3072/RSA4096.")
@click.option(
    "--role",
    required=True,
    help="SIGN, AUTHENTICATE, KEY_ESTABLISH, or a '+'-joined set such as SIGN+AUTHENTICATE.",
)
@click.option(
    "--contact", default="PIN", show_default=True, help="Access mode over the contact interface."
)
@click.option(
    "--contactless",
    default="NEVER",
    show_default=True,
    help="Access mode over the contactless interface.",
)
@click.option(
    "--rsa-crt", is_flag=True, help="RSA only: hold the key in CRT form (what import-key sends)."
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option("--dry-run", is_flag=True, help="Show the key object; send nothing.")
@click.pass_obj
def perso_create_key_object(
    app: AppContext,
    slot: str,
    algorithm: str,
    role: str,
    contact: str,
    contactless: str,
    rsa_crt: bool,
    default_keys: bool,
    dry_run: bool,
) -> None:
    """Add a key object for one (slot, algorithm) pair, with the role you choose.

    A key object is permanent: it cannot be changed or deleted, and a finalized card
    refuses new ones. A slot can hold one object per algorithm, so a slot whose key
    cannot sign gets a signing key by adding an object for another algorithm.
    """
    ref = _slot_ref(slot)
    slot = f"{ref:02X}"
    mech = _resolve_asym_mech(algorithm)
    try:
        keyimport.validate_slot_mechanism(ref, mech)
        role_bits = prof_mod.parse_role(role.replace("-", "_"))
        contact_mode = prof_mod.parse_mode(contact)
        contactless_mode = prof_mod.parse_mode(contactless)
    except CryptnoxError as exc:
        raise click.BadParameter(str(exc)) from exc
    if not role_bits:
        raise click.BadParameter("give at least one role", param_hint="--role")
    if role_bits & preperso_mod.ROLE_SIGN and role_bits & preperso_mod.ROLE_KEY_ESTABLISH:
        raise click.BadParameter(
            "the applet refuses a key object with both SIGN and KEY_ESTABLISH",
            param_hint="--role",
        )
    if rsa_crt and not keyimport.rsa_modulus_len(mech):
        raise click.BadParameter("applies to RSA algorithms only", param_hint="--rsa-crt")
    attrs = preperso_mod.ATTR_IMPORTABLE | (preperso_mod.ATTR_RSA_CRT if rsa_crt else 0)
    alg = algorithm.upper()
    payload: dict[str, object] = {
        "slot": slot,
        "algorithm": alg,
        "roles": inventory_mod.role_names(role_bits),
        "mode_contact": inventory_mod.describe_mode(contact_mode),
        "mode_contactless": inventory_mod.describe_mode(contactless_mode),
        "attributes": inventory_mod.attribute_names(attrs),
    }
    planning = dry_run or app.dry_run
    keys = None if planning else resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        status = inventory_mod.read_status(_select(session))
        if status is not None and status.secured:
            raise CryptnoxError(_FINALIZED_NO_NEW_KEYS)
        probe = session.transmit(keyimport.probe_apdu(ref, mech), context=f"probe {slot}")
        if probe.sw != 0x6A86:
            raise CryptnoxError(
                f"slot {slot} already has a key object for {alg}, and a key object cannot be "
                "changed. Choose another algorithm for the new object."
            )
        if not planning:
            app.out.warn(
                f"this adds a key object for {alg} to slot {slot} for good: it cannot be "
                "changed or deleted later."
            )
            if ref in _SIGNING_SLOTS and not preperso_mod.key_signs(role_bits, mech):
                app.out.warn(
                    f"a key with the role {prof_mod.role_name(role_bits)} cannot sign, which "
                    f"slot {slot} is normally used for."
                )
            if not app.yes and not click.confirm("Create the key object?", default=False):
                raise click.Abort()
            op = preperso_mod.create_key(
                ref, contact_mode, contactless_mode, mech, role_bits, attrs
            )
            _send_create_key(PivAdmin(session), keys, op, slot)

    payload["created"] = not planning
    next_step = f"{CLI_NAME} piv perso generate-key --slot {slot} --algorithm {alg}"
    roles_text = "+".join(inventory_mod.role_names(role_bits))

    def human(c: Console) -> None:
        verb = "[bold]DRY RUN[/bold] - would create" if planning else "[green]Created[/green]"
        c.print(f"{verb} key object {slot} {alg}: role {roles_text}")
        c.print(f"  Contact: {payload['mode_contact']}; contactless: {payload['mode_contactless']}")
        if planning:
            c.print("\n  [dim]Nothing was sent to the card.[/dim]")
        else:
            c.print(f"  Next: {next_step}")

    app.out.result(payload, human)
