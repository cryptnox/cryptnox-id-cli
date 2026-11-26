# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso import-key`` and ``import-p12``, with the key file helpers."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import keyimport, verifier
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import x509util
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys, resolve_secret
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError

from ..primitives import (
    _IMPORT_SW_HINTS,
    PIN_INPUT,
    SLOT_CERT_OBJECT,
    _create_key_object,
    _import_cert_der,
    _select,
    _slot_ref,
    _verifier_value,
)


def _load_private_key_file(app: AppContext, raw: bytes, password: str | None):
    """Load a private key, resolving a decryption password only if it is needed."""
    try:
        return keyimport.load_private_key(raw, password.encode() if password else None)
    except TypeError:
        # Encrypted key, no password given: env var or masked prompt.
        secret = resolve_secret(
            redactor=app.redactor,
            env_var="CRYPTNOX_PIV_KEY_PASSWORD",
            prompt_label="Key file password",
            provided=None,
        )
        try:
            return keyimport.load_private_key(raw, secret)
        except ValueError as exc:
            raise CryptnoxError(f"could not decrypt the private key: {exc}") from exc
    except ValueError as exc:
        raise CryptnoxError(f"could not load the private key: {exc}") from exc


def _warn_key_file_permissions(app: AppContext, path: str) -> None:
    import os
    import stat

    if os.name == "nt":  # POSIX mode bits are meaningless on Windows
        return
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        app.out.warn(f"{path} is group/world-readable; consider chmod 600.")


def _execute_key_import(
    app: AppContext,
    session,
    adm: PivAdmin,
    keys,
    ref: int,
    mech: int,
    plan: list[keyimport.KeyElement],
    slot: str,
    *,
    create_key_object: bool,
    rsa_crt: bool,
) -> list[dict[str, object]]:
    """Probe for the (slot, mechanism) key object — optionally creating it — then
    send the element sequence, one fresh SCP03 session per element (JCOP 4.5)."""
    _select(session)
    probe = session.transmit(keyimport.probe_apdu(ref, mech), context=f"probe {slot}")
    if probe.sw == 0x6A86:
        if not create_key_object:
            alg_name = pivc.ALGORITHMS[mech]
            raise CryptnoxError(
                f"slot {slot} has no {alg_name} key object: {_IMPORT_SW_HINTS[0x6A88]}."
            )
        _create_key_object(app, adm, keys, ref, mech, rsa_crt, slot)

    results: list[dict[str, object]] = []
    for index, el in enumerate(plan, 1):
        adm.select()
        adm.open(keys)
        body = el.body()
        label = f"IMPORT {slot} [{el.label}] [{index}/{len(plan)}]"
        if len(body) > keyimport.SINGLE_APDU_MAX:
            resp = adm.send_chained(
                keyimport.INS_CHANGE_REFERENCE_DATA, mech, ref, body, context=label
            )
        else:
            resp = adm.send(keyimport.import_apdu(ref, mech, el), context=label)
        results.append({"element": el.label, "sw": resp.sw_hex(), "ok": resp.ok})
        if not resp.ok:
            hint = _IMPORT_SW_HINTS.get(resp.sw)
            app.out.warn(
                "the key is left uninitialised - that is safe; re-run the import "
                "(it starts with a CLEAR) or generate a key instead."
            )
            ctx = f"IMPORT {slot} [{el.label}]" + (f" - {hint}" if hint else "")
            raise StatusWordError(resp.sw1, resp.sw2, context=ctx)
    return results


def _post_import_smoke(
    app: AppContext, session, ref: int, mech: int, key, pin_secret: bytes
) -> dict[str, object]:
    """Prove the imported key: verify the PIN, sign on-card, verify host-side
    against the key. A SIGN-incapable slot role reports a note, not a failure."""
    import hashlib
    import os

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

    modulus_len = keyimport.rsa_modulus_len(mech)
    verifier.require_pin(_select(session), pin_secret)
    message = os.urandom(32)
    hash_alg = keyimport.digest_for_mechanism(mech)
    digest = hashlib.new(hash_alg.name, message).digest()
    challenge = keyimport.emsa_pkcs1_v15(digest, modulus_len) if modulus_len else digest
    apdu = perso_mod.general_authenticate_sign_apdu(ref, mech, challenge)
    if len(apdu.data) > 0xFF:  # oversized body: plain-channel ISO chaining
        resp = session.transmit_chained(apdu, context="GENERAL AUTHENTICATE (smoke)")
    else:
        resp = session.transmit(apdu, context="GENERAL AUTHENTICATE (smoke)")
    if resp.sw == 0x6985:
        return {"signed": False, "note": "import OK; this slot's role cannot sign on this applet"}
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context="GENERAL AUTHENTICATE (smoke)")
    signature = perso_mod.parse_sign_response(resp.data)
    public_key = key.public_key()
    try:
        if modulus_len:
            public_key.verify(signature, message, rsa_padding.PKCS1v15(), hash_alg)
        else:
            public_key.verify(signature, message, ec_mod.ECDSA(hash_alg))
    except InvalidSignature as exc:
        raise CryptnoxError(
            "the on-card signature does not verify against the imported key - wrong "
            "key material landed?"
        ) from exc
    return {"signed": True, "verified": True}


@click.command("import-key")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9C.")
@click.option(
    "--key",
    "key_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Private key file (PEM or DER; PKCS#8 or traditional).",
)
@click.option(
    "--password",
    help="(discouraged) key-file password; prefer $CRYPTNOX_PIV_KEY_PASSWORD or the prompt.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option(
    "--rsa-form",
    type=click.Choice(["crt", "plain"]),
    default="crt",
    show_default=True,
    help="RSA private-key element form; must match the key object's CRT attribute.",
)
@click.option(
    "--create-key-object",
    is_flag=True,
    help="Dev/eval: create the (slot, mechanism) key object first if it is missing "
    "(structural PUT DATA ADMIN; a finalized applet refuses this). The object is "
    "permanent, also if the chip then refuses the key size.",
)
@click.option(
    "--public-out",
    "public_out",
    type=click.Path(dir_okay=False),
    help="Write the derived public-key PEM to FILE.",
)
@click.option("--pin", "pin_value", help="(discouraged) PIN for the post-import signing check.")
@click.option("--no-smoke-test", is_flag=True, help="Skip the post-import signing check.")
@click.option("--dry-run", "dry_run", is_flag=True, help="Show the element plan; nothing is sent.")
@click.pass_obj
def perso_import_key(
    app: AppContext,
    slot: str,
    key_file: str,
    password: str | None,
    default_keys: bool,
    rsa_form: str,
    create_key_object: bool,
    public_out: str | None,
    pin_value: str | None,
    no_smoke_test: bool,
    dry_run: bool,
) -> None:
    """Import an EXTERNAL private key into a PIV slot (over SCP03).

    Use this for a key generated off-card. For an on-card RSA key, `generate-key`
    works on any slot that has a key object for that mechanism (profile-dependent:
    cryptnox-default provides ECC objects only, ms-logon adds RSA2048 on 9A).
    The key goes to the card one element per SCP03 session, starting with a CLEAR,
    so a re-run of the same import is safe.
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    ref = _slot_ref(slot)
    key = _load_private_key_file(app, Path(key_file).read_bytes(), password)
    mech = keyimport.mechanism_for_key(key)
    keyimport.validate_slot_mechanism(ref, mech)
    alg_name = pivc.ALGORITHMS[mech]
    modulus_len = keyimport.rsa_modulus_len(mech)
    plan = keyimport.element_plan(key, rsa_crt=(rsa_form == "crt"))
    for el in plan:
        if el.secret:
            app.redactor.register(el.value)
    _warn_key_file_permissions(app, key_file)

    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(spki).hexdigest().upper()
    steps = [
        {
            "element": el.label,
            "bytes": len(el.body()),
            "chained": len(el.body()) > keyimport.SINGLE_APDU_MAX,
        }
        for el in plan
    ]

    if dry_run or app.dry_run:
        result = {
            "dry_run": True,
            "slot": slot,
            "algorithm": alg_name,
            "rsa_form": rsa_form if modulus_len else None,
            "elements": steps,
            "scp03_sessions": len(plan),
        }

        def human_dry(c: Console) -> None:
            c.print(f"[bold]DRY RUN[/bold] - import {alg_name} into slot {slot}:")
            for s in steps:
                via = "chained" if s["chained"] else "single APDU"
                c.print(f"    {s['element']}: {s['bytes']} bytes ({via}, own SCP03 session)")
            c.print("\n  [dim]Nothing was sent to the card.[/dim]")

        app.out.result(result, human_dry)
        return

    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    smoke_pin = None if no_smoke_test else _verifier_value(app, PIN_INPUT, pin_value)
    smoke: dict[str, object] | None = None
    with app.open_session() as session:
        adm = PivAdmin(session)
        results = _execute_key_import(
            app,
            session,
            adm,
            keys,
            ref,
            mech,
            plan,
            slot,
            create_key_object=create_key_object,
            rsa_crt=(rsa_form == "crt"),
        )
        if smoke_pin is not None:
            smoke = _post_import_smoke(app, session, ref, mech, key, smoke_pin)

    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if public_out:
        Path(public_out).write_bytes(pem)
    payload = {
        "slot": slot,
        "algorithm": alg_name,
        "rsa_form": rsa_form if modulus_len else None,
        "elements": results,
        "scp03_sessions": len(plan),
        "public_key_sha256": fingerprint,
        "public_out": public_out,
        "smoke_test": smoke,
    }

    def human(c: Console) -> None:
        c.print(f"[green]Imported {alg_name} key into slot {slot}[/green] ({len(plan)} elements).")
        c.print(f"  Public key SHA-256: {fingerprint}")
        if public_out:
            c.print(f"  Public key PEM -> {escape(public_out)}")
        if smoke is None:
            c.print("  [dim]Smoke test skipped.[/dim]")
        elif smoke.get("signed"):
            c.print("  Smoke test: [green]signed on-card, verified against the key[/green].")
        else:
            c.print(f"  Smoke test: [yellow]{smoke.get('note')}[/yellow]")

    app.out.result(payload, human)


@click.command("import-p12")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option(
    "--p12",
    "p12_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="PKCS#12 container (.p12/.pfx) holding the private key and its certificate.",
)
@click.option(
    "--password",
    help="(discouraged) container password; prefer $CRYPTNOX_PIV_P12_PASSWORD or the prompt.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option(
    "--rsa-form",
    type=click.Choice(["crt", "plain"]),
    default="crt",
    show_default=True,
    help="RSA private-key element form; must match the key object's CRT attribute.",
)
@click.option(
    "--create-key-object",
    is_flag=True,
    help="Dev/eval: create the (slot, mechanism) key object first if it is missing "
    "(structural PUT DATA ADMIN; a finalized applet refuses this). The object is "
    "permanent, also if the chip then refuses the key size.",
)
@click.option("--pin", "pin_value", help="(discouraged) PIN for the post-import signing check.")
@click.option("--no-smoke-test", is_flag=True, help="Skip the post-import signing check.")
@click.option("--dry-run", "dry_run", is_flag=True, help="Show the plan; nothing is sent.")
@click.pass_obj
def perso_import_p12(
    app: AppContext,
    slot: str,
    p12_file: str,
    password: str | None,
    default_keys: bool,
    rsa_form: str,
    create_key_object: bool,
    pin_value: str | None,
    no_smoke_test: bool,
    dry_run: bool,
) -> None:
    """Import a PKCS#12 credential (private key + certificate) into a PIV slot.

    The one-command device-setup flow for credentials issued by a PKI (e.g. an
    AD CA for Windows logon / Remote Desktop): the key goes over SCP03 one
    element per session starting with a CLEAR, then the certificate lands in
    the slot's container. Extra CA certificates in the container are ignored
    (PIV containers hold the entity certificate only).
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    ref = _slot_ref(slot)
    if ref not in SLOT_CERT_OBJECT:
        raise click.BadParameter(
            f"slot {slot} has no certificate container; import-p12 needs one "
            "(9A/9C/9D/9E). For a bare key use `piv perso import-key`.",
            param_hint="--slot",
        )
    raw = Path(p12_file).read_bytes()
    key, cert_der, extras = _load_p12_file(app, raw, password)
    mech = keyimport.mechanism_for_key(key)
    keyimport.validate_slot_mechanism(ref, mech)
    alg_name = pivc.ALGORITHMS[mech]
    modulus_len = keyimport.rsa_modulus_len(mech)

    # The container must actually pair: certificate public key == private key.
    from cryptography import x509

    cert_pub = x509.load_der_x509_certificate(cert_der).public_key()
    if cert_pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise CryptnoxError(
            "the PKCS#12 certificate does not match its private key - refusing to "
            "import a mismatched pair."
        )

    plan = keyimport.element_plan(key, rsa_crt=(rsa_form == "crt"))
    for el in plan:
        if el.secret:
            app.redactor.register(el.value)
    _warn_key_file_permissions(app, p12_file)
    cert_desc = x509util.describe_certificate(cert_der)
    fingerprint = (
        hashlib.sha256(
            key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        .hexdigest()
        .upper()
    )

    if dry_run or app.dry_run:
        steps = [
            {
                "element": el.label,
                "bytes": len(el.body()),
                "chained": len(el.body()) > keyimport.SINGLE_APDU_MAX,
            }
            for el in plan
        ]
        result = {
            "dry_run": True,
            "slot": slot,
            "algorithm": alg_name,
            "elements": steps,
            "certificate": cert_desc,
            "extra_certs_ignored": len(extras),
        }

        def human_dry(c: Console) -> None:
            c.print(f"[bold]DRY RUN[/bold] - import {alg_name} key + certificate into {slot}:")
            for s in steps:
                via = "chained" if s["chained"] else "single APDU"
                c.print(f"    {s['element']}: {s['bytes']} bytes ({via}, own SCP03 session)")
            subject = escape(str(cert_desc.get("subject")))
            c.print(f"    certificate ({subject}): chained PUT DATA")
            if extras:
                c.print(f"    [dim]{len(extras)} chain certificate(s) ignored[/dim]")
            c.print("\n  [dim]Nothing was sent to the card.[/dim]")

        app.out.result(result, human_dry)
        return

    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    smoke_pin = None if no_smoke_test else _verifier_value(app, PIN_INPUT, pin_value)
    smoke: dict[str, object] | None = None
    with app.open_session() as session:
        adm = PivAdmin(session)
        results = _execute_key_import(
            app,
            session,
            adm,
            keys,
            ref,
            mech,
            plan,
            slot,
            create_key_object=create_key_object,
            rsa_crt=(rsa_form == "crt"),
        )
        cert_resp = _import_cert_der(adm, keys, ref, cert_der, label=slot)
        if not cert_resp.ok:
            raise StatusWordError(cert_resp.sw1, cert_resp.sw2, context=f"IMPORT cert {slot}")
        if smoke_pin is not None:
            smoke = _post_import_smoke(app, session, ref, mech, key, smoke_pin)

    payload = {
        "slot": slot,
        "algorithm": alg_name,
        "rsa_form": rsa_form if modulus_len else None,
        "elements": results,
        "certificate": cert_desc,
        "extra_certs_ignored": len(extras),
        "public_key_sha256": fingerprint,
        "smoke_test": smoke,
    }

    def human(c: Console) -> None:
        c.print(f"[green]Imported {alg_name} credential into slot {slot}[/green].")
        subject = escape(str(cert_desc.get("subject")))
        c.print(f"  Certificate: {subject} (expires {cert_desc.get('not_after')})")
        if extras:
            c.print(f"  [dim]{len(extras)} chain certificate(s) ignored.[/dim]")
        if smoke is None:
            c.print("  [dim]Smoke test skipped.[/dim]")
        elif smoke.get("signed"):
            c.print("  Smoke test: [green]signed on-card, verified against the key[/green].")
        else:
            c.print(f"  Smoke test: [yellow]{smoke.get('note')}[/yellow]")

    app.out.result(payload, human)


def _load_p12_file(app: AppContext, raw: bytes, password: str | None):
    """Parse a PKCS#12 container, resolving the password only when needed.
    PKCS#12 cannot distinguish a wrong password from corrupt data, so the first
    passwordless attempt falling through to a prompt is the best we can do."""
    if password is not None:
        try:
            return keyimport.load_pkcs12(raw, password.encode())
        except ValueError as exc:
            raise CryptnoxError(f"could not open the PKCS#12 file: {exc}") from exc
    try:
        return keyimport.load_pkcs12(raw, None)
    except ValueError:
        secret = resolve_secret(
            redactor=app.redactor,
            env_var="CRYPTNOX_PIV_P12_PASSWORD",
            prompt_label="PKCS#12 password",
            provided=None,
        )
        try:
            return keyimport.load_pkcs12(raw, secret)
        except ValueError as exc:
            raise CryptnoxError(
                f"could not open the PKCS#12 file (wrong password or corrupt data): {exc}"
            ) from exc
