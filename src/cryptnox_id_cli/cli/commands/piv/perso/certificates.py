# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso generate-csr``, ``self-sign-cert`` and ``import-cert``."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import csr as csr_mod
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys
from cryptnox_id_cli.transport.errors import CryptnoxError, InputError, StatusWordError, describe_sw

from ..primitives import (
    PIN_INPUT,
    SLOT_CERT_OBJECT,
    _csr_spki,
    _exit_if_refused,
    _import_cert_der,
    _mechanism_for_public_key,
    _sign_with_session,
    _slot_ref,
    _verifier_value,
)
from .signing import _resolve_asym_mech, _sign_on_card


def _load_spki(pubkey_file: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    raw = Path(pubkey_file).read_bytes()
    try:
        pub = serialization.load_pem_public_key(raw)
    except ValueError:
        try:
            pub = serialization.load_der_public_key(raw)
        except ValueError as exc:
            raise InputError(f"{pubkey_file} is not a PEM or DER public key") from exc
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@click.command("generate-csr")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option("--subject", required=True, help='e.g. "CN=John Doe,O=Cryptnox,C=CH"')
@click.option(
    "--public-key", "pubkey_file", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option("--algorithm", default="ECCP256", show_default=True)
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.option("--out", "out_", type=click.Path(dir_okay=False))
@click.pass_obj
def perso_generate_csr(
    app: AppContext,
    slot: str,
    subject: str,
    pubkey_file: str,
    algorithm: str,
    pin_value: str | None,
    out_: str | None,
) -> None:
    """Generate a PKCS#10 CSR; the signature is computed ON-CARD by the slot key."""
    ref = _slot_ref(slot)
    mech = _resolve_asym_mech(algorithm)
    spki = _load_spki(pubkey_file)
    pem = _sign_on_card(
        app, ref, mech, pin_value, lambda s: csr_mod.build_csr(subject, spki, mech, s)
    )
    if out_:
        Path(out_).write_bytes(pem)
    app.out.result(
        {"slot": slot, "subject": subject, "out": out_, "csr_pem": None if out_ else pem.decode()},
        lambda c: c.print(
            f"[green]CSR written to {out_}[/green]" if out_ else pem.decode().rstrip()
        ),
    )


@click.command("self-sign-cert")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option("--subject", required=True, help='e.g. "CN=Test User"')
@click.option(
    "--public-key", "pubkey_file", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option("--algorithm", default="ECCP256", show_default=True)
@click.option("--days", default=365, show_default=True, type=int)
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.option("--out", "out_", type=click.Path(dir_okay=False))
@click.pass_obj
def perso_self_sign_cert(
    app: AppContext,
    slot: str,
    subject: str,
    pubkey_file: str,
    algorithm: str,
    days: int,
    pin_value: str | None,
    out_: str | None,
) -> None:
    """Build a self-signed certificate (DEV/TEST only), signed ON-CARD."""
    import datetime
    import secrets

    app.out.warn("Self-signed certificates are for development/testing only.")
    ref = _slot_ref(slot)
    mech = _resolve_asym_mech(algorithm)
    spki = _load_spki(pubkey_file)
    serial = int.from_bytes(secrets.token_bytes(8), "big") | 1
    not_before = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_after = not_before + datetime.timedelta(days=days)
    pem = _sign_on_card(
        app,
        ref,
        mech,
        pin_value,
        lambda s: csr_mod.build_self_signed(
            subject,
            spki,
            mech,
            s,
            serial=serial,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
        ),
    )
    if out_:
        Path(out_).write_bytes(pem)
    app.out.result(
        {"slot": slot, "subject": subject, "out": out_, "cert_pem": None if out_ else pem.decode()},
        lambda c: c.print(
            f"[green]Self-signed cert written to {out_}[/green]" if out_ else pem.decode().rstrip()
        ),
    )


def _check_slot_signs_for(session, ref: int, public_key, pin: bytes, slot: str) -> None:  # noqa: ANN001
    """One PIN verification and one on-card signature over a fresh challenge, verified
    with the certificate's public key: proof that the certificate is for this slot's key."""
    import hashlib
    import os

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    mech = _mechanism_for_public_key(public_key)
    hash_alg = keyimport.digest_for_mechanism(mech)
    message = os.urandom(32)
    digest = hashlib.new(hash_alg.name, message).digest()
    try:
        signature = _sign_with_session(session, ref, mech, pin, lambda sign: sign(digest))
    except StatusWordError as exc:
        if exc.info.sw_hex() == "6985":
            raise CryptnoxError(
                f"slot {slot} cannot sign on this applet (its role is not SIGN), so the "
                "certificate cannot be checked this way; use --csr instead."
            ) from exc
        if exc.info.sw_hex() == "6A86":
            raise CryptnoxError(
                f"slot {slot} holds no key of the certificate's type; the certificate is "
                "not for this slot."
            ) from exc
        raise
    try:
        if keyimport.rsa_modulus_len(mech):
            public_key.verify(signature, message, padding.PKCS1v15(), hash_alg)
        else:
            public_key.verify(signature, message, ec.ECDSA(hash_alg))
    except InvalidSignature as exc:
        raise CryptnoxError(
            f"the certificate's public key does not verify a signature made by slot {slot}; "
            "refusing to import a certificate for another key."
        ) from exc


@click.command("import-cert")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option("--cert", "cert_file", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--csr",
    "csr_file",
    type=click.Path(exists=True, dir_okay=False),
    help="Refuse unless the certificate's public key is the one in this CSR (the CSR the "
    "certificate was issued from). No PIN needed.",
)
@click.option(
    "--verify-pin",
    is_flag=True,
    help="Refuse unless the slot's key signs a challenge the certificate's public key "
    "verifies. Needs the PIN; works without the CSR.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_import_cert(
    app: AppContext,
    slot: str,
    cert_file: str,
    csr_file: str | None,
    verify_pin: bool,
    default_keys: bool,
) -> None:
    """Import an X.509 certificate into the slot's PIV container (over SCP03).

    The certificate is written as given; a certificate for another key fails only
    when it is used. --csr and --verify-pin make the command check first.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    ref = _slot_ref(slot)
    if ref not in SLOT_CERT_OBJECT:
        raise click.BadParameter(f"slot {slot} has no certificate container")
    raw = Path(cert_file).read_bytes()
    cert = (
        x509.load_pem_x509_certificate(raw)
        if raw.lstrip().startswith(b"-----")
        else x509.load_der_x509_certificate(raw)
    )
    public_key = cert.public_key()
    checked: list[str] = []
    if csr_file:
        cert_spki = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if cert_spki != _csr_spki(csr_file):
            raise CryptnoxError(
                f"the certificate's public key is not the one in {csr_file}; refusing to "
                f"import a certificate that is not for the key in slot {slot}."
            )
        checked.append("csr")
    pin_secret = _verifier_value(app, PIN_INPUT) if verify_pin else None
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        if pin_secret is not None:
            _check_slot_signs_for(session, ref, public_key, pin_secret, slot)
            checked.append("signature")
        resp = _import_cert_der(
            PivAdmin(session),
            keys,
            ref,
            cert.public_bytes(serialization.Encoding.DER),
            label=slot,
        )
    info = describe_sw(resp.sw1, resp.sw2)

    def human(c: Console) -> None:
        if not resp.ok:
            c.print(f"[red]Import failed:[/red] {info.message} (SW={info.sw_hex()})")
            return
        c.print(f"[green]Certificate imported to slot {slot}.[/green]")
        if checked:
            c.print(f"  Key match checked: {', '.join(checked)}")
        else:
            c.print("  [dim]Key match not checked; --csr or --verify-pin would have.[/dim]")

    app.out.result(
        {"slot": slot, "imported": resp.ok, "sw": info.sw_hex(), "checked": checked}, human
    )
    _exit_if_refused(resp.ok)
