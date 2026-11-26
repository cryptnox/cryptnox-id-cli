# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv quickstart``: the command, its planner and the card facts it plans from."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import inventory as inventory_mod
from cryptnox_id_cli.applets.piv import keyimport, verifier
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import csr as csr_mod
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys
from cryptnox_id_cli.state import StateDetector, counts_as_set
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError

from .primitives import (
    _ALGORITHM_NAMES,
    _SIGNING_SLOTS,
    PIN_INPUT,
    PUK_INPUT,
    SLOT_CERT_OBJECT,
    _certificate_mechanism,
    _create_key_object,
    _generate_key_on_card,
    _import_cert_der,
    _key_template,
    _read_cert_der,
    _refuse_on_fips_mode_build,
    _select,
    _set_verifier,
    _sign_with_session,
    _signing_siblings,
    _slot_ref,
    _verifier_value,
    _write_standard,
)

# Built-in profiles whose 9A is made for Windows logon: a signing key, with an RSA-2048
# object next to the ECC one. ms-logon-nfc is ms-logon for a card presented over NFC.
WINDOWS_LOGON_PROFILES = ("ms-logon", "ms-logon-nfc")


# -------------------------------------------------------------- quickstart --- #
@dataclass(frozen=True)
class QuickstartOptions:
    slot: int
    mechanism: int
    cert_mode: str  # self-signed | csr | none
    include_preperso: bool
    #: the pre-perso profile creates the (slot, mechanism) key object itself
    profile_provides_key_object: bool = True
    #: the key object quickstart would create (profile or create step) has the SIGN role
    new_object_can_sign: bool = True
    new_object_roles: str = "SIGN+AUTHENTICATE"
    profile_name: str = "cryptnox-default"


@dataclass(frozen=True)
class CardFacts:
    """What quickstart needs to know about the card before planning."""

    pin_configured: bool
    puk_configured: bool
    structure_present: bool  # the applet holds key objects or verifiers
    key_object_present: bool  # a (slot, mechanism) key object exists
    cert_present: bool
    #: None when the read failed, so a write could replace what the card holds
    chuid_present: bool | None
    ccc_present: bool | None
    #: the existing (slot, mechanism) key object can sign; None when unknown
    key_object_can_sign: bool | None = None
    #: CLI names of the slot's other key objects that can sign
    signing_siblings: tuple[str, ...] = ()
    applet_secured: bool = False
    #: algorithm of a slot certificate that is not for the requested key ("unrecognised")
    other_cert: str | None = None
    #: that certificate's key cannot sign or is not on the card, so replacing it loses nothing
    other_cert_replaceable: bool = False
    listing_withheld: bool = False


@dataclass(frozen=True)
class PlannedStep:
    step: str
    run: bool
    reason: str | None = None


def _creates_key_object(facts: CardFacts) -> bool:
    """The (slot, mechanism) key object is missing, so quickstart would create it."""
    return not facts.structure_present or not facts.key_object_present


def _key_cannot_sign(facts: CardFacts, opts: QuickstartOptions) -> bool:
    """The slot's key, existing or about to be created, is known to lack the SIGN role."""
    if _creates_key_object(facts):
        return not opts.new_object_can_sign
    return facts.key_object_can_sign is False


def _refuse_unsignable_certificate(
    facts: CardFacts, opts: QuickstartOptions, certificate_runs: bool
) -> None:
    """Stop before any write when the certificate step is bound to end in 6985."""
    if not certificate_runs or not _key_cannot_sign(facts, opts):
        return
    slot = f"{opts.slot:02X}"
    if _creates_key_object(facts):
        raise CryptnoxError(
            f"the key object quickstart would create on slot {slot} (roles from profile "
            f"'{opts.profile_name}') cannot sign, so the certificate step would fail after "
            "a permanent change to the card. Use --profile ssh or ms-logon, a SIGN-capable "
            "slot such as 9C, or --cert-mode none."
        )
    text = f"the key in slot {slot} cannot sign, so the certificate step would fail."
    if facts.signing_siblings:
        name = facts.signing_siblings[0]
        raise CryptnoxError(
            f"{text} Slot {slot} also holds a {name} key that can sign: pass --algorithm {name}."
        )
    options = ["--cert-mode none"]
    if opts.slot != pivc.KEYREF_DIGITAL_SIGNATURE:
        options.insert(0, "slot 9C")
    if not facts.applet_secured:
        options.append(
            "a signing key object for another algorithm, added with "
            f"`{CLI_NAME} piv perso create-key-object`"
        )
    raise CryptnoxError(f"{text} Use {', or '.join(options)}.")


def _refuse_other_certificate(slot: str, other: str) -> None:
    if other == "unrecognised":
        raise CryptnoxError(
            f"slot {slot} holds a certificate quickstart cannot match to a key it may "
            "replace, and the certificate step would overwrite it. Use --cert-mode none, or "
            "replace it yourself with `piv perso import-cert`."
        )
    raise CryptnoxError(
        f"slot {slot}'s certificate is for its {other} key, and quickstart's certificate step "
        f"would replace it. Pass --algorithm {other} to work on that key, or use "
        "--cert-mode none."
    )


def _plan_quickstart(facts: CardFacts, opts: QuickstartOptions) -> list[PlannedStep]:
    """Pure planner: which steps run for this card state. Raises when the card
    needs pre-personalization and the caller did not opt into it."""
    steps: list[PlannedStep] = []
    slot = f"{opts.slot:02X}"
    # A present certificate marks the slot as done: never silently replace a
    # certified key. Without a certificate the key is regenerated (nothing
    # references it yet).
    fresh_slot = not facts.cert_present
    certificate_runs = opts.cert_mode != "none" and fresh_slot
    for name, present in (("CHUID", facts.chuid_present), ("CCC", facts.ccc_present)):
        if present is None:
            raise CryptnoxError(
                f"quickstart could not read the card's {name}, so it cannot tell whether "
                f"writing one would replace it. Check `{CLI_NAME} piv objects read "
                f"--object {name.lower()}`, then re-run."
            )
    if _creates_key_object(facts) and facts.applet_secured:
        raise CryptnoxError(
            f"quickstart would add a key object to slot {slot}, but the applet is "
            "finalized (SECURED), so none can be added. Choose an algorithm the slot already "
            "has a key for."
        )
    if certificate_runs and facts.other_cert and not facts.other_cert_replaceable:
        _refuse_other_certificate(slot, facts.other_cert)
    _refuse_unsignable_certificate(facts, opts, certificate_runs)
    if not facts.structure_present:
        if not opts.include_preperso:
            raise CryptnoxError(
                "the PIV structure (containers, verifiers, key objects) is missing on "
                f"this card. Lay it down first:\n  {CLI_NAME} piv perso "
                f"load-config --profile {opts.profile_name}\nor re-run quickstart with "
                "--include-preperso."
            )
        steps.append(PlannedStep("preperso-load-config", True, "structure missing"))
        provided = opts.profile_provides_key_object
        steps.append(
            PlannedStep(
                "create-key-object",
                not provided,
                "provided by the profile" if provided else "the profile has no such object",
            )
        )
    elif not facts.key_object_present:
        # A structure can only grow: load-config over it ends in 6E27 (object exists),
        # so the missing (slot, mechanism) object is added on its own.
        if not opts.include_preperso:
            alg = _ALGORITHM_NAMES.get(opts.mechanism, "<name>")
            text = (
                f"this card has a PIV structure, but no key object for slot {slot} with this "
                f"mechanism. Add one (permanent) with\n  {CLI_NAME} piv perso create-key-object "
                f"--slot {slot} --algorithm {alg} --role {opts.new_object_roles}\nor re-run "
                "quickstart with --include-preperso, which creates it with the "
                f"role from profile '{opts.profile_name}' and leaves the rest of the structure "
                "alone."
            )
            if not opts.new_object_can_sign and opts.slot in _SIGNING_SLOTS:
                text += " That role cannot sign; for a signing key use --role SIGN+AUTHENTICATE."
            raise CryptnoxError(text)
        steps.append(PlannedStep("preperso-load-config", False, "structure present"))
        steps.append(
            PlannedStep("create-key-object", True, "no key object for this slot and mechanism")
        )
    else:
        steps.append(PlannedStep("preperso-load-config", False, "structure present"))
        steps.append(PlannedStep("create-key-object", False, "key object present"))
    steps.append(
        PlannedStep(
            "set-pin",
            not facts.pin_configured,
            None if not facts.pin_configured else "PIN already set",
        )
    )
    steps.append(
        PlannedStep(
            "set-puk",
            not facts.puk_configured,
            None if not facts.puk_configured else "PUK already set",
        )
    )
    steps.append(
        PlannedStep(
            "generate-key",
            fresh_slot,
            None if fresh_slot else "certificate present - keeping the existing key",
        )
    )
    if opts.cert_mode == "none":
        steps.append(PlannedStep("certificate", False, "--cert-mode none"))
    else:
        reason = None if fresh_slot else "already present"
        if fresh_slot and facts.other_cert:
            reason = f"replaces the slot's {facts.other_cert} certificate"
        steps.append(PlannedStep("certificate", fresh_slot, reason))
    steps.append(
        PlannedStep(
            "write-chuid",
            not facts.chuid_present,
            None if not facts.chuid_present else "already present",
        )
    )
    steps.append(
        PlannedStep(
            "write-ccc", not facts.ccc_present, None if not facts.ccc_present else "already present"
        )
    )
    if _key_cannot_sign(facts, opts):
        steps.append(PlannedStep("smoke-test", False, "the slot's key cannot sign"))
    else:
        steps.append(PlannedStep("smoke-test", True))
    return steps


def _apply_pin_truth(steps: list[PlannedStep], empty: bool) -> list[PlannedStep]:
    """Adjust a plan after the pre-flight PIN check.

    ``empty`` means the structure was laid down (e.g. a manual pre-personalization)
    but personalization never happened: the set-pin skip was a false positive, and
    the PUK, created by the same structure, is assumed valueless too, so both
    flips run. Setting them loses nothing: there is no value to preserve. Otherwise
    the PIN matched, and the skip reason says it was actually verified.
    """
    if not empty:
        return [
            PlannedStep(s.step, s.run, "PIN already set (verified)")
            if s.step == "set-pin" and not s.run
            else s
            for s in steps
        ]
    out: list[PlannedStep] = []
    for s in steps:
        if s.step == "set-pin" and not s.run:
            out.append(PlannedStep("set-pin", True, "verifier exists but holds no value"))
        elif s.step == "set-puk" and not s.run:
            out.append(PlannedStep("set-puk", True, "verifier assumed valueless, like the PIN"))
        else:
            out.append(s)
    return out


def _collect_quickstart_facts(session, ref: int, mech: int) -> tuple[CardFacts, str]:
    """Read-only detection pass: lifecycle state, verifier status, object presence,
    and the applet's own key-object listing (the non-destructive (slot, mechanism)
    probe stands in when the listing is withheld)."""
    st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
    note = verifier.refused_note(st.piv_pin, st.piv_puk)
    if note is None and st.piv_apt is not None:
        note = verifier.unread_note(st.piv_pin, st.piv_puk)
    if note:
        raise CryptnoxError(f"quickstart cannot tell whether the PIN and PUK are set: {note}")
    piv = _select(session)
    key_objects = None
    verifiers = None
    with contextlib.suppress(CryptnoxError):
        key_objects = inventory_mod.read_keys(piv)
        verifiers = inventory_mod.read_verifiers(piv)
    pin_configured = counts_as_set(st.piv_pin)
    puk_configured = counts_as_set(st.piv_puk)
    key_object_can_sign: bool | None = None
    signing_siblings: tuple[str, ...] = ()
    if key_objects is None:
        probe = session.transmit(keyimport.probe_apdu(ref, mech), context="probe quickstart")
        key_object_present = probe.sw != 0x6A86
        structure_present = key_object_present or pin_configured or puk_configured
    else:
        match = next((k for k in key_objects if k.ref == ref and k.mechanism == mech), None)
        key_object_present = match is not None
        if match is not None:
            key_object_can_sign = preperso_mod.key_signs(match.role, match.mechanism)
        signing_siblings = tuple(_signing_siblings(key_objects, ref, mech))
        structure_present = bool(key_objects) or bool(verifiers)
    # "Certificate present" means a PARSEABLE certificate: a created-but-unused
    # container is zero-length per SP 800-73 4.1.1, and factory containers can
    # hold non-certificate placeholder data - neither should stop quickstart
    # from provisioning the slot.
    obj_name = SLOT_CERT_OBJECT.get(ref)
    cert_der = _read_cert_der(piv, obj_name) if obj_name is not None else None
    cert_present = False
    other_cert: str | None = None
    other_cert_replaceable = False
    if cert_der is not None:
        cert_mech = _certificate_mechanism(cert_der)
        if cert_mech == mech and key_object_present:
            cert_present = True
        else:
            other_cert = "unrecognised"
            if cert_mech is not None:
                other_cert = _ALGORITHM_NAMES.get(cert_mech, other_cert)
            if cert_mech == mech:  # its key is not on the card
                other_cert_replaceable = True
            elif cert_mech is not None and key_objects is not None:
                cert_key = next(
                    (k for k in key_objects if k.ref == ref and k.mechanism == cert_mech), None
                )
                other_cert_replaceable = cert_key is None or not preperso_mod.key_signs(
                    cert_key.role, cert_key.mechanism
                )
    objs = st.piv_objects or {}
    facts = CardFacts(
        pin_configured=pin_configured,
        puk_configured=puk_configured,
        structure_present=structure_present,
        key_object_present=key_object_present,
        cert_present=cert_present,
        chuid_present=objs.get("chuid"),
        ccc_present=objs.get("ccc"),
        key_object_can_sign=key_object_can_sign,
        signing_siblings=signing_siblings,
        applet_secured=bool(st.piv_secured),
        other_cert=other_cert,
        other_cert_replaceable=other_cert_replaceable,
        listing_withheld=key_objects is None,
    )
    return facts, st.piv.label


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
    import datetime
    import hashlib
    import os
    import secrets as pysecrets
    import sys

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    ref = _slot_ref(slot)
    # ms-logon on 9A is the Windows shape, and the only built-in profile that gives a slot
    # an RSA key object. It matters because the Windows inbox minidriver does not enumerate
    # EC keys at all (confirmed 2026-08-14, reproduced on a YubiKey, so a Windows limit
    # rather than ours) -- an ECC 9A is unusable for the very purpose ms-logon is chosen for.
    # ms-logon-nfc is the same shape, opened to the contactless interface.
    windows_rsa_shape = profile_name in WINDOWS_LOGON_PROFILES and ref == pivc.KEYREF_PIV_AUTH

    algorithm_defaulted = (
        click.get_current_context().get_parameter_source("algorithm")
        == click.core.ParameterSource.DEFAULT
    )
    if windows_rsa_shape and algorithm_defaulted:
        # The one shape whose whole purpose is Windows, and an ECC 9A cannot log on there.
        algorithm = "RSA2048"
        app.out.note(
            f"profile {profile_name} on slot 9A: defaulting to RSA2048, which Windows needs "
            "(the inbox minidriver does not enumerate EC keys); pass --algorithm to override."
        )

    alg = algorithm.upper()

    mech = perso_mod.ALGORITHMS.get(alg)
    if mech is None or mech not in pivc.SUPPORTED_ALGORITHMS:
        raise click.BadParameter(f"algorithm {algorithm!r} not supported by this applet")
    keyimport.validate_slot_mechanism(ref, mech)
    profile = prof_mod.builtin(profile_name)  # validates the name early (exit 8 on typo)
    if cert_mode != "none" and ref not in (
        pivc.KEYREF_PIV_AUTH,
        pivc.KEYREF_DIGITAL_SIGNATURE,
    ):
        raise click.BadParameter(
            "certificate modes sign on-card and need a SIGN-capable slot: 9C always; "
            "9A only on cards pre-personalized with a SIGN-capable 9A (the ms-logon "
            "profile) - a default-profile 9A fails the certificate step with 6985.",
            param_hint="--slot",
        )
    if cert_mode == "csr" and not csr_out:
        raise click.BadParameter("--cert-mode csr requires --csr-out", param_hint="--csr-out")
    if cert_out and cert_mode != "self-signed":
        raise click.BadParameter(
            "--cert-out applies to --cert-mode self-signed", param_hint="--cert-out"
        )

    with app.open_session() as session:
        facts, state_before = _collect_quickstart_facts(session, ref, mech)
        if alg.startswith("RSA") and not windows_rsa_shape and not facts.key_object_present:
            missing = f"this card has no {alg} key object on slot {ref:02X}"
            if facts.applet_secured:
                advice = (
                    ", and the applet is finalized (SECURED), so none can be added. Choose an "
                    "algorithm the slot already has a key for."
                )
            elif not facts.structure_present:
                advice = (
                    " and no PIV structure yet. Use `--profile ms-logon --slot 9A "
                    "--include-preperso`, whose profile creates an RSA2048 object on 9A, or lay "
                    "down a structure first with `piv perso load-config`."
                )
            else:
                advice = (
                    ", and among the built-in profiles only ms-logon's 9A creates one. Use "
                    f"`--profile ms-logon --slot 9A`, add the object with `{CLI_NAME} piv perso "
                    "create-key-object`, or import an off-card key with `piv perso import-key`."
                )
            raise click.BadParameter(missing + advice, param_hint="--algorithm")
        provided = any(k.ref == ref and k.mechanism == mech for k in profile.keys)
        _, _, new_role, new_attrs = _key_template(ref, mech, profile)
        new_object_can_sign = preperso_mod.key_signs(new_role, mech)
        steps = _plan_quickstart(
            facts,
            QuickstartOptions(
                ref,
                mech,
                cert_mode,
                include_preperso,
                profile_provides_key_object=provided,
                new_object_can_sign=new_object_can_sign,
                new_object_roles=prof_mod.role_name(new_role),
                profile_name=profile.name,
            ),
        )
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
        if steps[1].run and not new_object_can_sign:
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

        if dry_run or app.dry_run:
            planned = [
                {"step": s.step, "status": "would-run" if s.run else "skip", "reason": s.reason}
                for s in steps
            ]

            def human_dry(c: Console) -> None:
                c.print(f"[bold]DRY RUN[/bold] - card state: {state_before}")
                table = app.out.table("Step", "Plan", "Reason")
                for p in planned:
                    mark = (
                        "[cyan]would run[/cyan]"
                        if p["status"] == "would-run"
                        else "[dim]skip[/dim]"
                    )
                    table.add_row(str(p["step"]), mark, str(p["reason"] or ""))
                c.print(table)
                c.print("\n  [dim]Nothing was sent to the card.[/dim]")

            app.out.result(
                {
                    "quickstart": True,
                    "dry_run": True,
                    "state_before": state_before,
                    "steps": planned,
                },
                human_dry,
            )
            return

        # The probe cannot tell a set PIN from a valueless one; a VERIFY settles the plan.
        keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
        run_set = {s.step for s in steps if s.run}
        pin_secret = _verifier_value(app, PIN_INPUT.new if "set-pin" in run_set else PIN_INPUT)
        if "set-pin" not in run_set:
            outcome = verifier.verify(_select(session), pin_secret)
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
            steps = _apply_pin_truth(steps, empty)
            run_set = {s.step for s in steps if s.run}

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

        puk_secret = _verifier_value(app, PUK_INPUT.new) if "set-puk" in run_set else None

        adm = PivAdmin(session)
        executed: list[dict[str, object]] = []
        outputs: dict[str, str | None] = {"public_key": None, "certificate": None, "csr": None}
        spki: bytes | None = None
        failed = False

        def record(step: str, status: str, **extra: object) -> None:
            executed.append({"step": step, "status": status, **extra})

        for planned_step in steps:
            if not planned_step.run:
                record(planned_step.step, "skipped", reason=planned_step.reason)
                continue
            try:
                if planned_step.step == "preperso-load-config":
                    for label, op in profile.build_ops():
                        adm.select()
                        adm.open(keys)
                        resp = adm.send(
                            preperso_mod.put_data_admin_apdu(preperso_mod.build_bulk([op])),
                            context=f"PUT DATA ADMIN [{label}]",
                        )
                        if not resp.ok:
                            raise StatusWordError(resp.sw1, resp.sw2, context=f"preperso [{label}]")
                    record(planned_step.step, "ok", detail={"profile": profile.name})
                elif planned_step.step == "set-pin":
                    padded = verifier.pad(pin_secret)
                    app.redactor.register(padded)
                    resp = _set_verifier(adm, keys, pivc.REF_PIV_PIN, padded, label="PIN")
                    if not resp.ok:
                        raise StatusWordError(resp.sw1, resp.sw2, context="SET PIN")
                    record(planned_step.step, "ok", sw=resp.sw_hex())
                elif planned_step.step == "set-puk":
                    if puk_secret is None:  # unreachable: planner gates set-puk on a resolved PUK
                        raise RuntimeError("set-puk planned without a PUK value")
                    padded = verifier.pad(puk_secret)
                    app.redactor.register(padded)
                    resp = _set_verifier(adm, keys, pivc.REF_PUK, padded, label="PUK")
                    if not resp.ok:
                        raise StatusWordError(resp.sw1, resp.sw2, context="SET PUK")
                    record(planned_step.step, "ok", sw=resp.sw_hex())
                elif planned_step.step == "create-key-object":
                    _create_key_object(
                        app,
                        adm,
                        keys,
                        ref,
                        mech,
                        bool(new_attrs & preperso_mod.ATTR_RSA_CRT),
                        slot,
                        profile=profile,
                        confirmed=True,
                    )
                    record(planned_step.step, "ok", detail={"slot": slot, "algorithm": alg})
                elif planned_step.step == "generate-key":
                    generated = _generate_key_on_card(
                        app, adm, keys, ref, mech, label=slot, default_keys=default_keys
                    )
                    public_key = generated.public_key
                    spki = public_key.public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    fingerprint = hashlib.sha256(spki).hexdigest().upper()
                    if public_out:
                        Path(public_out).write_bytes(perso_mod.public_key_pem(public_key))
                        outputs["public_key"] = public_out
                    record(
                        planned_step.step,
                        "ok",
                        detail={
                            "algorithm": alg,
                            "public_key_sha256": fingerprint,
                            "generate_path": generated.path,
                            "management_key_auth": generated.management_key_auth,
                        },
                    )
                elif planned_step.step == "certificate":
                    if spki is None:  # unreachable: generate-key runs whenever certificate runs
                        raise RuntimeError("certificate step planned without a generated key")
                    spki_bytes = spki
                    if cert_mode == "csr":
                        pem = _sign_with_session(
                            session,
                            ref,
                            mech,
                            pin_secret,
                            lambda s, _spki=spki_bytes: csr_mod.build_csr(subject, _spki, mech, s),
                        )
                        if csr_out is None:  # unreachable: csr mode validates --csr-out at parse
                            raise RuntimeError("csr mode without --csr-out")
                        Path(csr_out).write_bytes(pem)
                        outputs["csr"] = csr_out
                        record(
                            planned_step.step,
                            "ok",
                            detail={
                                "mode": "csr",
                                "note": "re-running quickstart regenerates the key and "
                                "invalidates this CSR",
                            },
                        )
                    else:
                        serial = int.from_bytes(pysecrets.token_bytes(8), "big") | 1
                        not_before = datetime.datetime.now(datetime.timezone.utc).replace(
                            microsecond=0
                        )
                        not_after = not_before + datetime.timedelta(days=days)

                        def _build_self_signed(
                            s,
                            _spki=spki_bytes,
                            _serial=serial,
                            _nb=not_before.isoformat(),
                            _na=not_after.isoformat(),
                        ):
                            return csr_mod.build_self_signed(
                                subject,
                                _spki,
                                mech,
                                s,
                                serial=_serial,
                                not_before=_nb,
                                not_after=_na,
                            )

                        pem = _sign_with_session(session, ref, mech, pin_secret, _build_self_signed)
                        cert_der = x509.load_pem_x509_certificate(pem).public_bytes(
                            serialization.Encoding.DER
                        )
                        resp = _import_cert_der(adm, keys, ref, cert_der, label=slot)
                        if not resp.ok:
                            raise StatusWordError(resp.sw1, resp.sw2, context="IMPORT cert")
                        if cert_out:
                            Path(cert_out).write_bytes(pem)
                            outputs["certificate"] = cert_out
                        record(
                            planned_step.step,
                            "ok",
                            detail={"mode": "self-signed", "subject": subject, "days": days},
                        )
                elif planned_step.step in ("write-chuid", "write-ccc"):
                    name = "chuid" if planned_step.step == "write-chuid" else "ccc"
                    results = _write_standard(adm, keys, (name,))
                    if not results[0]["ok"]:
                        raise StatusWordError(
                            int(str(results[0]["sw"])[:2], 16),
                            int(str(results[0]["sw"])[2:], 16),
                            context=f"PUT DATA {name}",
                        )
                    record(planned_step.step, "ok", sw=results[0]["sw"])
                elif planned_step.step == "smoke-test":
                    digest = os.urandom(keyimport.digest_for_mechanism(mech).digest_size)
                    try:
                        signature = _sign_with_session(
                            session, ref, mech, pin_secret, lambda s, _d=digest: s(_d)
                        )
                    except StatusWordError as exc:
                        if exc.info.sw_hex() == "6985":
                            raise CryptnoxError(
                                f"slot {slot} refused to sign (SW=6985): its key cannot sign "
                                "on this applet, so no signature was made. For a signing key, "
                                "use slot 9C or a key object for another algorithm that can "
                                f"sign; `{CLI_NAME} piv inventory` lists each key's role."
                            ) from exc
                        raise
                    record(planned_step.step, "ok", detail={"signature_len": len(signature)})
            except CryptnoxError as exc:
                record(planned_step.step, "failed", reason=str(exc))
                failed = True
                break

        if public_out and outputs["public_key"] is None and not failed:
            cert_name = SLOT_CERT_OBJECT.get(ref)
            kept_der = _read_cert_der(_select(session), cert_name) if cert_name else None
            if kept_der is not None:
                public_key = x509.load_der_x509_certificate(kept_der).public_key()
                Path(public_out).write_bytes(perso_mod.public_key_pem(public_key))
                outputs["public_key"] = public_out

        try:
            _, state_after = _collect_quickstart_facts(session, ref, mech)
        except CryptnoxError:
            state_after = "unknown"

    reader = app.resolved_reader or "<your contact reader>"
    slot_lc = slot.lower()
    next_cmds = [
        f'yubico-piv-tool -r "{reader}" -a status',
        f'yubico-piv-tool -r "{reader}" -a read-certificate -s {slot_lc} -o {slot_lc}.crt.pem',
        f'yubico-piv-tool -r "{reader}" -a verify-pin',
    ]
    payload = {
        "quickstart": True,
        "dry_run": False,
        "slot": slot,
        "algorithm": alg,
        "cert_mode": cert_mode,
        "preperso_profile": profile.name,
        "state_before": state_before,
        "steps": executed,
        "state_after": state_after,
        "outputs": outputs,
        "next": next_cmds if not failed else [],
    }

    def human(c: Console) -> None:
        table = app.out.table("Step", "Result", "Note")
        for e in executed:
            mark = {
                "ok": "[green]ok[/green]",
                "skipped": "[dim]skipped[/dim]",
                "failed": "[red]failed[/red]",
            }[str(e["status"])]
            note = e.get("reason") or e.get("sw") or ""
            detail = e.get("detail")
            if isinstance(detail, dict) and detail.get("note"):
                note = detail["note"]
            table.add_row(str(e["step"]), mark, str(note))
        c.print(table)
        c.print(f"\n  Card state: {state_before} -> {state_after}")
        if failed:
            c.print(
                "[red]quickstart stopped at the first failure[/red]; completed steps are "
                "kept - fix the cause and re-run (it skips what is already done)."
            )
            return
        c.print("\n[bold]Verify with standard PIV tooling:[/bold]")
        for cmd_line in next_cmds:
            c.print(f"  {cmd_line}")
        c.print(
            "[dim]Yubico-proprietary actions (version, attest, set-mgm-key, and writes via "
            "yubico-piv-tool) do not apply: this card administers over SCP03 via "
            f"{CLI_NAME}.[/dim]"
        )

    app.out.result(payload, human)
    if failed:
        sys.exit(6)
