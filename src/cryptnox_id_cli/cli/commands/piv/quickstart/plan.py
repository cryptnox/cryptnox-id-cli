# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What quickstart plans from the card facts, and the plan itself."""

from __future__ import annotations

from dataclasses import dataclass

import click

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.transport.errors import CryptnoxError

from ..primitives import (
    _ALGORITHM_NAMES,
    _SIGNING_SLOTS,
    _key_template,
)


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


def _refuse_missing_rsa_object(
    facts: CardFacts, alg: str, ref: int, windows_rsa_shape: bool
) -> None:
    """Stop when an RSA key is asked for on a slot with no RSA key object to hold it."""
    if not alg.startswith("RSA") or windows_rsa_shape or facts.key_object_present:
        return
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


def _plan_for_profile(
    facts: CardFacts,
    ref: int,
    mech: int,
    cert_mode: str,
    include_preperso: bool,
    profile: prof_mod.PivProfile,
) -> list[PlannedStep]:
    """The plan for this card, with what the profile gives a key object it would create."""
    provided = any(k.ref == ref and k.mechanism == mech for k in profile.keys)
    _, _, new_role, _ = _key_template(ref, mech, profile)
    return _plan_quickstart(
        facts,
        QuickstartOptions(
            ref,
            mech,
            cert_mode,
            include_preperso,
            profile_provides_key_object=provided,
            new_object_can_sign=preperso_mod.key_signs(new_role, mech),
            new_object_roles=prof_mod.role_name(new_role),
            profile_name=profile.name,
        ),
    )
