# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Card primitives and option helpers that several ``piv`` command modules share."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

import click
from rich.markup import escape

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import inventory as inventory_mod
from cryptnox_id_cli.applets.piv import keyimport, mgmt_auth, verifier
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.applets.piv.objects import (
    extract_certificate,
    object_by_name,
    wrap_certificate,
)
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import piv_objects
from cryptnox_id_cli.secrets.resolver import MGMT_KEY_ENV, resolve_mgmt_key, resolve_secret
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError, describe_sw
from cryptnox_id_cli.transport.pcsc import CardSession, is_contactless_interface

# Slots that carry a certificate container, and the object that holds it.
SLOT_CERT_OBJECT = {
    0x9A: "auth-cert",
    0x9C: "sign-cert",
    0x9D: "keymgmt-cert",
    0x9E: "card-auth-cert",
}


def _slot_ref(slot: str) -> int:
    try:
        return int(slot, 16)
    except ValueError:
        raise click.BadParameter(
            f"{slot!r} is not a hex key reference such as 9A", param_hint="--slot"
        ) from None


def _select(session: object) -> PivApplet:
    piv = PivApplet(session)  # type: ignore[arg-type]
    piv.select()
    return piv


_VERDICT_STYLE = {
    verifier.Verdict.NOT_CONFIGURED: "dim",
    verifier.Verdict.BLOCKED: "red",
    verifier.Verdict.REFUSED_ON_INTERFACE: "yellow",
    verifier.Verdict.NO_TRIES_ON_INTERFACE: "yellow",
    verifier.Verdict.OTHER: "yellow",
}


def _styled_status(outcome: verifier.Outcome, default: str | None = None) -> str:
    """The outcome's status text as console markup, in its verdict's style."""
    style = _VERDICT_STYLE.get(outcome.verdict, default)
    text = escape(outcome.status_text)
    return f"[{style}]{text}[/{style}]" if style else text


def _read_cert_der(piv: PivApplet, obj_name: str) -> bytes | None:
    obj = object_by_name(obj_name)
    if obj is None:
        return None
    val = piv.read_object(obj.oid)
    return extract_certificate(val) if val is not None else None


def _csr_spki(path: str) -> bytes:
    """SubjectPublicKeyInfo (DER) of the public key in a PEM or DER CSR."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    raw = Path(path).read_bytes()
    try:
        req = x509.load_pem_x509_csr(raw)
    except ValueError:
        req = x509.load_der_x509_csr(raw)
    return req.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _refuse_on_fips_mode_build(session: CardSession, profile: prof_mod.PivProfile) -> None:
    """Stop a profile for the build with FIPS mode off before it reaches the other build.

    The FIPS-mode build would refuse the PIN verifier part-way through, after the
    containers were created, and what was created cannot be removed. The applet
    reports its build without authentication, so the question is asked first. A
    card that does not answer is left to the applet's own judgement.
    """
    piv = PivApplet(session)
    try:
        piv.select()
        status = inventory_mod.read_status(piv)
    except CryptnoxError:
        return
    if status is not None and status.fips_mode:
        raise prof_mod.ProfileError(
            f"profile '{profile.name}' is written for the PIV applet build with FIPS mode off "
            "(fips_mode: false), and this card carries the FIPS-mode build, which refuses "
            "it. `remote reset --fips-off` installs the other build; it wipes the PIV "
            "function. Nothing was written."
        )


def _exit_if_refused(ok: bool) -> None:
    """End with the status-word exit code when the card refused the command.

    Called after the result is printed: that payload carries the status word and,
    for a PIN or PUK, the retries left, which the error object would not. A script
    that only looks at the exit code must not take a refused PIN for a verified one.
    """
    if not ok:
        sys.exit(6)


@dataclass(frozen=True)
class _SecretInput:
    """Where a PIN or PUK value comes from, and what a refusal calls it."""

    env_var: str
    prompt_label: str
    what: str
    new_env_var: str | None = None

    @property
    def current(self) -> _SecretInput:
        return _SecretInput(
            self.env_var, f"Current {self.prompt_label}", f"current {self.what}", self.new_env_var
        )

    @property
    def new(self) -> _SecretInput:
        if self.new_env_var is None:
            raise ValueError(f"no environment variable carries a new {self.what}")
        return _SecretInput(self.new_env_var, f"New {self.prompt_label}", f"new {self.what}")


PIN_INPUT = _SecretInput("CRYPTNOX_PIV_PIN", "PIV PIN", "PIN", "CRYPTNOX_PIV_NEW_PIN")


PUK_INPUT = _SecretInput("CRYPTNOX_PIV_PUK", "PIV PUK", "PUK", "CRYPTNOX_PIV_NEW_PUK")


def _verifier_value(app: AppContext, source: _SecretInput, provided: str | None = None) -> bytes:
    """A PIN or PUK from the option, environment or prompt, refused here when it cannot fit."""
    secret = resolve_secret(
        redactor=app.redactor,
        env_var=source.env_var,
        prompt_label=source.prompt_label,
        provided=provided,
    )
    verifier.check_length(secret, source.what)
    return secret


# ------------------------------------------------- session-level helpers --- #
# Each opens a FRESH SCP03 session (JCOP 4.5 allows one application APDU per
# applet-directed secure-channel session) and performs one perso primitive.
def _set_verifier(adm: PivAdmin, keys, ref: int, padded: bytes, *, label: str):
    adm.select()
    adm.open(keys)
    return adm.send(perso_mod.set_verifier_value_apdu(ref, padded), context=f"SET {label}")


class GeneratedKey(NamedTuple):
    """An on-card generated public key and the path that produced it."""

    #: An RSA or EC public key from ``cryptography``; untyped like every other
    #: public-key value in this module (the two classes share no protocol).
    public_key: Any
    #: ``admin-channel`` or ``management-key``.
    path: str
    #: ``{"mechanism": "AES-256", "source": "$PIV_MGMT_KEY"}`` on the management-key
    #: path, ``None`` on the admin channel.
    management_key_auth: dict[str, object] | None


def _parse_generated(mech: int, data: bytes, *, label: str, path: str):
    """Parse a GENERATE response, turning a malformed template into a CLI error."""
    try:
        return perso_mod.parse_public_key(mech, data)
    except ValueError as exc:
        raise CryptnoxError(
            f"GENERATE key {label}: the card returned a public-key template this CLI "
            f"cannot parse ({len(data)} bytes over the {path} path, SW=9000): {exc}. "
            "Re-run with --verbose to capture the exchange."
        ) from exc


def _generate_key_on_card(
    app: AppContext,
    adm: PivAdmin,
    keys,
    ref: int,
    mech: int,
    *,
    label: str,
    default_keys: bool = False,
) -> GeneratedKey:
    """Generate a key pair on the card and return its public half.

    The admin channel is tried first and is the whole story on a card that can return
    the full public-key template through it. A card that cannot says so in its own
    response - success, but only as many bytes as were asked for, with the template's
    own header declaring more - and only then does the generation repeat over plain
    APDUs behind a PIV management key authentication.
    """
    adm.select()
    adm.open(keys)
    resp = adm.send(perso_mod.generate_keypair_apdu(ref, mech), context=f"GENERATE {label}")
    if resp.sw == 0x6F00 and keyimport.rsa_modulus_len(mech):
        raise CryptnoxError(f"GENERATE key {label} failed (SW=6F00): {_IMPORT_SW_HINTS[0x6F00]}.")
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context=f"GENERATE key {label}")
    if perso_mod.generate_response_truncated(mech, resp):
        return _generate_via_mgmt_key(
            app,
            adm,
            ref,
            mech,
            label=label,
            default_keys=default_keys,
            received=len(resp.data),
            declared=perso_mod.declared_template_bytes(resp.data),
        )
    return GeneratedKey(
        _parse_generated(mech, resp.data, label=label, path="admin-channel"),
        "admin-channel",
        None,
    )


def _atr_or_none(session) -> bytes | None:
    """The session's ATR when the transport can supply one (diagnostic use only)."""
    try:
        return session.atr
    except Exception:  # noqa: BLE001 - a missing ATR only costs a less precise message
        return None


def _generate_via_mgmt_key(
    app: AppContext,
    adm: PivAdmin,
    ref: int,
    mech: int,
    *,
    label: str,
    default_keys: bool,
    received: int,
    declared: int | None,
) -> GeneratedKey:
    """Repeat the generation over plain APDUs, authenticating the management key first.

    The card generated and stored a key pair on the truncated attempt already - the
    applet builds the response only after generating - so that first key is gone
    whatever happens here, and RSA generation runs twice on such a card.
    """
    declared_text = f"{declared}" if declared is not None else "more"
    app.out.warn(
        f"the admin channel returned {received} of {declared_text} bytes of the public-key "
        "template; completing the generation with the PIV management key (9B) over plain "
        f"APDUs. The first attempt already replaced the key in slot {label}; the key that "
        "remains is the one generated now."
    )
    material = resolve_mgmt_key(
        app.redactor,
        default_keys=default_keys,
        missing_message=(
            f"The card returned {received} of {declared_text} bytes of the public-key "
            "template over the admin channel, so this command must authenticate the PIV "
            "management key (slot 9B) and repeat the generation over plain APDUs. Set "
            f"${MGMT_KEY_ENV} (hex: 32, 48 or 64 characters for AES-128/192/256), or pass "
            "--default-keys if this card still holds the published development value."
        ),
    )
    # A re-SELECT resets the card's secure channel, which is exactly the state the plain
    # phase wants; the key-holder role granted afterwards survives every later command.
    adm.select()
    adm.forget_channel()
    contactless = is_contactless_interface(adm.card.reader_name, _atr_or_none(adm.card))
    auth = mgmt_auth.authenticate(adm.card.transmit, material, contactless=contactless)
    app.out.detail(
        f"PIV management key 9B: {mgmt_auth.mechanism_name(auth.mechanism)}, mutual "
        f"authentication, card verified (value from {auth.source})."
    )

    context = f"GENERATE {label} (management-key path)"
    resp = adm.card.transmit(perso_mod.generate_keypair_apdu(ref, mech), context=context)
    if resp.sw == 0x6F00 and keyimport.rsa_modulus_len(mech):
        raise CryptnoxError(f"GENERATE key {label} failed (SW=6F00): {_IMPORT_SW_HINTS[0x6F00]}.")
    if resp.sw == 0x6982:
        raise StatusWordError(
            resp.sw1,
            resp.sw2,
            context=(
                f"GENERATE key {label} (management-key path; 9B authenticated, so slot "
                f"{label}'s key object is bound to a different admin key than 9B)"
            ),
        )
    if not resp.ok:
        raise StatusWordError(
            resp.sw1, resp.sw2, context=f"GENERATE key {label} (management-key path)"
        )
    if perso_mod.generate_response_truncated(mech, resp):
        raise CryptnoxError(
            f"GENERATE key {label}: the card truncated the response on the plain path as "
            f"well ({len(resp.data)} bytes); this CLI has no further fallback."
        )
    info: dict[str, object] = {
        "mechanism": mgmt_auth.mechanism_name(auth.mechanism),
        "source": auth.source,
    }
    return GeneratedKey(
        _parse_generated(mech, resp.data, label=label, path="management-key"),
        "management-key",
        info,
    )


def _import_cert_der(adm: PivAdmin, keys, ref: int, cert_der: bytes, *, label: str):
    obj = object_by_name(SLOT_CERT_OBJECT[ref])
    if obj is None:  # unreachable: SLOT_CERT_OBJECT values are built-in object names
        raise RuntimeError(f"unknown PIV object for slot {ref:02X}")
    adm.select()
    adm.open(keys)
    return adm.send_chained(
        perso_mod.INS_PUT_DATA,
        0x3F,
        0xFF,
        perso_mod.put_data_body(obj.oid, wrap_certificate(cert_der)),
        context=f"PUT DATA cert {label}",
    )


def _write_standard(adm: PivAdmin, keys, names: tuple[str, ...]) -> list[dict[str, object]]:
    generators: dict[str, Callable[[], bytes]] = {
        "chuid": piv_objects.generate_chuid,
        "ccc": piv_objects.generate_ccc,
    }
    results: list[dict[str, object]] = []
    for name in names:
        obj = object_by_name(name)
        if obj is None:  # unreachable: callers pass built-in object names
            raise RuntimeError(f"unknown PIV object {name!r}")
        adm.select()
        adm.open(keys)
        resp = adm.send(
            perso_mod.put_data_apdu(obj.oid, generators[name]()), context=f"PUT DATA {name}"
        )
        results.append(
            {"object": name, "ok": resp.ok, "sw": describe_sw(resp.sw1, resp.sw2).sw_hex()}
        )
    return results


def _sign_with_session(session, ref: int, mech: int, pin: bytes, build):
    """Verify the PIN and run ``build(signer)`` against an already-open session."""
    verifier.require_pin(_select(session), pin)

    def signer(digest: bytes) -> bytes:
        k = keyimport.rsa_modulus_len(mech)
        challenge = keyimport.emsa_pkcs1_v15(digest, k) if k else digest
        apdu = perso_mod.general_authenticate_sign_apdu(ref, mech, challenge)
        if len(apdu.data) > 0xFF:  # oversized body: plain-channel ISO chaining
            resp = session.transmit_chained(apdu, context="GENERAL AUTHENTICATE (sign)")
        else:
            resp = session.transmit(apdu, context="GENERAL AUTHENTICATE (sign)")
        if not resp.ok:
            refused = resp.sw in (0x6983, 0x6985, 0x6A86)
            hint = _sign_refusal(session, ref, mech, resp.sw) if refused else None
            raise StatusWordError(
                resp.sw1, resp.sw2, context="GENERAL AUTHENTICATE (sign)", hint=hint
            )
        return perso_mod.parse_sign_response(resp.data)

    return build(signer)


# Tried in order when suggesting a second key object for a slot that cannot sign.
_SIGN_ALTERNATIVES = ("RSA2048", "ECCP384", "ECCP256")


_ALGORITHM_NAMES = {mech: name for name, mech in perso_mod.ALGORITHMS.items()}


_SIGNING_SLOTS = (pivc.KEYREF_PIV_AUTH, pivc.KEYREF_DIGITAL_SIGNATURE)


_FINALIZED_NO_NEW_KEYS = (
    "the applet is finalized (SECURED): key objects can no longer be created. "
    "Import into an existing object. A full reset of the PIV applet runs through the "
    f"Cryptnox remote PIV service: `{CLI_NAME} remote reset`."
)


def _signing_siblings(listing, ref: int, mech: int) -> list[str]:  # noqa: ANN001
    """CLI names of the slot's other asymmetric key objects that can sign."""
    return [
        _ALGORITHM_NAMES[k.mechanism]
        for k in listing
        if k.ref == ref
        and k.mechanism != mech
        and k.mechanism in _ALGORITHM_NAMES
        and preperso_mod.key_signs(k.role, k.mechanism)
    ]


def _sign_refusal(session, ref: int, mech: int, sw: int) -> str | None:  # noqa: ANN001
    """Why a slot refused to sign, from the applet's keyless status and key listing."""
    slot = f"{ref:02X}"
    alg = _ALGORITHM_NAMES.get(mech, hex(mech))
    piv = PivApplet(session)
    try:
        listing = inventory_mod.read_keys(piv)
        status = inventory_mod.read_status(piv)
    except CryptnoxError:
        listing, status = None, None
    obj = next((k for k in listing or [] if k.ref == ref and k.mechanism == mech), None)
    # The applet reports an empty key (6983) before it checks the role.
    if sw == 0x6983 and (obj is None or preperso_mod.key_signs(obj.role, obj.mechanism)):
        return (
            f"the {alg} key object in slot {slot} holds no key yet. Generate one with "
            f"`{CLI_NAME} piv perso generate-key --slot {slot} --algorithm {alg}` or import one."
        )
    if listing is None:
        if sw == 0x6A86:
            return (
                f"slot {slot} has no {alg} key that can sign. "
                "The usual cause is an --algorithm the slot has no key for; this card withholds "
                "its key listing, so the slot's keys cannot be read."
            )
        text = (
            f"slot {slot} refused to sign. The usual cause is a key whose role does not "
            "include SIGN; this card withholds its key listing, so the role cannot be read."
        )
        if ref != pivc.KEYREF_DIGITAL_SIGNATURE:
            text += " Slot 9C signs on every built-in profile."
        return text
    if obj is None and sw == 0x6A86:
        text = f"slot {slot} has no {alg} key object."
        siblings = _signing_siblings(listing, ref, mech)
        if siblings:
            text += (
                f" Its {siblings[0]} key can sign: pass --algorithm {siblings[0]}, and that "
                "key's public key where the command takes one."
            )
        return text
    if obj is None or preperso_mod.key_signs(obj.role, obj.mechanism):
        return None
    roles = "+".join(inventory_mod.role_names(obj.role)) or "none"
    text = (
        f"the {obj.mechanism_name} key in slot {slot} has the role {roles}, which cannot "
        "sign, and a key's role cannot be changed."
    )
    siblings = _signing_siblings(listing, ref, mech)
    if siblings:
        name = siblings[0]
        return (
            f"{text} Slot {slot} also holds a {name} key that can sign: pass --algorithm "
            f"{name}, and that key's public key where the command takes one."
        )
    taken = {k.mechanism for k in listing if k.ref == ref}
    free = next((a for a in _SIGN_ALTERNATIVES if perso_mod.ALGORITHMS[a] not in taken), None)
    options = [] if ref == pivc.KEYREF_DIGITAL_SIGNATURE else ["sign with slot 9C"]
    if free and not (status is not None and status.secured):
        options.append(
            "add a signing key object for another algorithm on this slot (permanent): "
            f"`{CLI_NAME} piv perso create-key-object --slot {slot} --algorithm {free} "
            f"--role SIGN+AUTHENTICATE`, then generate the key and certificate with "
            f"--algorithm {free}"
        )
    if len(options) == 2:
        text += f" Either {options[0]}, or {options[1]}."
    elif options:
        text += f" {options[0][0].upper()}{options[0][1:]}."
    return text


# Friendly diagnoses for CHANGE REFERENCE DATA ADMIN rejections during key import.
_IMPORT_SW_HINTS = {
    0x6A88: (
        "no key object with this (slot, mechanism) pair exists - the cryptnox-default "
        "profile creates ECC-P256 objects only; re-run pre-perso with a profile that "
        "defines it, or pass --create-key-object on a non-finalized card"
    ),
    0x6982: "the key object is not IMPORTABLE (or the admin channel is not accepted)",
    0x6A80: (
        "the card rejected this element - for RSA this usually means the key object's "
        "CRT attribute does not match; try the other --rsa-form"
    ),
    0x6700: "element too long for the transport (chaining should have engaged - report this)",
    0x6F00: (
        "the chip refuses this key size - its pre-issuance maximum-RSA configuration "
        "(DF2B) caps RSA below it, and that is factory-set before the card is secured"
    ),
}


def _key_template(
    ref: int, mech: int, profile: prof_mod.PivProfile | None = None
) -> tuple[int, int, int, int]:
    """(contact, contactless, role, attributes) for a new key object on ``ref``: the
    profile's entry for the slot, else cryptnox-default's, else a role by slot type."""
    for source in (profile, prof_mod.builtin("cryptnox-default")):
        on_slot = [k for k in source.keys if k.ref == ref] if source else []
        if on_slot:
            rsa = mech in perso_mod.RSA_MECHANISMS
            k = next((k for k in on_slot if k.mechanism == mech), None) or next(
                (k for k in on_slot if (k.mechanism in perso_mod.RSA_MECHANISMS) == rsa),
                on_slot[0],
            )
            return k.contact, k.contactless, k.role, k.attributes
    if ref == pivc.KEYREF_DIGITAL_SIGNATURE:
        role = preperso_mod.ROLE_SIGN
    elif ref == pivc.KEYREF_KEY_MANAGEMENT or ref >= pivc.KEYREF_RETIRED_FIRST:
        role = preperso_mod.ROLE_KEY_ESTABLISH
    else:
        role = preperso_mod.ROLE_AUTHENTICATE
    return preperso_mod.MODE_PIN, preperso_mod.MODE_NEVER, role, preperso_mod.ATTR_IMPORTABLE


def _create_key_object(
    app: AppContext,
    adm: PivAdmin,
    keys,
    ref: int,
    mech: int,
    rsa_crt: bool,
    slot: str,
    *,
    profile: prof_mod.PivProfile | None = None,
    confirmed: bool = False,
) -> None:
    """Dev/eval fallback: create the missing (slot, mechanism) key object via PUT
    DATA ADMIN, copying modes/role from the profile's slot template."""
    if not confirmed:
        status = inventory_mod.read_status(PivApplet(adm.card))
        if status is not None and status.secured:
            raise CryptnoxError(_FINALIZED_NO_NEW_KEYS)
    contact, contactless, role, _ = _key_template(ref, mech, profile)
    attrs = preperso_mod.ATTR_IMPORTABLE
    if keyimport.rsa_modulus_len(mech) and rsa_crt:
        attrs |= preperso_mod.ATTR_RSA_CRT
    roles = prof_mod.role_name(role)
    app.out.warn(
        f"creating the key object (PUT DATA ADMIN) with the role {roles} - a structural "
        "change normally done at pre-personalization. It is permanent, also if the chip "
        "then refuses this key size."
    )
    if ref in _SIGNING_SLOTS and not preperso_mod.key_signs(role, mech) and not confirmed:
        crt = " --rsa-crt" if attrs & preperso_mod.ATTR_RSA_CRT else ""
        app.out.warn(
            f"a key with the role {roles} cannot sign. For a signing key on slot {slot}, "
            f"use `{CLI_NAME} piv perso create-key-object --slot {slot} --algorithm "
            f"{_ALGORITHM_NAMES.get(mech, hex(mech))} --role SIGN+AUTHENTICATE{crt}` instead."
        )
        if not app.yes and not click.confirm("Create it anyway?", default=False):
            raise click.Abort()
    op = preperso_mod.create_key(ref, contact, contactless, mech, role, attrs)
    _send_create_key(adm, keys, op, slot)


def _send_create_key(adm: PivAdmin, keys, op: bytes, slot: str) -> None:  # noqa: ANN001
    adm.select()
    adm.open(keys)
    resp = adm.send(
        preperso_mod.put_data_admin_apdu(preperso_mod.build_bulk([op])),
        context=f"CREATE KEY {slot}",
    )
    if resp.sw == 0x6986:
        raise CryptnoxError(_FINALIZED_NO_NEW_KEYS)
    if resp.sw == 0x6E27:
        raise CryptnoxError(
            f"slot {slot} already has a key object for this algorithm, and a key object "
            "cannot be changed."
        )
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context=f"CREATE KEY {slot}")


def _certificate_mechanism(cert_der: bytes) -> int | None:
    """The key mechanism a certificate is for, or ``None`` when this applet has none."""
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        return _mechanism_for_public_key(x509.load_der_x509_certificate(cert_der).public_key())
    except (CryptnoxError, ValueError, UnsupportedAlgorithm):
        return None


def _mechanism_for_public_key(public_key) -> int:  # noqa: ANN001
    """The applet mechanism a certificate's public key implies."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    name = None
    if isinstance(public_key, rsa.RSAPublicKey):
        name = {2048: "RSA2048", 3072: "RSA3072", 4096: "RSA4096"}.get(public_key.key_size)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        name = {"secp256r1": "ECCP256", "secp384r1": "ECCP384"}.get(public_key.curve.name)
    if name is None:
        raise CryptnoxError(
            "the certificate's public key is not of a type this applet holds "
            "(RSA-2048/3072/4096, P-256, P-384)."
        )
    return perso_mod.ALGORITHMS[name]
