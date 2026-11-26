# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The quickstart steps that write to the card, and the loop that runs them."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import keyimport, verifier
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import csr as csr_mod
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession
from cryptnox_id_cli.transport.scp03 import Scp03Keys

from ..primitives import (
    SLOT_CERT_OBJECT,
    _create_key_object,
    _generate_key_on_card,
    _import_cert_der,
    _key_template,
    _read_cert_der,
    _select,
    _set_verifier,
    _sign_with_session,
    _write_standard,
)
from .plan import PlannedStep


@dataclass
class _Run:
    """What the steps of one quickstart run share; ``spki`` and ``outputs`` fill in as it goes."""

    app: AppContext
    session: CardSession
    adm: PivAdmin
    keys: Scp03Keys
    slot: str
    ref: int
    mech: int
    alg: str
    profile: prof_mod.PivProfile
    cert_mode: str
    subject: str
    days: int
    csr_out: str | None
    cert_out: str | None
    public_out: str | None
    default_keys: bool
    pin: bytes
    puk: bytes | None
    spki: bytes | None = None
    outputs: dict[str, str | None] = field(
        default_factory=lambda: {"public_key": None, "certificate": None, "csr": None}
    )


def _step_preperso(run: _Run) -> dict[str, object]:
    for label, op in run.profile.build_ops():
        run.adm.select()
        run.adm.open(run.keys)
        resp = run.adm.send(
            preperso_mod.put_data_admin_apdu(preperso_mod.build_bulk([op])),
            context=f"PUT DATA ADMIN [{label}]",
        )
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context=f"preperso [{label}]")
    return {"detail": {"profile": run.profile.name}}


def _set_value(run: _Run, ref: int, value: bytes, label: str) -> dict[str, object]:
    padded = verifier.pad(value)
    run.app.redactor.register(padded)
    resp = _set_verifier(run.adm, run.keys, ref, padded, label=label)
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context=f"SET {label}")
    return {"sw": resp.sw_hex()}


def _step_set_pin(run: _Run) -> dict[str, object]:
    return _set_value(run, pivc.REF_PIV_PIN, run.pin, "PIN")


def _step_set_puk(run: _Run) -> dict[str, object]:
    if run.puk is None:  # unreachable: planner gates set-puk on a resolved PUK
        raise RuntimeError("set-puk planned without a PUK value")
    return _set_value(run, pivc.REF_PUK, run.puk, "PUK")


def _step_create_key_object(run: _Run) -> dict[str, object]:
    _, _, _, attrs = _key_template(run.ref, run.mech, run.profile)
    _create_key_object(
        run.app,
        run.adm,
        run.keys,
        run.ref,
        run.mech,
        bool(attrs & preperso_mod.ATTR_RSA_CRT),
        run.slot,
        profile=run.profile,
        confirmed=True,
    )
    return {"detail": {"slot": run.slot, "algorithm": run.alg}}


def _step_generate_key(run: _Run) -> dict[str, object]:
    import hashlib

    from cryptography.hazmat.primitives import serialization

    generated = _generate_key_on_card(
        run.app, run.adm, run.keys, run.ref, run.mech, label=run.slot, default_keys=run.default_keys
    )
    public_key = generated.public_key
    run.spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(run.spki).hexdigest().upper()
    if run.public_out:
        Path(run.public_out).write_bytes(perso_mod.public_key_pem(public_key))
        run.outputs["public_key"] = run.public_out
    return {
        "detail": {
            "algorithm": run.alg,
            "public_key_sha256": fingerprint,
            "generate_path": generated.path,
            "management_key_auth": generated.management_key_auth,
        }
    }


def _step_certificate(run: _Run) -> dict[str, object]:
    if run.spki is None:  # unreachable: generate-key runs whenever certificate runs
        raise RuntimeError("certificate step planned without a generated key")
    if run.cert_mode == "csr":
        return _make_csr(run, run.spki)
    return _make_self_signed(run, run.spki)


def _make_csr(run: _Run, spki: bytes) -> dict[str, object]:
    pem = _sign_with_session(
        run.session,
        run.ref,
        run.mech,
        run.pin,
        lambda s: csr_mod.build_csr(run.subject, spki, run.mech, s),
    )
    if run.csr_out is None:  # unreachable: csr mode validates --csr-out at parse
        raise RuntimeError("csr mode without --csr-out")
    Path(run.csr_out).write_bytes(pem)
    run.outputs["csr"] = run.csr_out
    return {
        "detail": {
            "mode": "csr",
            "note": "re-running quickstart regenerates the key and invalidates this CSR",
        }
    }


def _make_self_signed(run: _Run, spki: bytes) -> dict[str, object]:
    import datetime
    import secrets as pysecrets

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    serial = int.from_bytes(pysecrets.token_bytes(8), "big") | 1
    not_before = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_after = not_before + datetime.timedelta(days=run.days)

    def build(s):
        return csr_mod.build_self_signed(
            run.subject,
            spki,
            run.mech,
            s,
            serial=serial,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
        )

    pem = _sign_with_session(run.session, run.ref, run.mech, run.pin, build)
    cert_der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    resp = _import_cert_der(run.adm, run.keys, run.ref, cert_der, label=run.slot)
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context="IMPORT cert")
    if run.cert_out:
        Path(run.cert_out).write_bytes(pem)
        run.outputs["certificate"] = run.cert_out
    return {"detail": {"mode": "self-signed", "subject": run.subject, "days": run.days}}


def _write_object(run: _Run, name: str) -> dict[str, object]:
    results = _write_standard(run.adm, run.keys, (name,))
    if not results[0]["ok"]:
        raise StatusWordError(
            int(str(results[0]["sw"])[:2], 16),
            int(str(results[0]["sw"])[2:], 16),
            context=f"PUT DATA {name}",
        )
    return {"sw": results[0]["sw"]}


def _step_write_chuid(run: _Run) -> dict[str, object]:
    return _write_object(run, "chuid")


def _step_write_ccc(run: _Run) -> dict[str, object]:
    return _write_object(run, "ccc")


def _step_smoke_test(run: _Run) -> dict[str, object]:
    import os

    digest = os.urandom(keyimport.digest_for_mechanism(run.mech).digest_size)
    try:
        signature = _sign_with_session(run.session, run.ref, run.mech, run.pin, lambda s: s(digest))
    except StatusWordError as exc:
        if exc.info.sw_hex() == "6985":
            raise CryptnoxError(
                f"slot {run.slot} refused to sign (SW=6985): its key cannot sign "
                "on this applet, so no signature was made. For a signing key, "
                "use slot 9C or a key object for another algorithm that can "
                f"sign; `{CLI_NAME} piv inventory` lists each key's role."
            ) from exc
        raise
    return {"detail": {"signature_len": len(signature)}}


#: Each planned step's code; what it returns goes into the step's result entry.
_STEPS: dict[str, Callable[[_Run], dict[str, object]]] = {
    "preperso-load-config": _step_preperso,
    "set-pin": _step_set_pin,
    "set-puk": _step_set_puk,
    "create-key-object": _step_create_key_object,
    "generate-key": _step_generate_key,
    "certificate": _step_certificate,
    "write-chuid": _step_write_chuid,
    "write-ccc": _step_write_ccc,
    "smoke-test": _step_smoke_test,
}


def _run_steps(run: _Run, steps: list[PlannedStep]) -> tuple[list[dict[str, object]], bool]:
    """Run the planned steps in order and stop at the first failure; True when one failed."""
    executed: list[dict[str, object]] = []
    for planned in steps:
        if not planned.run:
            executed.append({"step": planned.step, "status": "skipped", "reason": planned.reason})
            continue
        try:
            extra = _STEPS[planned.step](run)
        except CryptnoxError as exc:
            executed.append({"step": planned.step, "status": "failed", "reason": str(exc)})
            return executed, True
        executed.append({"step": planned.step, "status": "ok", **extra})
    return executed, False


def _export_kept_public_key(run: _Run, public_out: str) -> None:
    """Write ``--public-out`` from the slot's certificate when quickstart kept the key."""
    from cryptography import x509

    cert_name = SLOT_CERT_OBJECT.get(run.ref)
    kept_der = _read_cert_der(_select(run.session), cert_name) if cert_name else None
    if kept_der is not None:
        public_key = x509.load_der_x509_certificate(kept_der).public_key()
        Path(public_out).write_bytes(perso_mod.public_key_pem(public_key))
        run.outputs["public_key"] = public_out
