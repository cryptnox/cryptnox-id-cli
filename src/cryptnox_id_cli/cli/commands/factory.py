# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``factory`` - the card as a whole: the card manager's lifecycle and the JCOP fuse.

Fusing is the manufacturer's irreversible last step, kept apart from the ``piv``
commands on purpose.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli.applets import cardmanager as cm
from cryptnox_id_cli.applets.piv.admin import scp_label
from cryptnox_id_cli.applets.piv.ssd import (
    ISD_AID,
    SecurityDomainInfo,
    describe_security_domain,
    kcv,
    put_key_apdu,
)
from cryptnox_id_cli.cli.commands.info import _read_cplc
from cryptnox_id_cli.cli.commands.piv.admin import _key_encryption_key, _open_domain_channel
from cryptnox_id_cli.cli.commands.piv.perso import preperso_moved
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.secrets.resolver import (
    CARD_MANAGER_KEY_ENVS,
    DEFAULT_GP_KEY,
    NEW_CARD_MANAGER_KEY_ENVS,
    resolve_new_scp03_keys,
    resolve_scp03_keys,
)
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.scp03 import Scp03Keys


@click.group("factory")
@click.pass_context
def command(ctx: click.Context) -> None:
    """MANUFACTURING-ONLY operations on the whole card. Use with care."""
    app: AppContext = ctx.obj
    if not app.json and ctx.invoked_subcommand != "piv":
        app.out.err.print(
            "[bold yellow]*** MANUFACTURING MODE - irreversible operations ***[/bold yellow]"
        )


@command.command(
    "piv",
    hidden=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def piv_redirect(args: tuple[str, ...]) -> None:
    """(moved) Pre-personalization is under `piv perso`."""
    raise preperso_moved(args)


# ------------------------------------------------------------------- card --- #
FUSE_PHRASE = "FUSE-CARD"


@command.group("card")
def card_group() -> None:
    """The card as a whole: the card manager's lifecycle and the JCOP fuse."""


def _card_manager_keys(app: AppContext, default_keys: bool) -> Scp03Keys:
    e, m, d = CARD_MANAGER_KEY_ENVS
    return resolve_scp03_keys(
        app.redactor, default_keys=default_keys, enc_env=e, mac_env=m, dek_env=d
    )


def _card_manager_domain(session) -> tuple[SecurityDomainInfo, int, int]:  # noqa: ANN001
    """The card manager, its SCP version and its single key version."""
    domain = describe_security_domain(session, (ISD_AID,))
    if domain is None:
        raise CryptnoxError(f"the card manager ({ISD_AID.hex().upper()}) is not selectable.")
    if domain.scp_version is None:
        raise CryptnoxError(
            "cannot tell SCP02 from SCP03 from the card manager's key table; refusing."
        )
    if len(domain.key_versions) != 1:
        raise CryptnoxError(
            f"the card manager holds key versions {domain.key_versions}; refusing to choose "
            "which one to use."
        )
    return domain, domain.scp_version, domain.key_versions[0]


def _configuration_sealed(state: cm.CardState) -> bool | None:
    """``False`` when the configuration module is listed; otherwise unknown, because a
    card may leave it out of GET STATUS while it is still loaded."""
    return False if state.listed(cm.CONFIG_MODULE_AID) else None


def _yes_no(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _print_card_state(c: Console, state: cm.CardState) -> None:
    c.print(f"  Lifecycle: {cm.lifecycle_name(state.lifecycle)}")
    c.print("  JCOP modules the fuse deletes, as GET STATUS lists them:")
    for m in cm.FUSE_MODULES:
        c.print(f"    {m.label} ({m.aid.hex().upper()}): {state.listing(m.aid)}")
    c.print("    [dim]A module that is not listed may still be loaded.[/dim]")


@card_group.command("status")
@click.option(
    "--default-keys",
    is_flag=True,
    help="The card-manager keys are the publicly known GlobalPlatform test keys "
    "(development cards). Otherwise CARD_MANAGER_ENC / _MAC / _DEK.",
)
@click.pass_obj
def card_status(app: AppContext, default_keys: bool) -> None:
    """Show the card's lifecycle and which JCOP modules are loaded. Changes nothing.

    Authenticates to the card manager, so it needs the card-manager keys.
    """
    keys = _card_manager_keys(app, default_keys)
    with app.open_session() as session:
        domain, _scp, version = _card_manager_domain(session)
        adm = _open_domain_channel(session, ISD_AID, keys, version)
        state = cm.read_card_state(adm.send)
        adm.forget_channel()
    payload = {
        "aid": domain.aid_hex,
        "scp_version": scp_label(domain.scp_version),
        "key_version": version,
        **state.to_dict(),
        "configuration_sealed": _configuration_sealed(state),
    }

    def human(c: Console) -> None:
        c.print(f"Card manager {domain.aid_hex} ({scp_label(domain.scp_version)}):")
        _print_card_state(c, state)
        sealed = _configuration_sealed(state)
        note = "" if sealed is not None else " (only the fuse's DELETE can tell)"
        c.print(f"  Configuration sealed: {_yes_no(sealed)}{note}")

    app.out.result(payload, human)


def _write_key_file(path: str, record: dict[str, object]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)
        fh.write("\n")


def _fuse_failed(steps: list[dict[str, object]], what: str, sw_hex: str) -> CryptnoxError:
    done = ", ".join(f"{s['step']} ({s['result']})" for s in steps) or "nothing"
    return CryptnoxError(
        f"{what} refused (SW={sw_hex}); the fuse stopped there. Already done on the card: "
        f"{done}. Run `factory card status` to see the card's state."
    )


@card_group.command("fuse")
@click.option(
    "--default-keys",
    is_flag=True,
    help="The CURRENT card-manager keys are the publicly known GlobalPlatform test keys "
    "(development cards). Otherwise CARD_MANAGER_ENC / _MAC / _DEK.",
)
@click.option(
    "--randomize",
    is_flag=True,
    help="Generate the new card-manager keys. Requires --out.",
)
@click.option(
    "--out",
    "out_",
    type=click.Path(dir_okay=False),
    help="Write the new card-manager keys to FILE (created with mode 0600, never "
    "overwritten) before anything on the card changes.",
)
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.option("--dry-run", is_flag=True, help="Show the plan; send nothing that changes the card.")
@click.pass_obj
def card_fuse(
    app: AppContext,
    default_keys: bool,
    randomize: bool,
    out_: str | None,
    understood: bool,
    dry_run: bool,
) -> None:
    """IRREVERSIBLY fuse the card: seal the JCOP configuration, set it SECURED, lock it.

    Deletes the JCOP sample modules and then the configuration module, moves the card's
    lifecycle to SECURED and replaces the card-manager key. New keys come from
    CARD_MANAGER_NEW_ENC / _MAC / _DEK, or from --randomize with --out.
    """
    if randomize and not out_:
        raise CryptnoxError(
            "--randomize needs --out FILE: a card locked to keys nobody holds can never be "
            "administered again."
        )
    if out_ and Path(out_).exists():
        raise CryptnoxError(f"{out_} exists; the key file is never overwritten.")
    if randomize:
        new_keys = Scp03Keys(os.urandom(16), os.urandom(16), os.urandom(16))
        for k in (new_keys.enc, new_keys.mac, new_keys.dek):
            app.redactor.register(k)
    else:
        new_keys = resolve_new_scp03_keys(app.redactor, NEW_CARD_MANAGER_KEY_ENVS)
    if new_keys == Scp03Keys.same(DEFAULT_GP_KEY):
        raise CryptnoxError("the new keys are the publicly known test keys; choose your own.")
    planning = dry_run or app.dry_run

    with app.open_session() as session:
        identity = _read_cplc(session) or {}
        domain, scp_version, version = _card_manager_domain(session)
        label = scp_label(scp_version)
        new_kcvs = [kcv(scp_version, k) for k in (new_keys.enc, new_keys.mac, new_keys.dek)]
        kcv_hex = [v.hex().upper() for v in new_kcvs]
        if planning:
            plan = {
                "dry_run": True,
                "aid": domain.aid_hex,
                "scp_version": label,
                "key_version": version,
                "delete": [m.key for m in cm.FUSE_MODULES],
                "lifecycle_target": cm.lifecycle_name(cm.SECURED),
                "new_key_kcvs": kcv_hex,
            }

            def plan_human(c: Console) -> None:
                c.print(
                    f"[bold]DRY RUN[/bold] - would fuse the card ({label}, key version {version}):"
                )
                for m in cm.FUSE_MODULES:
                    c.print(f"  delete the {m.label} ({m.aid.hex().upper()}) if present")
                c.print("  set the lifecycle to INITIALIZED, then SECURED, where not already")
                c.print(f"  replace the card-manager key; new key check values {' '.join(kcv_hex)}")
                c.print("\n  [dim]Nothing that changes the card was sent.[/dim]")

            app.out.result(plan, plan_human)
            return

        current = _card_manager_keys(app, default_keys)
        if current == new_keys:
            raise CryptnoxError("the new keys equal the current ones; nothing would be locked.")
        adm = _open_domain_channel(session, ISD_AID, current, version)
        before = cm.read_card_state(adm.send)
        if before.lifecycle is None:
            raise CryptnoxError("the card manager did not report the card's lifecycle; refusing.")
        if before.lifecycle in (cm.CARD_LOCKED, cm.TERMINATED):
            raise CryptnoxError(
                f"the card is {cm.lifecycle_name(before.lifecycle)}; it cannot be fused."
            )

        if not app.json:
            app.out.console.print(f"Card manager {domain.aid_hex} ({label}), before fusing:")
            _print_card_state(app.out.console, before)
        app.out.warn(
            "this fuses the card and cannot be undone. The JCOP configuration is sealed "
            "for good, the lifecycle becomes SECURED and cannot go back, and the card "
            "manager answers only to the new key from now on."
        )
        if not understood:
            if app.json or not sys.stdin.isatty():
                raise CryptnoxError(
                    "fuse requires --i-understand-this-is-irreversible in non-interactive mode."
                )
            if click.prompt(f"Type {FUSE_PHRASE} to continue") != FUSE_PHRASE:
                raise click.Abort()

        if out_:
            _write_key_file(
                out_,
                {
                    "card_manager_aid": domain.aid_hex,
                    "cplc_uid": identity.get("uid"),
                    "ic_serial": identity.get("ic_serial"),
                    "key_version": version,
                    "scp_version": label,
                    "enc": new_keys.enc.hex().upper(),
                    "mac": new_keys.mac.hex().upper(),
                    "dek": new_keys.dek.hex().upper(),
                    "kcv": kcv_hex,
                    "written": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                },
            )

        steps: list[dict[str, object]] = []
        for m in cm.FUSE_MODULES:
            resp = adm.send(cm.delete_aid_apdu(m.aid), context=f"DELETE {m.label}")
            if resp.ok:
                steps.append(
                    {"step": f"delete {m.label}", "sw": resp.sw_hex(), "result": "deleted"}
                )
            elif resp.sw == 0x6A88:
                steps.append({"step": f"delete {m.label}", "sw": resp.sw_hex(), "result": "absent"})
            else:
                raise _fuse_failed(steps, f"DELETE {m.label}", resp.sw_hex())
        targets = [cm.INITIALIZED] if before.lifecycle == cm.OP_READY else []
        if before.lifecycle != cm.SECURED:
            targets.append(cm.SECURED)
        for target in targets:
            name = cm.lifecycle_name(target)
            resp = adm.send(cm.set_card_lifecycle_apdu(target), context=f"SET STATUS {name}")
            if not resp.ok:
                raise _fuse_failed(steps, f"SET STATUS {name}", resp.sw_hex())
            steps.append({"step": f"lifecycle {name}", "sw": resp.sw_hex(), "result": "set"})
        apdu, kcvs = put_key_apdu(
            scp_version,
            _key_encryption_key(adm, current),
            new_keys,
            replace_version=version,
            new_version=version,
        )
        resp = adm.send(apdu, context="PUT KEY")
        if not resp.ok:
            raise _fuse_failed(steps, "PUT KEY", resp.sw_hex())
        steps.append({"step": "lock card manager", "sw": resp.sw_hex(), "result": "locked"})
        card_kcvs_match = resp.data == bytes([version]) + b"".join(kcvs)
        adm.forget_channel()

        verify_error: str | None = None
        after: cm.CardState | None = None
        try:
            check = _open_domain_channel(session, ISD_AID, new_keys, version)
            after = cm.read_card_state(check.send)
            check.forget_channel()
        except CryptnoxError as exc:
            verify_error = str(exc)

    config_step = next(s for s in steps if s["step"] == f"delete {cm.FUSE_MODULES[-1].label}")
    sealed = config_step["result"] in ("deleted", "absent") and not (
        after is not None and after.listed(cm.CONFIG_MODULE_AID)
    )
    secured = after is not None and after.lifecycle == cm.SECURED
    payload = {
        "aid": domain.aid_hex,
        "scp_version": label,
        "key_version": version,
        "before": before.to_dict(),
        "steps": steps,
        "after": after.to_dict() if after else None,
        "configuration_sealed": sealed,
        "new_key_kcvs": kcv_hex,
        "card_kcvs_match": card_kcvs_match,
        "new_keys_authenticate": verify_error is None,
        "key_file": out_,
    }

    def human(c: Console) -> None:
        c.print(f"[green]Fuse sequence complete[/green] ({label}, key version {version}):")
        for s in steps:
            c.print(f"  {s['step']}: {s['result']} (SW={s['sw']})")
        if after is not None:
            c.print("After:")
            _print_card_state(c, after)
        word = "yes" if sealed else "[red]no[/red]"
        c.print(
            f"  Configuration sealed: {word} (its DELETE answered "
            f"{config_step['result']}, SW={config_step['sw']})"
        )
        agree = "card agrees" if card_kcvs_match else "[red]card echoed different values[/red]"
        c.print(f"  New key check values: {' '.join(kcv_hex)} (ENC MAC DEK); {agree}")
        auth = "yes" if verify_error is None else f"[red]no[/red] ({verify_error})"
        c.print(f"  New keys authenticate: {auth}")
        if out_:
            c.print(f"  New keys written to {out_}; keep that file safe.")
        c.print("  From now on set CARD_MANAGER_ENC / _MAC / _DEK to the new values.")

    app.out.result(payload, human)
    if not (card_kcvs_match and verify_error is None and sealed and secured):
        raise CryptnoxError(
            "the fuse steps were accepted but a post-check failed; see the lines above, then "
            "run `factory card status` with the new keys."
        )
