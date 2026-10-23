"""``factory`` - MANUFACTURING-ONLY operations.

Pre-personalization is structural and (at finalize) irreversible. It is isolated
here, away from the operator-facing ``piv`` commands, on purpose.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console

from cryptnox_id_cli.applets import cardmanager as cm
from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv import mgmt_auth
from cryptnox_id_cli.applets.piv import preperso as pp
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin, scp_label
from cryptnox_id_cli.applets.piv.slots import PIV_SLOTS
from cryptnox_id_cli.applets.piv.ssd import (
    ISD_AID,
    SecurityDomainInfo,
    describe_security_domain,
    kcv,
    put_key_apdu,
)
from cryptnox_id_cli.cli.commands.info import _read_cplc
from cryptnox_id_cli.cli.commands.piv import _key_encryption_key, _open_domain_channel
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.secrets.resolver import (
    CARD_MANAGER_KEY_ENVS,
    DEFAULT_GP_KEY,
    NEW_CARD_MANAGER_KEY_ENVS,
    resolve_mgmt_key,
    resolve_new_scp03_keys,
    resolve_scp03_keys,
)
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import PivState
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError
from cryptnox_id_cli.transport.scp03 import Scp03Keys


@click.group("factory")
@click.pass_obj
def command(app: AppContext) -> None:
    """MANUFACTURING-ONLY operations (pre-personalization). Use with care."""
    if not app.json:
        app.out.err.print(
            "[bold yellow]*** MANUFACTURING MODE - irreversible operations ***[/bold yellow]"
        )


@command.group("piv")
def piv_group() -> None:
    """Factory PIV operations."""


@piv_group.group("preperso")
def preperso() -> None:
    """PIV pre-personalization (OpenFIPS201 vendor, over SCP03)."""


def _probe_mgmt_key(session: object) -> dict[str, object] | None:
    """Read-only look at slot 9B: does the key object exist, does it hold a value?

    At most three short GENERAL AUTHENTICATE requests, none of which writes anything
    or consumes a retry counter (9B has none). ``None`` when the PIV applet is not
    selectable at all - that is already visible in the lifecycle state.
    """
    try:
        adm = PivAdmin(session)  # type: ignore[arg-type]
        adm.select()
        found = mgmt_auth.probe(adm.card.transmit, mgmt_auth.MECHANISM_PROBE_ORDER)
    except CryptnoxError:
        return None
    if found.mechanism is None:
        return {"present": False, "mechanism": None, "value_set": None, "sw": f"{found.sw:04X}"}
    # 6983 is "no value"; 6982 is "not usable on this interface", which says nothing
    # about the value. Everything else means the object answered, so a value is there.
    value_set: bool | None = None
    if found.sw == 0x6983:
        value_set = False
    elif found.sw != 0x6982:
        value_set = True
    return {
        "present": True,
        "mechanism": mgmt_auth.mechanism_name(found.mechanism),
        "value_set": value_set,
        "sw": f"{found.sw:04X}",
    }


def _mgmt_key_line(mgmt: dict[str, object] | None) -> str:
    if mgmt is None:
        return "not determined"
    if not mgmt["present"]:
        return "absent"
    name = mgmt["mechanism"]
    if mgmt["value_set"] is None:
        return f"{name}, not accessible on this interface"
    return f"{name}, {'value set' if mgmt['value_set'] else 'no value'}"


def _domain_line(domain: SecurityDomainInfo | None) -> str:
    if domain is None:
        return "not determined (no security domain selectable)"
    if not domain.keys:
        return f"{domain.aid_hex}, key table withheld (SW={domain.key_table_sw:04X})"
    versions = ", ".join(
        f"{v} ({len(keys)} x {keys[0].type_name} {keys[0].length} B)"
        for v in domain.key_versions
        for keys in [domain.keys_for(v)]
    )
    return f"{scp_label(domain.scp_version)} via {domain.aid_hex}; key version(s) {versions}"


def _secured_word(secured: bool | None) -> str:
    return "undetermined" if secured is None else ("yes" if secured else "no")


# --------------------------------------------------------------------------- #
@preperso.command("status")
@click.pass_obj
def status(app: AppContext) -> None:
    """Show whether pre-personalization is still possible on this card (no authentication)."""
    with app.open_session() as session:
        st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
        try:
            domain = describe_security_domain(session)
        except CryptnoxError:
            domain = None
        mgmt = _probe_mgmt_key(session)
    selectable = st.piv not in (PivState.NOT_PRESENT, PivState.UNKNOWN)
    # Same gate as the finalize command: selectable and not yet SECURED.
    finalize_allowed = selectable and not st.piv_secured
    load_config_allowed = st.piv == PivState.PRE_PERSONALIZED and not st.piv_secured
    scp_version = scp_label(domain.scp_version) if domain and domain.scp_version else None
    payload = {
        "state": st.piv.label,
        "scp03_available": domain is not None,  # kept for back-compat; covers SCP02/SCP03
        "scp_version": scp_version,
        "security_domain": domain.to_dict() if domain else None,
        "secured": st.piv_secured,
        "finalize_allowed": finalize_allowed,
        "load_config_allowed": load_config_allowed,
        "management_key": mgmt,
    }

    def human(con: Console) -> None:
        con.print(f"PIV lifecycle state: [bold]{st.piv.label}[/bold]")
        con.print(f"  Admin secure channel: {_domain_line(domain)}")
        con.print(f"  Finalized (SECURED): {_secured_word(st.piv_secured)}")
        con.print(f"  Management key (9B): {_mgmt_key_line(mgmt)}")
        if load_config_allowed:
            con.print("  Pre-perso load-config: [green]allowed[/green] (no structure yet)")
        elif st.piv_secured:
            con.print(
                "  Pre-perso load-config: [yellow]not allowed[/yellow], structure is finalized"
            )
        else:
            con.print(
                "  Pre-perso load-config: structure present; it can only add elements, "
                "existing ones cannot be changed or removed"
            )
        if finalize_allowed:
            con.print("  Finalize: [green]allowed[/green]")
        elif st.piv_secured:
            con.print("  Finalize: [yellow]not allowed[/yellow], already finalized")
        else:
            con.print(f"  Finalize: [yellow]not allowed[/yellow] in state {st.piv.label}")

    app.out.result(payload, human)


@preperso.command("inspect-defaults")
@click.pass_obj
def inspect_defaults(app: AppContext) -> None:
    """Show safe, non-secret defaults and what this applet supports."""
    supported = [c.ALGORITHMS[a] for a in sorted(c.SUPPORTED_ALGORITHMS)]
    payload = {
        "supported_algorithms": supported,
        "slots": [s.ref_hex for s in PIV_SLOTS],
        "pin_limits": {"min_length": 6, "profile_retry_cap": 10, "applet_retry_limit": 15},
        "builtin_profiles": prof_mod.builtin_names(),
    }

    def human(con: Console) -> None:
        con.print("PIV pre-personalization defaults (non-secret):")
        con.print(f"  Supported algorithms: {', '.join(supported)}")
        con.print(f"  Key slots: {', '.join(s.ref_hex for s in PIV_SLOTS)}")
        con.print(
            "  PIN/PUK limits: min length 6; retries up to 10 in a profile (the applet allows 15)"
        )
        con.print(f"  Built-in profiles: {', '.join(prof_mod.builtin_names())}")

    app.out.result(payload, human)


@preperso.command("init-config")
@click.option("--profile", "profile_name", default="cryptnox-default", show_default=True)
@click.option("--out", "out_", required=True, type=click.Path(dir_okay=False))
@click.pass_obj
def init_config(app: AppContext, profile_name: str, out_: str) -> None:
    """Write a built-in profile to a YAML file you can edit and load."""
    profile = prof_mod.builtin(profile_name)
    Path(out_).write_text(profile.to_yaml(), encoding="utf-8")
    app.out.result(
        {"profile": profile.name, "out": out_},
        lambda con: con.print(f"[green]Wrote profile '{profile.name}' to {out_}[/green]"),
    )


@preperso.command("export-config")
@click.option("--out", "out_", required=True, type=click.Path(dir_okay=False))
@click.pass_obj
def export_config(app: AppContext, out_: str) -> None:
    """Export an observed (read-only) snapshot of the card state. Not a loadable profile."""
    with app.open_session() as session:
        st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
    snapshot = {
        "_note": "Observed read-only snapshot - NOT a loadable profile (secrets excluded).",
        "state": st.piv.label,
        "objects_present": st.piv_objects,
        "pin": st.piv_pin.to_dict() if st.piv_pin else None,
        "puk": st.piv_puk.to_dict() if st.piv_puk else None,
    }
    Path(out_).write_text(yaml.safe_dump(snapshot, sort_keys=False), encoding="utf-8")
    app.out.result(
        {"out": out_, **snapshot},
        lambda con: con.print(f"[green]Wrote observed state snapshot to {out_}[/green]"),
    )


def _load_profile(file_: str | None, profile_name: str | None) -> prof_mod.PivProfile:
    if bool(file_) == bool(profile_name):
        raise click.UsageError("specify exactly one of --file or --profile")
    profile = (
        prof_mod.from_yaml(Path(file_).read_text(encoding="utf-8"))
        if file_
        else prof_mod.builtin(profile_name or "")
    )
    profile.ensure_valid()
    return profile


@preperso.command("load-config")
@click.option("--file", "file_", type=click.Path(exists=True, dir_okay=False))
@click.option("--profile", "profile_name", help="A built-in profile name instead of --file.")
@click.option("--dry-run", is_flag=True, help="Validate and show the payload; do not write.")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def load_config(
    app: AppContext, file_: str | None, profile_name: str | None, dry_run: bool, default_keys: bool
) -> None:
    """Apply a pre-personalization profile (structure) to the card over SCP03."""
    profile = _load_profile(file_, profile_name)
    ops = profile.build_ops()
    payload_bytes = profile.build_payload()

    if dry_run or app.dry_run:
        result = {
            "dry_run": True,
            "profile": profile.name,
            "operations": [label for label, _ in ops],
            "bulk_bytes": len(payload_bytes),
            "bulk_hex": payload_bytes.hex().upper(),
        }

        def human(con: Console) -> None:
            con.print(f"[bold]DRY RUN[/bold] - profile '{profile.name}' ({profile.mode})")
            con.print(f"  {len(ops)} operations, each sent as a short PUT DATA ADMIN command:")
            for label, op in ops:
                con.print(f"    [{op[0]:#04x}] {label}")
            con.print("\n  [dim]Nothing was sent to the card.[/dim]")

        app.out.result(result, human)
        return

    # Real write.
    app.out.warn(
        f"This writes {len(ops)} structural operations. They are permanent: existing "
        "elements cannot be changed or removed later (only new ones can be added), and "
        "finalize locks the structure completely."
    )
    if not app.yes and not click.confirm("Proceed with writing to the card?", default=False):
        raise click.Abort()

    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    # Send one op per PUT DATA ADMIN (each a single-op BULK) to keep every wrapped
    # command a short APDU. Stop at the first rejection and report what was applied.
    sent: list[dict[str, object]] = []
    failed: tuple[str, str] | None = None
    with app.open_session() as session:
        adm = PivAdmin(session)
        for label, op in ops:
            # JCOP 4.5 allows only ONE application APDU per applet-directed SCP03
            # session, so open a fresh secure channel for each PUT DATA ADMIN.
            adm.select()
            adm.open(keys)
            resp = adm.send(
                pp.put_data_admin_apdu(pp.build_bulk([op])), context=f"PUT DATA ADMIN [{label}]"
            )
            sent.append({"op": label, "sw": resp.sw_hex(), "ok": resp.ok})
            if not resp.ok:
                failed = (label, resp.sw_hex())
                break
    applied_ok = failed is None

    def report(con: Console) -> None:
        for s in sent:
            mark = "[green]ok[/green]" if s["ok"] else f"[red]{s['sw']}[/red]"
            con.print(f"  {mark}  {s['op']}")
        if applied_ok:
            con.print(
                f"\n[green]Applied profile '{profile.name}'[/green] ({len(sent)} operations)."
            )
        else:
            if failed is None:  # unreachable: this branch exists because an op failed
                raise RuntimeError("stopped without a failing operation")
            con.print(f"\n[red]Stopped at[/red] {failed[0]} (SW={failed[1]}).")
            con.print(
                "  Operations before it were applied. An existing element cannot be changed "
                "or removed; add missing key objects with `piv perso generate-key "
                "--create-key-object` or `piv perso import-key --create-key-object`. A full "
                "reset of the PIV applet runs through the Cryptnox remote PIV service: "
                "`cryptnox-id remote reset`."
            )

    app.out.result({"profile": profile.name, "applied": applied_ok, "operations": sent}, report)
    if not applied_ok:
        # Partial/failed structural load must not look like success to a caller's exit check.
        sys.exit(6)


#: Why the card refused the management-key write, in its own terms.
_SET_MGMT_KEY_SW_HINTS = {
    0x6985: "slot 9B already holds a value (SW=6985); re-run with --replace.",
    0x6A88: "there is no 9B key object for this mechanism (SW=6A88).",
    0x6700: "the card rejected the value's length (SW=6700).",
    0x6982: "the admin channel is not authorized to write the management key (SW=6982).",
}


@preperso.command("set-mgmt-key")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the publicly known GlobalPlatform TEST keys for the admin channel, and "
    "the same published value for the PIV management key (9B) itself "
    "(fine for dev/eval, never for deployment).",
)
@click.option(
    "--replace",
    is_flag=True,
    help="Replace a value that is already set (CLEAR then SET). Irreversible for the "
    "current value.",
)
@click.pass_obj
def set_mgmt_key(app: AppContext, default_keys: bool, replace: bool) -> None:
    """Load the PIV management key (slot 9B) value over the admin channel.

    The 9B key object itself comes from the pre-personalization profile; this command
    refuses to create one. A value that is already set is replaced only with
    ``--replace`` (CLEAR, then SET); if that is interrupted after the CLEAR, re-run
    without ``--replace``.
    """
    material = resolve_mgmt_key(app.redactor, default_keys=default_keys)
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        adm = PivAdmin(session)
        adm.select()
        found = mgmt_auth.probe(adm.card.transmit, material.mechanisms())
        if found.mechanism is None:
            names = ", ".join(mgmt_auth.mechanism_name(m) for m in material.mechanisms())
            raise mgmt_auth.MgmtKeyError(
                f"this card has no AES key object in slot 9B (SW=6A86 for {names}). The "
                "key object is laid down by pre-personalization; load a profile first.",
                stage="missing",
                sw=found.sw,
            )
        if found.sw == 0x6982:
            raise mgmt_auth.MgmtKeyError(
                "slot 9B is not accessible on this interface (SW=6982); the management key "
                "is contact-only on this card.",
                stage="access",
                sw=found.sw,
            )
        name = mgmt_auth.mechanism_name(found.mechanism)
        # The applet checks "has a value" before it checks the key's attributes, so
        # anything but 6983 means a value is already there - 6985 included.
        has_value = found.sw != 0x6983
        if has_value and not replace:
            raise mgmt_auth.MgmtKeyError(
                f"slot 9B ({name}) already holds a value (SW={found.sw:04X}); pass "
                "--replace to replace it.",
                stage="set_value",
                sw=found.sw,
            )
        value = material.key_for(found.mechanism)
        if has_value:
            app.out.warn(
                "slot 9B already holds a PIV management key; replacing it invalidates "
                "every credential that knows the current value."
            )
            adm.select()
            adm.open(keys)
            cleared = adm.send(
                mgmt_auth.clear_value_apdu(found.mechanism), context="CLEAR management key"
            )
            if not cleared.ok:
                raise StatusWordError(cleared.sw1, cleared.sw2, context="CLEAR management key")
        adm.select()
        adm.open(keys)
        resp = adm.send(
            mgmt_auth.set_value_apdu(found.mechanism, value), context="SET management key"
        )
    if not resp.ok:
        hint = _SET_MGMT_KEY_SW_HINTS.get(resp.sw)
        if hint is None:
            raise StatusWordError(resp.sw1, resp.sw2, context="SET management key")
        raise mgmt_auth.MgmtKeyError(hint, stage="set_value", sw=resp.sw)
    action = "replaced" if has_value else "set"
    payload = {
        "slot": "9B",
        "mechanism": name,
        "source": material.source,
        "action": action,
        "sw": resp.sw_hex(),
    }
    app.out.result(
        payload,
        lambda con: con.print(
            f"[green]PIV management key {action}[/green] in slot 9B ({name}, "
            f"value from {material.source})."
        ),
    )


@preperso.command("finalize")
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def finalize(app: AppContext, understood: bool, default_keys: bool) -> None:
    """IRREVERSIBLY lock the applet (SECURE APPLET). Pre-perso commands stop working."""
    with app.open_session() as session:
        st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
    # Finalize gates on the lifecycle (must be selectable and not already SECURED),
    # not on how much structure has been loaded - finalize runs AFTER pre-perso load.
    if st.piv in (PivState.NOT_PRESENT, PivState.UNKNOWN):
        raise CryptnoxError(
            f"Refusing to finalize: PIV applet is not selectable (state {st.piv.label})."
        )
    if st.piv_secured:
        raise CryptnoxError("Applet is already SECURED (finalized) - nothing to do.")

    if app.dry_run:
        app.out.result(
            {"dry_run": True, "would_finalize": True, "state": st.piv.label},
            lambda con: con.print(
                "[yellow]dry-run:[/yellow] would finalize (SECURE APPLET) - no command sent. "
                f"Current PIV state: {st.piv.label}."
            ),
        )
        return

    if not understood:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                "finalize requires --i-understand-this-is-irreversible in non-interactive mode."
            )
        app.out.warn("This is IRREVERSIBLE: pre-personalization commands will stop working.")
        if click.prompt("Type FINALIZE-PIV to continue") != "FINALIZE-PIV":
            raise click.Abort()

    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        adm = PivAdmin(session)
        adm.select()
        adm.open(keys)
        resp = adm.send(
            pp.put_data_admin_apdu(pp.build_bulk([pp.secure_applet()])), context="SECURE APPLET"
        )
        if not resp.ok:
            # Surface as a non-zero exit so manufacturing automation detects the failure.
            raise StatusWordError(resp.sw1, resp.sw2, context="SECURE APPLET (finalize)")
        post = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
    confirmed = "confirmed" if post.piv_secured else "not confirmed by the applet"
    app.out.result(
        {
            "finalized": True,
            "sw": resp.sw_hex(),
            "state": post.piv.label,
            "secured": post.piv_secured,
        },
        lambda con: con.print(
            f"[green]Applet finalized[/green] (SW={resp.sw_hex()}); state {post.piv.label}, "
            f"SECURED {confirmed}. Pre-personalization commands are no longer available."
        ),
    )


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
    config = state.present(cm.CONFIG_MODULE_AID)
    return None if config is None else not config


def _yes_no(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _print_card_state(c: Console, state: cm.CardState) -> None:
    c.print(f"  Lifecycle: {cm.lifecycle_name(state.lifecycle)}")
    c.print("  JCOP modules (the fuse deletes these):")
    for m in cm.FUSE_MODULES:
        present = state.present(m.aid)
        word = "unknown" if present is None else ("present" if present else "absent")
        c.print(f"    {m.label} ({m.aid.hex().upper()}): {word}")


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
        c.print(f"  Configuration sealed: {_yes_no(_configuration_sealed(state))}")

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
@click.option("-y", "--yes", "yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option("--dry-run", is_flag=True, help="Show the plan; send nothing that changes the card.")
@click.pass_obj
def card_fuse(
    app: AppContext,
    default_keys: bool,
    randomize: bool,
    out_: str | None,
    yes: bool,
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
        if not (yes or app.yes):
            if app.json or not sys.stdin.isatty():
                raise CryptnoxError("fuse asks for confirmation; pass -y in non-interactive use.")
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

    sealed = _configuration_sealed(after) if after else None
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
