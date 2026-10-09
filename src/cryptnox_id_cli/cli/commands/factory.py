"""``factory`` - MANUFACTURING-ONLY operations.

Pre-personalization is structural and (at finalize) irreversible. It is isolated
here, away from the operator-facing ``piv`` commands, on purpose.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import yaml
from rich.console import Console

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv import mgmt_auth
from cryptnox_id_cli.applets.piv import preperso as pp
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin, scp_label
from cryptnox_id_cli.applets.piv.slots import PIV_SLOTS
from cryptnox_id_cli.applets.piv.ssd import SecurityDomainInfo, describe_security_domain
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.secrets.resolver import resolve_mgmt_key, resolve_scp03_keys
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.state.model import PivState
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError


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
        "pin_fips": {"min_length": 6, "retry_cap": 10},
        "builtin_profiles": prof_mod.builtin_names(),
    }

    def human(con: Console) -> None:
        con.print("PIV pre-personalization defaults (non-secret):")
        con.print(f"  Supported algorithms: {', '.join(supported)}")
        con.print(f"  Key slots: {', '.join(s.ref_hex for s in PIV_SLOTS)}")
        con.print("  PIN/PUK limits: min length 6, retry cap 10")
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
                "reset of the PIV applet is a Cryptnox operation: contact Cryptnox support."
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
