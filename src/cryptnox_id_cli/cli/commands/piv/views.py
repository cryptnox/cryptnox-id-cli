# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Read-only ``piv`` views: info, status, discover, slots, inventory and validate."""

from __future__ import annotations

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import inventory as inventory_mod
from cryptnox_id_cli.applets.piv.objects import object_by_name
from cryptnox_id_cli.applets.piv.slots import PIV_SLOTS
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.output.render import state_style
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.util import tlv
from cryptnox_id_cli.util.hexutil import to_hex

from .primitives import SLOT_CERT_OBJECT, _read_cert_der, _select, _styled_status


# --------------------------------------------------------------------------- #
@click.command("info")
@click.pass_obj
def info(app: AppContext) -> None:
    """Show the PIV AID, label, URL and the algorithms/slots this applet exposes."""
    with app.open_session() as session:
        piv = _select(session)
        apt = piv.apt
    if apt is None:  # unreachable: _select() always parses the APT
        raise RuntimeError("card returned no PIV Application Property Template")
    supported = [pivc.ALGORITHMS[a] for a in sorted(pivc.SUPPORTED_ALGORITHMS)]
    note = "Values are read from the card; no FIPS/NIST/SP800-73 validation is claimed."
    payload = {
        "aid": apt.aid_hex,
        "label": apt.label,
        "url": apt.url,
        "supported_algorithms": supported,
        "slots": [{"ref": s.ref_hex, "name": s.name} for s in PIV_SLOTS],
        "note": note,
    }

    def human(c: Console) -> None:
        c.print("[bold]PIV applet[/bold]")
        c.print(f"  AID:   {apt.aid_hex}")
        c.print(f"  Label: {escape(str(apt.label))}")
        c.print(f"  URL:   {escape(str(apt.url))}")
        c.print(f"\n  Supported algorithms: {', '.join(supported)}")
        c.print(f"  Key slots: {', '.join(s.ref_hex for s in PIV_SLOTS)}")
        c.print(f"\n[dim]{note}[/dim]")

    app.out.result(payload, human)


_OBJECT_PRESENCE = {
    True: "[green]yes[/green]",
    False: "[dim]no[/dim]",
    None: "[yellow]unknown[/yellow] (read failed)",
}


@click.command("status")
@click.pass_obj
def status(app: AppContext) -> None:
    """Show PIV lifecycle state, PIN/PUK status and which objects are present."""
    with app.open_session() as session:
        st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
    payload: dict[str, object] = {
        "state": st.piv.label,
        "reader": app.resolved_reader,
        "apt": st.piv_apt.to_dict() if st.piv_apt else None,
        "pin": st.piv_pin.to_dict() if st.piv_pin else None,
        "puk": st.piv_puk.to_dict() if st.piv_puk else None,
        "objects_present": st.piv_objects,
        "secured": st.piv_secured,
        "notes": st.notes,
    }

    def human(c: Console) -> None:
        c.print(f"[bold]PIV state:[/bold] {state_style(st.piv.label)}")
        if st.piv_secured is None:
            c.print("  Structure: finalize state not readable")
        elif st.piv_secured:
            c.print("  Structure: finalized (SECURED), no further pre-personalization")
        else:
            c.print("  Structure: not finalized")
        for label, vs in (("PIN (80)", st.piv_pin), ("PUK (81)", st.piv_puk)):
            if not vs:
                continue
            if vs.configured is None:
                c.print(f"  {label}: {_styled_status(vs)}")
            elif not vs.configured:
                c.print(f"  {label}: not set")
            elif vs.ok:
                c.print(f"  {label}: set")
            else:
                c.print(f"  {label}: set, {_styled_status(vs)}")
        if st.piv_objects:
            table = app.out.table("Object", "Present")
            for name, present in st.piv_objects.items():
                table.add_row(name, _OBJECT_PRESENCE[present])
            c.print(table)
        for note in st.notes:
            c.print(f"[yellow]*[/yellow] {escape(note)}")

    app.out.result(payload, human)


@click.command("discover")
@click.pass_obj
def discover(app: AppContext) -> None:
    """Read the PIV Discovery Object (PIN usage policy), if present."""
    with app.open_session() as session:
        piv = _select(session)
        data = piv.read_object(bytes([0x7E]))
    if data is None:
        app.out.result(
            {"present": False},
            lambda c: c.print("Discovery object: [yellow]not present[/yellow]"),
        )
        return
    nodes = tlv.parse(data)
    disc = tlv.find(nodes, 0x7E)
    scope = disc.children if (disc and disc.children) else nodes
    aid_node = tlv.find(scope, 0x4F)
    policy_node = tlv.find(scope, 0x5F2F)
    payload = {
        "present": True,
        "aid": to_hex(aid_node.value) if aid_node else None,
        "pin_policy": to_hex(policy_node.value) if policy_node else None,
    }

    def human(c: Console) -> None:
        c.print("Discovery object: [green]present[/green]")
        c.print(f"  AID: {payload['aid']}")
        c.print(f"  PIN usage policy: {payload['pin_policy']}")

    app.out.result(payload, human)


@click.command("slots")
@click.pass_obj
def slots(app: AppContext) -> None:
    """List PIV key slots and whether each cert-bearing slot has a certificate."""
    with app.open_session() as session:
        piv = _select(session)
        cert_present = {}
        for ref, obj_name in SLOT_CERT_OBJECT.items():
            obj = object_by_name(obj_name)
            cert_present[ref] = piv.object_present(obj.oid) if obj else False
    rows = []
    for s in PIV_SLOTS:
        has = None if s.ref not in SLOT_CERT_OBJECT else bool(cert_present.get(s.ref))
        rows.append({"ref": s.ref_hex, "name": s.name, "usage": s.usage, "certificate": has})

    def human(c: Console) -> None:
        table = app.out.table("Slot", "Name", "Usage", "Cert")
        for r in rows:
            cert = (
                "-"
                if r["certificate"] is None
                else ("[green]yes[/green]" if r["certificate"] else "[dim]no[/dim]")
            )
            table.add_row(str(r["ref"]), str(r["name"]), str(r["usage"]), cert)
        c.print(table)

    app.out.result({"slots": rows}, human)


def _mode_cell(mode: int) -> str:
    return f"{inventory_mod.describe_mode(mode)} ({mode:02X})"


@click.command("inventory")
@click.pass_obj
def inventory(app: AppContext) -> None:
    """List the applet's structure with its access rules (no authentication).

    Key objects, verifiers and containers as the applet itself reports them, plus
    its version, state and config flags.
    """
    with app.open_session() as session:
        inv = inventory_mod.read_inventory(_select(session))

    def human(c: Console) -> None:
        ver = inv.version
        title = f"{escape(ver.label)} {ver.version}" if ver else "PIV applet"
        c.print(f"[bold]{title}[/bold]")
        if inv.status:
            s = inv.status
            finalized = "finalized (SECURED)" if s.secured else "not finalized"
            c.print(f"  State:     {inventory_mod.describe_state(s.state)}, {finalized}")
            interface = "contactless" if s.contactless else "contact"
            c.print(f"  Interface: {interface}; FIPS-mode build: {'yes' if s.fips_mode else 'no'}")
        if inv.config:
            flags = ", ".join(
                f"{name.replace('_', '-')}={'on' if on else 'off'}"
                for name, on in inv.config.to_dict().items()
            )
            c.print(f"  Config:    {flags}")
        if inv.restricted:
            c.print(
                "\n[yellow]The applet withholds its structure (restrict-enumeration is "
                "set); listing key objects, verifiers and containers needs the admin "
                "channel.[/yellow]"
            )
        if inv.keys is not None:
            table = app.out.table(
                "Slot",
                "Name",
                "Mechanism",
                "Roles",
                "Attributes",
                "Contact",
                "Contactless",
                "Admin",
                title=f"Key objects ({len(inv.keys)})",
            )
            for k in inv.keys:
                table.add_row(
                    f"{k.ref:02X}",
                    k.slot_name,
                    k.mechanism_name,
                    "+".join(inventory_mod.role_names(k.role)) or "none",
                    "+".join(inventory_mod.attribute_names(k.attributes)) or "none",
                    _mode_cell(k.mode_contact),
                    _mode_cell(k.mode_contactless),
                    f"{k.admin_key:02X}",
                )
            c.print(table)
        if inv.verifiers is not None:
            table = app.out.table(
                "Ref",
                "Name",
                "Contact",
                "Contactless",
                "Length",
                "Retries",
                "Rules",
                title=f"Verifiers ({len(inv.verifiers)})",
            )
            for v in inv.verifiers:
                rules = (
                    f"charset={v.charset:02X} history={v.history} sequence={v.sequence} "
                    f"repeat={v.repeat} restrict-update={'yes' if v.restrict_update else 'no'}"
                )
                table.add_row(
                    f"{v.ref:02X}",
                    v.name,
                    _mode_cell(v.mode_contact),
                    _mode_cell(v.mode_contactless),
                    f"{v.min_length}-{v.max_length}",
                    f"{v.retries_contact}/{v.retries_contactless}",
                    rules,
                )
            c.print(table)
        if inv.containers is not None:
            table = app.out.table(
                "OID",
                "Name",
                "Contact",
                "Contactless",
                "Admin",
                title=f"Containers ({len(inv.containers)})",
            )
            for o in inv.containers:
                table.add_row(
                    o.oid_hex,
                    o.name,
                    _mode_cell(o.mode_contact),
                    _mode_cell(o.mode_contactless),
                    f"{o.admin_key:02X}",
                )
            c.print(table)

    app.out.result(inv.to_dict(), human)


@click.command("validate")
@click.option("--profile", default=None, help="Informational label for the report.")
@click.pass_obj
def validate(app: AppContext, profile: str | None) -> None:
    """Compatibility / consistency check (NOT a NIST/FIPS validation)."""
    with app.open_session() as session:
        st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
        piv = _select(session)
        certs_loaded = {
            ref: _read_cert_der(piv, name) is not None for ref, name in SLOT_CERT_OBJECT.items()
        }
    objs = st.piv_objects
    checks: list[dict[str, object]] = []

    def add(name: str, ok: bool, detail: str = "", *, unknown: bool = False) -> None:
        check: dict[str, object] = {"check": name, "ok": ok, "detail": detail}
        if unknown:
            check["unknown"] = True
        checks.append(check)

    add("PIV applet selectable", st.piv_apt is not None, st.piv.label)
    for label, vs in (("PIN configured", st.piv_pin), ("PUK configured", st.piv_puk)):
        if st.piv_apt is None:
            add(label, False)
        elif vs is None:
            add(label, False, "not readable", unknown=True)
        elif vs.refused:
            add(label, False, vs.hint or vs.status_text, unknown=True)
        elif vs.configured is None:
            add(label, False, vs.status_text, unknown=True)
        else:
            add(label, bool(vs.configured))
    add("CHUID present", bool(objs.get("chuid")))
    add("CCC present", bool(objs.get("ccc")))
    add("Discovery present", bool(objs.get("discovery")))
    for ref in SLOT_CERT_OBJECT:
        add(f"certificate {ref:02X} loaded", certs_loaded[ref])
    supported = ", ".join(pivc.ALGORITHMS[a] for a in sorted(pivc.SUPPORTED_ALGORITHMS))
    add("Supported algorithms reported", True, supported)
    payload = {
        "profile": profile,
        "checks": checks,
        "note": "Compatibility/consistency check only - NOT a NIST/FIPS/SP800-73 validation.",
    }

    def human(c: Console) -> None:
        table = app.out.table("Check", "Result", "Detail")
        for ch in checks:
            if ch["ok"]:
                mark = "[green]pass[/green]"
            elif ch.get("unknown"):
                mark = "[yellow]unknown[/yellow]"
            else:
                mark = "[yellow]absent[/yellow]"
            table.add_row(str(ch["check"]), mark, str(ch["detail"]))
        c.print(table)
        c.print(f"\n[dim]{payload['note']}[/dim]")

    app.out.result(payload, human)
