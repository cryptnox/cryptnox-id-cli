# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""How a result is shown: the service's assertions, the local reads, the warnings.

Nothing here touches a card or the network. Every value that came from the
service goes through :func:`text`: formatted, stripped of control sequences,
escaped for the console.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import protocol as rproto

from .card import build_text


def fmt(value: object) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(", ", ": "))
    return str(value)


def text(value: object) -> str:
    """A value the service supplied: formatted, control sequences stripped, markup escaped."""
    return escape(rproto.sanitize_server_text(fmt(value)))


#: Result keys with a rendering of their own, left out of the generic dump.
RENDERED_KEYS = frozenset({"channel", "nfc_admin_lock"})


def print_result(c: Console, result: dict[str, object]) -> None:
    c.print("\n[bold]Service result[/bold] (asserted by the service)")
    for key, value in result.items():
        if key in RENDERED_KEYS:
            continue
        if key == "steps" and isinstance(value, list):
            c.print("  steps:")
            for step in value:
                c.print(f"    {text(step)}")
            continue
        c.print(f"  {text(key)}: {text(value)}")


CHANNEL_MODES = {
    "hardened": "the card authenticates and encrypts its answers",
    "legacy": "the card's answers are not authenticated",
}


def channel(result: dict[str, object]) -> dict[str, object] | None:
    chan = result.get("channel")
    return chan if isinstance(chan, dict) else None


def print_channel(c: Console, result: dict[str, object], *, expected: bool = False) -> None:
    """The admin channel as the service reports it; ``expected`` for operations that open one."""
    chan = channel(result)
    if chan is None:
        if expected:
            c.print("  Admin channel: not reported by the service (treated as legacy)")
        return
    mode = chan.get("mode")
    mode_text = text(mode) if isinstance(mode, str) else "mode not reported"
    line = f"{text(chan.get('scp'))} level {text(chan.get('level'))}, {mode_text}"
    if isinstance(mode, str) and mode in CHANNEL_MODES:
        line += f" ({CHANNEL_MODES[mode]})"
    c.print(f"  Admin channel: {line}, as the service reports it")


def warn_channel(app: AppContext, result: dict[str, object]) -> None:
    chan = channel(result)
    if chan is None:
        return
    scp = chan.get("scp")
    if chan.get("mode") == "legacy" and isinstance(scp, str) and scp.upper() == "SCP03":
        app.out.warn(
            "the service drove this SCP03 card at the legacy channel level, so the card's "
            "answers were not authenticated; the service's log says why."
        )


def print_nfc_admin_lock(c: Console, result: dict[str, object]) -> None:
    lock = result.get("nfc_admin_lock")
    if not isinstance(lock, dict):
        return
    if lock.get("restrict_contactless_admin") is True:
        c.print("  Contactless administration: refused by the applet from now on (lock set)")
        return
    detail = f" ({text(lock['error'])})" if isinstance(lock.get("error"), str) else ""
    c.print(f"  Contactless administration: lock [red]NOT set[/red]{detail}")


def warn_nfc_admin_lock(app: AppContext, result: dict[str, object]) -> None:
    lock = result.get("nfc_admin_lock")
    if isinstance(lock, dict) and lock.get("restrict_contactless_admin") is not True:
        app.out.warn(
            "the service could not set the applet's contactless-administration lock; the "
            "applet still accepts its admin channel over the contactless interface."
        )


def print_checks(c: Console, checks: dict[str, object]) -> None:
    c.print("\n[bold]Verified locally[/bold]")
    for key, value in checks.items():
        if value is True:
            label = "[green]match[/green]"
        elif value is False:
            label = "[red]MISMATCH[/red]"
        else:
            label = "[dim]unchecked[/dim]"
        c.print(f"  {key}: {label}")


def print_header(
    c: Console, op: str, url: str, card: dict[str, object], relayed: dict[str, object]
) -> None:
    c.print(f"[bold]remote {op}[/bold]  {escape(url)}")
    c.print(f"  Reader: {escape(str(card['reader']))}")
    c.print(f"  ATR:    {card['atr']}")
    if card.get("cplc_uid"):
        c.print(f"  UID:    {card['cplc_uid']} (CPLC, read locally)")
    c.print(
        f"  Relay:  {relayed['apdus_relayed']} command(s) in "
        f"{relayed['seconds']}s, proof-of-work {relayed['pow_bits']} bits"
    )


def print_inventory(c: Console, title: str, inv: dict[str, object]) -> None:
    ssd = inv.get("piv_ssd_key_versions")
    if not isinstance(ssd, list):
        ssd_text = "absent"
    elif not ssd:
        ssd_text = "present, key versions unreadable"
    else:
        ssd_text = "present, key version(s) " + ", ".join(str(v) for v in ssd)
    objects = inv.get("piv_objects")
    objects_text = (
        ", ".join(str(o) for o in objects) if isinstance(objects, list) and objects else "none"
    )
    c.print(f"[bold]{title}[/bold] (read locally)")
    c.print(f"  PIV:                 {inv['piv_state']}")
    if inv.get("piv_build") is not None:
        c.print(f"  PIV applet build:    {escape(build_text(inv['piv_build']))}")
    c.print(f"  PIV data objects:    {objects_text}")
    c.print(f"  PIV security domain: {ssd_text}")
    c.print(f"  FIDO2:               {inv['fido_state']}")
    c.print(f"  Genuineness:         {inv['genuineness_state']}")


def clean(value: object, depth: int = 0) -> object:
    """A value from the service made safe to print: text sanitised, size bounded."""
    if isinstance(value, str):
        return rproto.sanitize_server_text(value, limit=200)
    if value is None or isinstance(value, bool | int | float):
        return value
    if depth >= 4:
        return None
    if isinstance(value, list):
        return [clean(v, depth + 1) for v in value[:64]]
    if isinstance(value, dict):
        return {
            rproto.sanitize_server_text(str(k), limit=64): clean(v, depth + 1)
            for k, v in list(value.items())[:64]
        }
    return None


def print_ping(
    c: Console,
    url: str,
    service: dict[str, object],
    available: list[str],
    others: list[str],
    skew: int | None,
) -> None:
    c.print(f"[bold]remote ping[/bold]  {escape(url)}")

    build = service.get("build")
    if isinstance(build, dict) and build.get("commit"):
        line = str(build["commit"])
        if build.get("released"):
            line += f", released {build['released']}"
        if build.get("lib"):
            line += f" (card library {build['lib']})"
    else:
        line = "not reported"
    c.print(f"  Service build:     {escape(line)}")

    c.print(f"  Operations:        {escape(', '.join(available) or 'none this tool runs')}")
    if others:
        c.print(f"                     offered, not run by this tool: {escape(', '.join(others))}")

    builds = service.get("piv_variants")
    if isinstance(builds, dict) and isinstance(builds.get("enabled"), list):
        deployed = builds.get("deployed") if isinstance(builds.get("deployed"), dict) else {}
        names = []
        for name in builds["enabled"]:
            if not isinstance(name, str):
                continue
            marks = []
            if name == builds.get("default"):
                marks.append("default")
            if isinstance(deployed, dict) and deployed.get(name) is False:
                marks.append("not installed on the service")
            names.append(f"{name} ({', '.join(marks)})" if marks else str(name))
        line = ", ".join(names) or "none"
    else:
        line = "not reported (the FIPS-mode build only)"
    c.print(f"  PIV applet builds: {escape(line)}")

    scp = service.get("scp")
    if isinstance(scp, dict):
        if scp.get("legacy_attest"):
            c.print(
                "  Key attestation on a channel that cannot authenticate the card's "
                f"answers: {escape(str(scp['legacy_attest']))}"
            )
        if isinstance(scp.get("refuse_contactless_admin"), bool):
            c.print(
                "  PIV administration over the contactless interface: "
                + ("refused" if scp["refuse_contactless_admin"] else "allowed")
            )

    if skew is not None and abs(skew) > 120:
        c.print(
            f"  [yellow]This computer's clock differs from the service's by {abs(skew)} "
            "seconds; certificate dates are checked against this computer's clock.[/yellow]"
        )


def pem_lines(pem: str) -> str:
    """A PEM from the service with each line stripped of control sequences, line breaks kept."""
    return "\n".join(
        rproto.sanitize_server_text(line, limit=128) for line in pem.strip().splitlines()
    )
