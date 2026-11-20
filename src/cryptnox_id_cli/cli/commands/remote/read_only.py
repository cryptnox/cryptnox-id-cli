# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``remote authenticate`` and ``remote inspect``: key-free reads through the service."""

from __future__ import annotations

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.cli.context import AppContext

from .card import build_text, open_card, piv_build
from .render import print_channel, print_checks, print_header, print_result
from .run import cross_check, endpoint, exit_if_unverified, relay_info, relay_operation


def service_fips_flag(result: dict[str, object]) -> bool | None:
    """The applet's FIPS flag as the service read it during ``inspect``."""
    node: object = result.get("piv_applet")
    for key in ("applet", "status"):
        node = node.get(key) if isinstance(node, dict) else None
    flag = node.get("fips_mode") if isinstance(node, dict) else None
    return flag if isinstance(flag, bool) else None


def run_read_only(ctx: click.Context, op: str) -> None:
    app: AppContext = ctx.obj
    url, production = endpoint(op)
    card = open_card(app)
    build: dict[str, object] | None = None
    try:
        if not production:
            app.out.warn(f"connecting to a non-production endpoint: {url}")
        app.out.note(f"remote {op} via {url}")
        report = relay_operation(app, ctx, card, op, {}, url)
        if op == "inspect":
            build = piv_build(card.session)
    finally:
        card.conn.disconnect()

    card_info = card.to_dict()
    checks = cross_check(card_info, report.result)
    relayed = relay_info(report)
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "card": card_info,
        "result": report.result,
        "verified_locally": checks,
        "relay": relayed,
    }
    if op == "inspect":
        # The service reads the applet's build through the relay, unauthenticated; the
        # same read done here is the one to trust, and the two must agree.
        reported = service_fips_flag(report.result)
        local = build.get("fips_mode") if build else None
        payload["piv_build"] = build
        checks["piv_build_matches"] = (
            None if reported is None or not isinstance(local, bool) else reported == local
        )

    def human(c: Console) -> None:
        print_header(c, op, url, card_info, relayed)
        print_channel(c, report.result)
        print_result(c, report.result)
        if op == "inspect":
            c.print(f"\n[bold]PIV applet build[/bold] (read locally): {escape(build_text(build))}")
        print_checks(c, checks)

    app.out.result(payload, human)
    exit_if_unverified(app, checks)


@click.command("authenticate")
@click.pass_context
def authenticate(ctx: click.Context) -> None:
    """Identify the card to the service: ATR and CPLC UID, nothing else.

    Key-free on both sides. The relay policy allows only card-manager reads.
    """
    run_read_only(ctx, "authenticate")


@click.command("inspect")
@click.pass_context
def inspect(ctx: click.Context) -> None:
    """Probe the PIV function through the service without changing anything.

    Reports whether the PIV applet and its security domain are present and
    which key versions they carry. Key-free: the relay policy refuses any
    authentication attempt.
    """
    run_read_only(ctx, "inspect")
