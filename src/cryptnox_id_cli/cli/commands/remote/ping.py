# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``remote ping``: what the service runs and offers, with no card involved."""

from __future__ import annotations

import math
import time

import click

from cryptnox_id_cli import CLI_NAME, __version__
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import protocol as rproto
from cryptnox_id_cli.remote import relay

from .render import clean, print_ping
from .run import endpoint

#: Operations of the service this tool runs, by command name. The service may
#: offer others; those are reserved to Cryptnox's own tooling.
CLIENT_OPS: tuple[str, ...] = tuple(op for op in rproto.OPS if op != "ping")

#: Fields of the service's answer that concern Cryptnox's factory tooling only.
PING_HIDDEN = frozenset({"ok", "op", "token_valid", "token_label"})


@click.command("ping")
@click.pass_context
def ping(ctx: click.Context) -> None:
    """Ask the service what it runs and what it offers. No card is needed.

    Shows the service's build, the operations it serves, the PIV applet builds
    it can install and its secure-channel policy. The reader is not opened,
    nothing is sent to a card, and the call does not count toward a card's
    operation limit.
    """
    app: AppContext = ctx.obj
    url, production = endpoint("ping")
    if not production:
        app.out.warn(f"connecting to a non-production endpoint: {url}")
    with rchannel.open_channel(url) as ch:
        answer = relay.ping(ch)

    cleaned = clean({k: v for k, v in answer.items() if k not in PING_HIDDEN})
    service: dict[str, object] = cleaned if isinstance(cleaned, dict) else {}
    ops = service.get("ops")
    offered = sorted(str(o) for o in ops) if isinstance(ops, list) else []
    server_time = answer.get("server_time")
    skew = (
        round(time.time() - server_time)
        if isinstance(server_time, int | float)
        and not isinstance(server_time, bool)
        and math.isfinite(server_time)
        else None
    )
    available = [op for op in CLIENT_OPS if op in offered]
    others = [op for op in offered if op not in CLIENT_OPS]
    payload: dict[str, object] = {
        "op": "ping",
        "endpoint": url,
        "client": {"name": CLI_NAME, "version": __version__, "operations": list(CLIENT_OPS)},
        "service": service,
        "operations_available": available,
        "operations_not_in_this_client": others,
        "clock_skew_seconds": skew,
    }
    app.out.result(payload, lambda c: print_ping(c, url, service, available, others, skew))
