# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The plumbing every operation shares: the endpoint, the relay call, the
cross-checks, and the exit code a failed local check ends with."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

import click
from rich.markup import escape

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import protocol as proto
from cryptnox_id_cli.remote import refusal as rrefusal
from cryptnox_id_cli.remote import relay
from cryptnox_id_cli.remote.policy import ISD, PIV, PIV_SSD, RelayPolicy
from cryptnox_id_cli.transport.errors import RemoteConnectError, RemoteOperationError
from cryptnox_id_cli.transport.pcsc import is_contactless_interface

from .card import Card

FULL_TRANSCRIPT_KEY = "remote.full_transcript"
READ_ONLY = ("ping", "authenticate", "inspect")
UNVERIFIED_EXIT = 17

DOMAIN_NAMES = {ISD: "card manager", PIV_SSD: "PIV security domain", PIV: "PIV applet"}


def endpoint(op: str) -> tuple[str, bool]:
    """The service URL for this run, and whether it is the production endpoint."""
    override = os.environ.get(rchannel.URL_ENV)
    if not override:
        return rchannel.PRODUCTION_URL, True
    url = rchannel.validate_url(override, allow_insecure_loopback=True)
    if op not in READ_ONLY:
        raise RemoteConnectError(
            f"${rchannel.URL_ENV} is set; {op} runs only against the production service"
        )
    return url, False


def relay_operation(
    app: AppContext,
    ctx: click.Context,
    card: Card,
    op: str,
    params: dict[str, object],
    url: str,
    *,
    dry_run: bool = False,
    answer_kex: Callable[[proto.KexRequest], bytes] | None = None,
    stop_requested: Callable[[], bool] | None = None,
    report: relay.RelayReport | None = None,
) -> relay.RelayReport:
    slot = params.get("slot")
    policy = RelayPolicy(
        op, slot=int(str(slot), 16) if isinstance(slot, str) else None, dry_run=dry_run
    )
    if report is None:
        report = relay.RelayReport(op=op, result={})
    try:
        with rchannel.open_channel(url) as ch:
            return relay.run_operation(
                ch,
                card.conn,
                op,
                params,
                policy=policy,
                redactor=app.redactor,
                transcript=app.apdu_trace,
                unmasked_transcript=bool(ctx.meta.get(FULL_TRANSCRIPT_KEY)),
                on_log=lambda msg: app.out.note(f"service: {escape(msg)}"),
                answer_kex=answer_kex,
                stop_requested=stop_requested,
                report=report,
            )
    except RemoteOperationError as exc:
        # A recognised refusal is reworded for the card holder; the service's own
        # sentence is still shown, so nothing it said is lost.
        said = rrefusal.service_text(exc.result or {})
        if said and exc.reason != "refused":
            app.out.note(f"the service said: {escape(said)}")
        raise
    finally:
        warn_open_initialize_updates(app, policy.open_initialize_updates)
        for warning in report.warnings:
            app.out.warn(escape(warning))


def warn_open_initialize_updates(app: AppContext, open_counts: dict[str, int]) -> None:
    counts = {ctx: n for ctx, n in open_counts.items() if n}
    if not counts:
        return
    total = sum(counts.values())
    detail = ", ".join(f"{DOMAIN_NAMES.get(ctx, ctx)}: {n}" for ctx, n in counts.items())
    app.out.warn(
        f"the service left {total} INITIALIZE UPDATE{'s' if total != 1 else ''} without a "
        f"completed authentication ({detail}). On some chips each one counts toward a delay "
        "of about 24 seconds on later authentications to that security domain, until one "
        "succeeds."
    )


def cross_check(card: dict[str, object], result: dict[str, object]) -> dict[str, object]:
    """Compare what the service reports about the card with what was read locally.

    The service's field names are not fixed; each candidate is tried and the
    comparison reported as ``None`` when the service said nothing usable.
    """

    def pick(*keys: str) -> str | None:
        for key in keys:
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().upper()
        return None

    checks: dict[str, object] = {}
    reported_uid = pick("cplc_uid", "uid", "card_uid")
    local_uid = card.get("cplc_uid")
    checks["cplc_uid_matches"] = (
        None if reported_uid is None or not local_uid else reported_uid == local_uid
    )
    reported_atr = pick("atr")
    checks["atr_matches"] = None if reported_atr is None else reported_atr == card.get("atr")
    return checks


def relay_info(report: relay.RelayReport) -> dict[str, object]:
    return {
        "apdus_relayed": report.apdus_relayed,
        "seconds": round(report.seconds, 3),
        "pow_bits": report.pow_bits,
        "service_log": report.log_lines,
        "open_initialize_updates": report.open_initialize_updates,
    }


def warn_contactless_reader(app: AppContext, card: Card, *, refused: bool) -> None:
    """Advice from the reader's name; the service's gate reads the card's own interface report."""
    if is_contactless_interface(card.reader, bytes.fromhex(card.atr)):
        gate = " and refuses this operation over contactless" if refused else ""
        app.out.warn(
            "this looks like a contactless reader; the service administers the PIV "
            f"function over the contact interface only{gate}. Use a contact reader, or the "
            "contact slot of a combination reader."
        )


def exit_if_unverified(app: AppContext, checks: dict[str, object]) -> None:
    """End with code 17 when a local check failed.

    Called after the result is printed: that payload carries every check, so no
    error object follows it. A script that only looks at the exit code must not
    take a result this tool itself rejected for a success.
    """
    failed = [name for name, value in checks.items() if value is False]
    if failed:
        app.out.error(
            "local verification failed: " + ", ".join(failed) + ". The result above is the "
            "service's account; the checks named are this tool's own and did not hold."
        )
        sys.exit(UNVERIFIED_EXIT)
