"""``remote`` — operations carried out by the Cryptnox remote PIV service.

The card stays in the local reader. The service holds the keys that make a card
genuine and drives the operation over a relayed command channel; this tool
relays what the service asks for, under a fail-closed policy, and shows the
outcome. What the service asserts and what this tool verified locally are kept
apart in the output.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.cli.commands.info import _read_cplc
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import relay
from cryptnox_id_cli.remote.policy import RelayPolicy
from cryptnox_id_cli.transport.errors import RemoteConnectError
from cryptnox_id_cli.transport.pcsc import connect, pick_reader

_FULL_TRANSCRIPT_KEY = "remote.full_transcript"


@click.group("remote")
@click.option(
    "--full-transcript",
    is_flag=True,
    help=(
        "Write relayed commands to --apdu-log and --verbose without the extra masking "
        "the relay applies by default. The standard secret masking still applies."
    ),
)
@click.pass_context
def command(ctx: click.Context, full_transcript: bool) -> None:
    """Run operations through the Cryptnox remote PIV service.

    Every command opens the local reader, connects to the service over TLS,
    answers a small proof-of-work, and relays the commands the service sends to
    the card. Only the PIV function and its security domains are reachable; the
    other card functions are fenced off by the relay policy.
    """
    ctx.meta[_FULL_TRANSCRIPT_KEY] = full_transcript


def _endpoint(op: str) -> tuple[str, bool]:
    """The service URL for this run, and whether it is the production endpoint."""
    override = os.environ.get(rchannel.URL_ENV)
    if not override:
        return rchannel.PRODUCTION_URL, True
    url = rchannel.validate_url(override, allow_insecure_loopback=True)
    if op not in ("authenticate", "inspect"):
        raise RemoteConnectError(
            f"${rchannel.URL_ENV} is set; {op} runs only against the production service"
        )
    return url, False


def _run(app: AppContext, ctx: click.Context, op: str, params: dict[str, object]) -> None:
    """Open the card, run one operation through the service, render the outcome."""
    url, production = _endpoint(op)
    reader = pick_reader(app.reader)
    app.resolved_reader = reader
    conn = connect(reader)
    try:
        session = app.make_session(conn, reader_name=reader)
        atr = session.atr
        cplc = _read_cplc(session)  # leaves the card manager selected, as the policy assumes
        card: dict[str, object] = {
            "reader": reader,
            "atr": atr.hex().upper(),
            "cplc_uid": cplc["uid"] if cplc else None,
            "ic_serial": cplc["ic_serial"] if cplc else None,
        }

        if not production:
            app.out.warn(f"connecting to a non-production endpoint: {url}")
        app.out.note(f"remote {op} via {url}")

        with rchannel.open_channel(url) as ch:
            report = relay.run_operation(
                ch,
                conn,
                op,
                params,
                policy=RelayPolicy(op),
                redactor=app.redactor,
                transcript=app.apdu_trace,
                unmasked_transcript=bool(ctx.meta.get(_FULL_TRANSCRIPT_KEY)),
                on_log=lambda msg: app.out.note(f"service: {escape(msg)}"),
            )
    finally:
        conn.disconnect()

    checks = _cross_check(card, report.result)
    relay_info: dict[str, object] = {
        "apdus_relayed": report.apdus_relayed,
        "seconds": round(report.seconds, 3),
        "pow_bits": report.pow_bits,
        "service_log": report.log_lines,
    }
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "card": card,
        "result": report.result,
        "verified_locally": checks,
        "relay": relay_info,
    }
    app.out.result(payload, _human(op, url, card, report.result, checks, relay_info))


def _cross_check(card: dict[str, object], result: dict[str, object]) -> dict[str, object]:
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


def _human(
    op: str,
    url: str,
    card: dict[str, object],
    result: dict[str, object],
    checks: dict[str, object],
    relay_info: dict[str, object],
) -> Callable[[Console], None]:
    def render(c: Console) -> None:
        c.print(f"[bold]remote {op}[/bold]  {escape(url)}")
        c.print(f"  Reader: {escape(str(card['reader']))}")
        c.print(f"  ATR:    {card['atr']}")
        if card.get("cplc_uid"):
            c.print(f"  UID:    {card['cplc_uid']} (CPLC, read locally)")
        c.print(
            f"  Relay:  {relay_info['apdus_relayed']} command(s) in "
            f"{relay_info['seconds']}s, proof-of-work {relay_info['pow_bits']} bits"
        )

        c.print("\n[bold]Service result[/bold] (asserted by the service)")
        for key, value in result.items():
            c.print(f"  {escape(str(key))}: {escape(_fmt(value))}")

        c.print("\n[bold]Verified locally[/bold]")
        for key, value in checks.items():
            if value is True:
                label = "[green]match[/green]"
            elif value is False:
                label = "[red]MISMATCH[/red]"
            else:
                label = "[dim]not reported by the service[/dim]"
            c.print(f"  {key}: {label}")

    return render


def _fmt(value: object) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(", ", ": "))
    return str(value)


@command.command("authenticate")
@click.pass_context
def authenticate(ctx: click.Context) -> None:
    """Identify the card to the service: ATR and CPLC UID, nothing else.

    Key-free on both sides. The relay policy allows only card-manager reads.
    """
    _run(ctx.obj, ctx, "authenticate", {})


@command.command("inspect")
@click.pass_context
def inspect(ctx: click.Context) -> None:
    """Probe the PIV function through the service without changing anything.

    Reports whether the PIV applet and its security domain are present and
    which key versions they carry. Key-free: the relay policy refuses any
    authentication attempt.
    """
    _run(ctx.obj, ctx, "inspect", {})
