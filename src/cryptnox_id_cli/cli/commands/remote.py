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
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli import CLI_NAME, __version__
from cryptnox_id_cli.applets.piv import inventory as inventory_mod
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.cli.commands.info import _read_cplc
from cryptnox_id_cli.cli.commands.piv import SLOT_CERT_OBJECT, _read_cert_der
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import attest_verify as av
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import protocol as rproto
from cryptnox_id_cli.remote import refusal as rrefusal
from cryptnox_id_cli.remote import relay
from cryptnox_id_cli.remote.policy import ISD, PIV, PIV_SSD, PIV_SSD_AID, RelayPolicy
from cryptnox_id_cli.state.detector import StateDetector
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import (
    CryptnoxError,
    RemoteConnectError,
    RemoteError,
    RemoteOperationError,
)
from cryptnox_id_cli.transport.pcsc import CardSession, RawConnection
from cryptnox_id_cli.util import tlv

_FULL_TRANSCRIPT_KEY = "remote.full_transcript"

#: Phrases typed to confirm the irreversible operations interactively.
RESET_PHRASE = "RESET-PIV"
DEV_RESET_PHRASE = "DEV-RESET-PIV"

_READ_ONLY = ("ping", "authenticate", "inspect")

#: PIV applet builds the service can install, by the name its protocol uses
#: (``piv_variant``). Both are built from the same source and carry the same
#: applet and package identifiers; the applet reports which one it is.
PIV_BUILDS = ("fips", "fipsoff")
DEFAULT_PIV_BUILD = "fips"
_BUILD_NAMES = {"fips": "FIPS-mode build", "fipsoff": "build with FIPS mode off"}


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


# --------------------------------------------------------------------------- #
# Shared plumbing                                                             #
# --------------------------------------------------------------------------- #
def _endpoint(op: str) -> tuple[str, bool]:
    """The service URL for this run, and whether it is the production endpoint."""
    override = os.environ.get(rchannel.URL_ENV)
    if not override:
        return rchannel.PRODUCTION_URL, True
    url = rchannel.validate_url(override, allow_insecure_loopback=True)
    if op not in _READ_ONLY:
        raise RemoteConnectError(
            f"${rchannel.URL_ENV} is set; {op} runs only against the production service"
        )
    return url, False


@dataclass
class _Card:
    reader: str | None
    conn: RawConnection
    session: CardSession
    atr: str
    cplc_uid: str | None
    ic_serial: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "reader": self.reader,
            "atr": self.atr,
            "cplc_uid": self.cplc_uid,
            "ic_serial": self.ic_serial,
        }


def _open_card(app: AppContext) -> _Card:
    """Open the reader and read the card's identity. Leaves the card manager selected."""
    session = app.open_session()
    cplc = _read_cplc(session)
    return _Card(
        reader=session.reader_name or app.resolved_reader,
        conn=session.raw_connection,
        session=session,
        atr=session.atr.hex().upper(),
        cplc_uid=cplc["uid"] if cplc else None,
        ic_serial=cplc["ic_serial"] if cplc else None,
    )


def _ssd_key_versions(session: CardSession) -> list[int] | None:
    """Key versions the PIV security domain holds, read key-free.

    ``None`` when the security domain is absent. The key information template
    lists one ``C0`` entry per key: id, version, type, length.
    """
    selected = session.transmit(APDU(0x00, 0xA4, 0x04, 0x00, data=PIV_SSD_AID, le=256))
    if not selected.ok:
        return None
    info = session.transmit(APDU(0x80, 0xCA, 0x00, 0xE0, le=256))
    if not info.ok:
        return []
    versions: set[int] = set()
    for node in tlv.parse(info.data):
        if node.tag != 0xE0:
            continue
        for entry in tlv.parse(node.value, recurse=False):
            if entry.tag == 0xC0 and len(entry.value) >= 2:
                versions.add(entry.value[1])
    return sorted(versions)


def _piv_build(session: CardSession) -> dict[str, object] | None:
    """The PIV applet's own account of its build, read key-free.

    ``None`` when there is no applet to ask or it does not answer the vendor
    reads. ``fips_mode`` is the applet's FIPS flag: true for the FIPS-mode
    build, false for the build with FIPS mode off. Leaves the PIV applet
    selected; callers re-read the CPLC when the card manager must be selected.
    """
    piv = PivApplet(session)
    try:
        piv.select()
        version = inventory_mod.read_version(piv)
        status = inventory_mod.read_status(piv)
    except CryptnoxError:
        return None
    if version is None and status is None:
        return None
    return {
        "label": version.label if version else None,
        "version": version.version if version else None,
        "fips_mode": status.fips_mode if status else None,
    }


def _build_matches(requested: str, build: object) -> bool | None:
    """Whether the applet on the card is the requested build. ``None`` when unreadable."""
    if not isinstance(build, dict) or not isinstance(build.get("fips_mode"), bool):
        return None
    return build["fips_mode"] == (requested == "fips")


def _build_text(build: object) -> str:
    if not isinstance(build, dict):
        return "not readable"
    flag = build.get("fips_mode")
    name = "not reported" if flag is None else _BUILD_NAMES["fips" if flag else "fipsoff"]
    label = " ".join(str(v) for v in (build.get("label"), build.get("version")) if v)
    return f"{name} ({label})" if label else name


def _inventory(card: _Card) -> dict[str, object]:
    """What the PIV function and its neighbours hold right now, read locally.

    Ends by re-reading the CPLC so the card manager is the selected applet
    again, which is what the relay policy assumes at the start of an operation.
    """
    state = StateDetector(
        card.session, probe_fido=True, probe_desfire=False, probe_genuine=True
    ).detect()
    build = _piv_build(card.session)
    ssd = _ssd_key_versions(card.session)
    _read_cplc(card.session)
    return {
        "piv_state": state.piv.label,
        "piv_build": build,
        "piv_objects": sorted(name for name, present in state.piv_objects.items() if present),
        "piv_ssd_key_versions": ssd,
        "fido_state": state.fido.label,
        "genuineness_state": state.genuine.label,
    }


def _relay(
    app: AppContext, ctx: click.Context, card: _Card, op: str, params: dict[str, object], url: str
) -> relay.RelayReport:
    slot = params.get("slot")
    policy = RelayPolicy(op, slot=int(str(slot), 16) if isinstance(slot, str) else None)
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
                unmasked_transcript=bool(ctx.meta.get(_FULL_TRANSCRIPT_KEY)),
                on_log=lambda msg: app.out.note(f"service: {escape(msg)}"),
            )
    except RemoteOperationError as exc:
        # A recognised refusal is reworded for the card holder; the service's own
        # sentence is still shown, so nothing it said is lost.
        said = rrefusal.service_text(exc.result or {})
        if said and exc.reason != "refused":
            app.out.note(f"the service said: {escape(said)}")
        raise
    finally:
        _warn_open_initialize_updates(app, policy.open_initialize_updates)


_DOMAIN_NAMES = {ISD: "card manager", PIV_SSD: "PIV security domain", PIV: "PIV applet"}


def _warn_open_initialize_updates(app: AppContext, open_counts: dict[str, int]) -> None:
    counts = {ctx: n for ctx, n in open_counts.items() if n}
    if not counts:
        return
    total = sum(counts.values())
    detail = ", ".join(f"{_DOMAIN_NAMES.get(ctx, ctx)}: {n}" for ctx, n in counts.items())
    app.out.warn(
        f"the service left {total} INITIALIZE UPDATE{'s' if total != 1 else ''} without a "
        f"completed authentication ({detail}). On some chips each one counts toward a delay "
        "of about 24 seconds on later authentications to that security domain, until one "
        "succeeds."
    )


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


def _relay_info(report: relay.RelayReport) -> dict[str, object]:
    return {
        "apdus_relayed": report.apdus_relayed,
        "seconds": round(report.seconds, 3),
        "pow_bits": report.pow_bits,
        "service_log": report.log_lines,
        "open_initialize_updates": report.open_initialize_updates,
    }


def _fmt(value: object) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(", ", ": "))
    return str(value)


def _print_result(c: Console, result: dict[str, object]) -> None:
    c.print("\n[bold]Service result[/bold] (asserted by the service)")
    for key, value in result.items():
        if key == "steps" and isinstance(value, list):
            c.print("  steps:")
            for step in value:
                c.print(f"    {escape(_fmt(step))}")
            continue
        c.print(f"  {escape(str(key))}: {escape(_fmt(value))}")


def _print_checks(c: Console, checks: dict[str, object]) -> None:
    c.print("\n[bold]Verified locally[/bold]")
    for key, value in checks.items():
        if value is True:
            label = "[green]match[/green]"
        elif value is False:
            label = "[red]MISMATCH[/red]"
        else:
            label = "[dim]not reported by the service[/dim]"
        c.print(f"  {key}: {label}")


def _print_header(
    c: Console, op: str, url: str, card: dict[str, object], relay_info: dict[str, object]
) -> None:
    c.print(f"[bold]remote {op}[/bold]  {escape(url)}")
    c.print(f"  Reader: {escape(str(card['reader']))}")
    c.print(f"  ATR:    {card['atr']}")
    if card.get("cplc_uid"):
        c.print(f"  UID:    {card['cplc_uid']} (CPLC, read locally)")
    c.print(
        f"  Relay:  {relay_info['apdus_relayed']} command(s) in "
        f"{relay_info['seconds']}s, proof-of-work {relay_info['pow_bits']} bits"
    )


def _print_inventory(c: Console, title: str, inv: dict[str, object]) -> None:
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
        c.print(f"  PIV applet build:    {escape(_build_text(inv['piv_build']))}")
    c.print(f"  PIV data objects:    {objects_text}")
    c.print(f"  PIV security domain: {ssd_text}")
    c.print(f"  FIDO2:               {inv['fido_state']}")
    c.print(f"  Genuineness:         {inv['genuineness_state']}")


# --------------------------------------------------------------------------- #
# The service itself                                                          #
# --------------------------------------------------------------------------- #
#: Operations of the service this tool runs, by command name. The service may
#: offer others; those are reserved to Cryptnox's own tooling.
_CLIENT_OPS: tuple[str, ...] = tuple(op for op in rproto.OPS if op != "ping")

#: Fields of the service's answer that concern Cryptnox's factory tooling only.
_PING_HIDDEN = frozenset({"ok", "op", "token_valid", "token_label"})


def _clean(value: object, depth: int = 0) -> object:
    """A value from the service made safe to print: text sanitised, size bounded."""
    if isinstance(value, str):
        return rproto.sanitize_server_text(value, limit=200)
    if value is None or isinstance(value, bool | int | float):
        return value
    if depth >= 4:
        return None
    if isinstance(value, list):
        return [_clean(v, depth + 1) for v in value[:64]]
    if isinstance(value, dict):
        return {
            rproto.sanitize_server_text(str(k), limit=64): _clean(v, depth + 1)
            for k, v in list(value.items())[:64]
        }
    return None


def _print_ping(c: Console, url: str, payload: dict[str, object]) -> None:
    service = payload["service"]
    assert isinstance(service, dict)
    c.print(f"[bold]remote ping[/bold]  {escape(url)}")

    build = service.get("build")
    if isinstance(build, dict) and build.get("commit"):
        text = str(build["commit"])
        if build.get("released"):
            text += f", released {build['released']}"
        if build.get("lib"):
            text += f" (card library {build['lib']})"
    else:
        text = "not reported"
    c.print(f"  Service build:     {escape(text)}")

    available = payload["operations_available"]
    others = payload["operations_not_in_this_client"]
    assert isinstance(available, list) and isinstance(others, list)
    c.print(f"  Operations:        {escape(', '.join(available) or 'none this tool runs')}")
    if others:
        c.print(f"                     offered, not run by this tool: {escape(', '.join(others))}")

    builds = service.get("piv_variants")
    if isinstance(builds, dict) and isinstance(builds.get("enabled"), list):
        deployed = builds.get("deployed") if isinstance(builds.get("deployed"), dict) else {}
        names = []
        for name in builds["enabled"]:
            marks = []
            if name == builds.get("default"):
                marks.append("default")
            if isinstance(deployed, dict) and deployed.get(name) is False:
                marks.append("not installed on the service")
            names.append(f"{name} ({', '.join(marks)})" if marks else str(name))
        text = ", ".join(names) or "none"
    else:
        text = "not reported (the FIPS-mode build only)"
    c.print(f"  PIV applet builds: {escape(text)}")

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

    skew = payload.get("clock_skew_seconds")
    if isinstance(skew, int) and abs(skew) > 120:
        c.print(
            f"  [yellow]This computer's clock differs from the service's by {abs(skew)} "
            "seconds; certificate dates are checked against this computer's clock.[/yellow]"
        )


@command.command("ping")
@click.pass_context
def ping(ctx: click.Context) -> None:
    """Ask the service what it runs and what it offers. No card is needed.

    Shows the service's build, the operations it serves, the PIV applet builds
    it can install and its secure-channel policy. The reader is not opened,
    nothing is sent to a card, and the call does not count toward a card's
    operation limit.
    """
    app: AppContext = ctx.obj
    url, production = _endpoint("ping")
    if not production:
        app.out.warn(f"connecting to a non-production endpoint: {url}")
    with rchannel.open_channel(url) as ch:
        answer = relay.ping(ch)

    service = _clean({k: v for k, v in answer.items() if k not in _PING_HIDDEN})
    assert isinstance(service, dict)
    ops = service.get("ops")
    offered = sorted(str(o) for o in ops) if isinstance(ops, list) else []
    server_time = answer.get("server_time")
    skew = (
        round(time.time() - server_time)
        if isinstance(server_time, int | float) and not isinstance(server_time, bool)
        else None
    )
    payload: dict[str, object] = {
        "op": "ping",
        "endpoint": url,
        "client": {"name": CLI_NAME, "version": __version__, "operations": list(_CLIENT_OPS)},
        "service": service,
        "operations_available": [op for op in _CLIENT_OPS if op in offered],
        "operations_not_in_this_client": [op for op in offered if op not in _CLIENT_OPS],
        "clock_skew_seconds": skew,
    }
    app.out.result(payload, lambda c: _print_ping(c, url, payload))


# --------------------------------------------------------------------------- #
# Read-only operations                                                        #
# --------------------------------------------------------------------------- #
def _service_fips_flag(result: dict[str, object]) -> bool | None:
    """The applet's FIPS flag as the service read it during ``inspect``."""
    node: object = result.get("piv_applet")
    for key in ("applet", "status"):
        node = node.get(key) if isinstance(node, dict) else None
    flag = node.get("fips_mode") if isinstance(node, dict) else None
    return flag if isinstance(flag, bool) else None


def _run_read_only(ctx: click.Context, op: str) -> None:
    app: AppContext = ctx.obj
    url, production = _endpoint(op)
    card = _open_card(app)
    build: dict[str, object] | None = None
    try:
        if not production:
            app.out.warn(f"connecting to a non-production endpoint: {url}")
        app.out.note(f"remote {op} via {url}")
        report = _relay(app, ctx, card, op, {}, url)
        if op == "inspect":
            build = _piv_build(card.session)
    finally:
        card.conn.disconnect()

    card_info = card.to_dict()
    checks = _cross_check(card_info, report.result)
    relay_info = _relay_info(report)
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "card": card_info,
        "result": report.result,
        "verified_locally": checks,
        "relay": relay_info,
    }
    if op == "inspect":
        # The service reads the applet's build through the relay, unauthenticated; the
        # same read done here is the one to trust, and the two must agree.
        reported = _service_fips_flag(report.result)
        local = build.get("fips_mode") if build else None
        payload["piv_build"] = build
        checks["piv_build_matches"] = (
            None if reported is None or not isinstance(local, bool) else reported == local
        )

    def human(c: Console) -> None:
        _print_header(c, op, url, card_info, relay_info)
        _print_result(c, report.result)
        if op == "inspect":
            c.print(f"\n[bold]PIV applet build[/bold] (read locally): {escape(_build_text(build))}")
        _print_checks(c, checks)

    app.out.result(payload, human)


@command.command("authenticate")
@click.pass_context
def authenticate(ctx: click.Context) -> None:
    """Identify the card to the service: ATR and CPLC UID, nothing else.

    Key-free on both sides. The relay policy allows only card-manager reads.
    """
    _run_read_only(ctx, "authenticate")


@command.command("inspect")
@click.pass_context
def inspect(ctx: click.Context) -> None:
    """Probe the PIV function through the service without changing anything.

    Reports whether the PIV applet and its security domain are present and
    which key versions they carry. Key-free: the relay policy refuses any
    authentication attempt.
    """
    _run_read_only(ctx, "inspect")


# --------------------------------------------------------------------------- #
# Destructive operations                                                      #
# --------------------------------------------------------------------------- #
_RESET_DEFAULT_KEYS_HELP = (
    "Reserved to Cryptnox: have the service authenticate with the publicly known "
    "GlobalPlatform default key and make the card genuine. The service refuses it "
    "without a Cryptnox factory token and leaves the card untouched."
)
_DEV_RESET_DEFAULT_KEYS_HELP = (
    "Have the card prove it is genuine with key version 2 of its PIV security domain "
    "instead of its card-manager key."
)


_PIV_VARIANT_HELP = (
    "PIV applet build the service installs: fips, the FIPS-mode build (default), or "
    "fipsoff, the same applet with FIPS mode off."
)
_FIPS_OFF_HELP = "Short for --piv-variant fipsoff."
_FIPS_OFF_MEANS = (
    "It accepts pre-personalization profiles the FIPS-mode build refuses (a PIN shorter "
    "than 6 digits, more than 15 retries, a PIN usable over the contactless interface "
    "without secure messaging) and skips the FIPS power-up self-tests. Keys, algorithms "
    "and commands are the same."
)


def _resolve_piv_build(piv_variant: str | None, fips_off: bool) -> str:
    """The build to request from ``--piv-variant`` and ``--fips-off``."""
    if fips_off and piv_variant is not None and piv_variant.lower() != "fipsoff":
        raise click.UsageError("--fips-off and --piv-variant fips contradict each other.")
    if fips_off:
        return "fipsoff"
    return (piv_variant or DEFAULT_PIV_BUILD).lower()


def _service_offers_build(url: str, build: str) -> bool | None:
    """Whether the service says it can install this build; ``None`` when it does not say.

    Asked before a destructive operation, so a build the service does not offer
    is refused here instead of costing one of the card's operations.
    """
    try:
        with rchannel.open_channel(url) as ch:
            answer = relay.ping(ch)
    except RemoteError:
        return None
    offered = answer.get("piv_variants")
    if not isinstance(offered, dict) or not isinstance(offered.get("enabled"), list):
        return None
    if build not in offered["enabled"]:
        return False
    deployed = offered.get("deployed")
    return not (isinstance(deployed, dict) and deployed.get(build) is False)


def _confirm_destructive(
    app: AppContext,
    op: str,
    phrase: str,
    understood: bool,
    card: _Card,
    default_keys: bool,
    piv_build: str = DEFAULT_PIV_BUILD,
) -> dict[str, object]:
    """Show what is about to be destroyed and obtain consent. Returns the inventory."""
    before = _inventory(card)
    app.out.warn(
        f"remote {op} wipes the PIV function on card {card.cplc_uid or card.atr}: the "
        "applet, every key and certificate in it, and its security domain are deleted and "
        "reinstalled. This cannot be undone."
    )
    if piv_build == "fipsoff":
        app.out.warn(
            "the PIV applet is reinstalled as the build with FIPS mode off. "
            f"{_FIPS_OFF_MEANS} `remote reset` without the option installs the FIPS-mode "
            "build again."
        )
    elif _build_matches("fipsoff", before.get("piv_build")):
        app.out.note(
            "the card carries the PIV applet build with FIPS mode off; this operation "
            "installs the FIPS-mode build."
        )
    if op == "dev-reset":
        app.out.warn(
            "dev-reset leaves the card manager and the PIV security domain on the PUBLIC "
            "default key: anyone with a reader can then install or delete applets, "
            "including the wallet. Only Cryptnox can make the card genuine again."
        )
    elif default_keys:
        app.out.warn(
            "--default-keys: the service refuses this without a Cryptnox factory token and "
            "leaves the card untouched. To have a card on the default key re-provisioned, "
            "contact Cryptnox support."
        )
    if not app.json:
        _print_inventory(app.out.console, "Before", before)
    if not understood:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                f"remote {op} needs --i-understand-this-is-irreversible non-interactively."
            )
        if click.prompt(f"Type {phrase} to continue") != phrase:
            raise click.Abort()
    return before


def _run_destructive(
    ctx: click.Context,
    op: str,
    *,
    default_keys: bool,
    understood: bool,
    phrase: str,
    piv_build: str = DEFAULT_PIV_BUILD,
) -> None:
    app: AppContext = ctx.obj
    url, _production = _endpoint(op)  # refuses any override for these operations
    # Sent explicitly either way, so behaviour never depends on the service's own default.
    params: dict[str, object] = {"fused": not default_keys, "piv_variant": piv_build}
    if piv_build != DEFAULT_PIV_BUILD and _service_offers_build(url, piv_build) is False:
        raise CryptnoxError(
            f"the service does not offer the PIV applet {_BUILD_NAMES[piv_build]} at the "
            "moment (`remote ping` lists what it offers). Nothing was sent to the card."
        )

    card = _open_card(app)
    try:
        before = _confirm_destructive(app, op, phrase, understood, card, default_keys, piv_build)
        app.out.note(f"remote {op} via {url}")
        report = _relay(app, ctx, card, op, params, url)
        after = _inventory(card)
    finally:
        card.conn.disconnect()

    card_info = card.to_dict()
    checks = _cross_check(card_info, report.result)
    checks["piv_present_after"] = after["piv_state"] not in ("PivNotPresent", "PivUnknown")
    ssd_after = after.get("piv_ssd_key_versions")
    checks["piv_ssd_present_after"] = ssd_after is not None
    # The applet says which build it is; the service's word alone is not the check.
    checks["piv_build_matches"] = _build_matches(piv_build, after.get("piv_build"))
    if checks["piv_build_matches"] is False:
        app.out.warn(
            f"the card does not carry the requested PIV applet {_BUILD_NAMES[piv_build]}: "
            f"it reports {_build_text(after.get('piv_build'))}."
        )
    relay_info = _relay_info(report)
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "fused": not default_keys,
        "piv_variant": piv_build,
        "card": card_info,
        "before": before,
        "result": report.result,
        "after": after,
        "verified_locally": checks,
        "relay": relay_info,
    }

    def human(c: Console) -> None:
        _print_header(c, op, url, card_info, relay_info)
        _print_result(c, report.result)
        c.print()
        _print_inventory(c, "After", after)
        _print_checks(c, checks)

    app.out.result(payload, human)


def _piv_build_options(fn):  # noqa: ANN001, ANN202 - a click decorator stack
    fn = click.option("--fips-off", "fips_off", is_flag=True, help=_FIPS_OFF_HELP)(fn)
    return click.option(
        "--piv-variant",
        "piv_variant",
        type=click.Choice(PIV_BUILDS, case_sensitive=False),
        default=None,
        help=_PIV_VARIANT_HELP,
    )(fn)


@command.command("reset")
@click.option("--default-keys", "default_keys", is_flag=True, help=_RESET_DEFAULT_KEYS_HELP)
@_piv_build_options
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.pass_context
def reset(
    ctx: click.Context,
    default_keys: bool,
    piv_variant: str | None,
    fips_off: bool,
    understood: bool,
) -> None:
    """IRREVERSIBLY wipe and reinstall the PIV function through the service.

    The service deletes the PIV applet, its package and its security domain,
    reinstalls the applet, recreates the security domain and loads the card's
    keys, so the card is genuine and remotely manageable afterwards. Every PIV
    key and certificate is destroyed. The other card functions are outside the
    operation.

    The applet is reinstalled as the FIPS-mode build unless --fips-off (or
    --piv-variant fipsoff) asks for the build with FIPS mode off. Afterwards
    the applet itself is asked which build it is, and the answer is reported
    under "Verified locally".
    """
    _run_destructive(
        ctx,
        "reset",
        default_keys=default_keys,
        understood=understood,
        phrase=RESET_PHRASE,
        piv_build=_resolve_piv_build(piv_variant, fips_off),
    )


@command.command("dev-reset")
@click.option("--default-keys", "default_keys", is_flag=True, help=_DEV_RESET_DEFAULT_KEYS_HELP)
@_piv_build_options
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.pass_context
def dev_reset(
    ctx: click.Context,
    default_keys: bool,
    piv_variant: str | None,
    fips_off: bool,
    understood: bool,
) -> None:
    """IRREVERSIBLY wipe the PIV function and leave the card on the public default keys.

    For development cards only. Before anything is deleted, the card proves it
    is genuine with one of its own keys; a card that cannot is refused untouched.
    Afterwards the card manager and the PIV security domain are on the publicly
    documented GlobalPlatform key, so the PIV function can be pre-personalized
    and personalized locally. Only Cryptnox can make the card genuine again.

    --fips-off (or --piv-variant fipsoff) reinstalls the applet as the build
    with FIPS mode off instead of the FIPS-mode build.
    """
    _run_destructive(
        ctx,
        "dev-reset",
        default_keys=default_keys,
        understood=understood,
        phrase=DEV_RESET_PHRASE,
        piv_build=_resolve_piv_build(piv_variant, fips_off),
    )


# --------------------------------------------------------------------------- #
# Key attestation                                                             #
# --------------------------------------------------------------------------- #
ATTEST_ALGORITHMS = ("ECCP256", "ECCP384", "RSA2048", "RSA3072", "RSA4096")
ATTESTATION_CONTAINER = "attestation-cert"  # 5FC120, the one container the service writes


def _parse_slot(value: str) -> int:
    try:
        slot = int(value, 16)
    except ValueError:
        raise click.BadParameter(f"not a hex slot: {value!r}", param_hint="--slot") from None
    if slot not in (0x9A, 0x9C, 0x9D, 0x9E) and not 0x82 <= slot <= 0x95:
        raise click.BadParameter(
            "slot must be 9A, 9C, 9D, 9E or a retired slot 82 to 95", param_hint="--slot"
        )
    return slot


def _read_certificates(card: _Card, slot: int) -> tuple[bytes | None, bytes | None]:
    """The slot's certificate and the attestation container, read locally.

    Leaves the card manager selected afterwards.
    """
    piv = PivApplet(card.session)
    slot_cert = attestation = None
    try:
        piv.select()
        slot_object = SLOT_CERT_OBJECT.get(slot)
        slot_cert = _read_cert_der(piv, slot_object) if slot_object else None
        attestation = _read_cert_der(piv, ATTESTATION_CONTAINER)
    except CryptnoxError:
        # An applet that is absent, unselectable or refusing the read simply has
        # no certificate to report; the operation goes ahead either way.
        pass
    _read_cplc(card.session)
    return slot_cert, attestation


@command.command("attest")
@click.option("--slot", default="9C", show_default=True, help="Slot to generate the key in.")
@click.option(
    "--algorithm",
    default="ECCP256",
    show_default=True,
    type=click.Choice(ATTEST_ALGORITHMS, case_sensitive=False),
    help="Key algorithm.",
)
@click.option(
    "--ca-obj",
    default=None,
    hidden=True,
    help="No longer used: the service signs key attestations with one fixed CA key.",
)
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write the leaf PEM here.")
@click.pass_context
def attest(
    ctx: click.Context, slot: str, algorithm: str, ca_obj: str | None, out_: str | None
) -> None:
    """Generate a key on the card through the service and receive its attestation.

    The service generates the key in the slot, signs a key-attestation certificate
    for it and stores that certificate in the card's attestation container. The
    slot's previous key and the container's previous certificate are replaced.
    Afterwards the certificate is verified locally: chain to the pinned anchors,
    subject serial number against the card's CPLC UID, attested slot against the
    request, trust model, and the certified key against the certificate read
    back from the card. That the key was generated on the card is the service's
    claim; the relay cannot witness it.
    """
    app: AppContext = ctx.obj
    op = "attest"
    slot_ref = _parse_slot(slot)
    slot_hex = f"{slot_ref:02X}"
    url, _production = _endpoint(op)
    params: dict[str, object] = {"slot": slot_hex, "algorithm": algorithm.upper()}
    if ca_obj:
        # The signing key is the service's own setting; naming another one is refused
        # and still counts as an operation on the card, so the value is not sent.
        app.out.warn(
            "--ca-obj is ignored: the service signs key attestations with one fixed CA key. "
            "The option will be removed."
        )

    card = _open_card(app)
    try:
        slot_cert, container_before = _read_certificates(card, slot_ref)
        occupied = []
        if slot_cert is not None:
            occupied.append(f"slot {slot_hex} holds a certificate")
        if container_before is not None:
            occupied.append("the attestation container holds a certificate")
        if occupied:
            app.out.warn(
                "remote attest replaces the key in the slot and the certificate in the "
                "attestation container: " + "; ".join(occupied) + "."
            )
            if not app.yes:
                if app.json or not sys.stdin.isatty():
                    raise CryptnoxError(
                        "remote attest would overwrite existing material; pass --yes to confirm."
                    )
                if not click.confirm("Continue and overwrite?", default=False):
                    raise click.Abort()

        app.out.note(f"remote {op} via {url}")
        report = _relay(app, ctx, card, op, params, url)
        _slot_after, container_after = _read_certificates(card, slot_ref)
    finally:
        card.conn.disconnect()

    pem = report.result.get("attestation_cert_pem")
    verification: av.AttestVerification | None = None
    identifiers: dict[str, bool | None] = {}
    if isinstance(pem, str) and pem.strip():
        try:
            leaf_der = av.leaf_from_pem(pem)
        except ValueError as exc:
            raise CryptnoxError(f"the service returned an unreadable certificate: {exc}") from exc
        verification = av.verify_returned_attestation(
            leaf_der, slot=slot_ref, cplc_uid=card.cplc_uid, on_card_der=container_after
        )
        identifiers = av.check_reported_identifiers(report.result, leaf_der)
        if out_:
            Path(out_).write_bytes(pem.encode("utf-8"))

    card_info = card.to_dict()
    checks = _cross_check(card_info, report.result)
    checks["attestation_returned"] = verification is not None
    checks["attestation_verified"] = verification.verified if verification else False
    checks["attestation_container_written"] = container_after is not None
    # What the service says it signed, against the certificate it returned.
    checks.update(identifiers)
    if any(value is False for value in identifiers.values()):
        app.out.warn(
            "the identifiers the service reports for the certificate do not match the "
            "certificate it returned; report this to Cryptnox support."
        )
    relay_info = _relay_info(report)
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "slot": slot_hex,
        "algorithm": algorithm.upper(),
        "card": card_info,
        "result": report.result,
        "verification": verification.to_dict() if verification else None,
        "verified_locally": checks,
        "out": out_,
        "relay": relay_info,
    }

    def human(c: Console) -> None:
        _print_header(c, op, url, card_info, relay_info)
        _print_result(c, {k: v for k, v in report.result.items() if k != "attestation_cert_pem"})
        c.print("\n[bold]Key attestation[/bold] (checked locally)")
        if verification is None:
            c.print("  [red]the service returned no certificate[/red]")
        else:
            verdict = (
                "[green]verified[/green]" if verification.verified else "[red]NOT verified[/red]"
            )
            c.print(f"  {verdict}  {escape(verification.subject)}")
            c.print(f"  chain: {' -> '.join(escape(n) for n in verification.chain)}")
            for label, value in (
                ("serial number is this card", verification.serial_number_matches_card),
                (f"attests slot {slot_hex}", verification.slot_matches),
                ("trust model is server-driven", verification.trust_model_matches),
                ("key equals the card's stored certificate", verification.public_key_matches_card),
            ):
                if value is True:
                    mark = "[green]yes[/green]"
                elif value is False:
                    mark = "[red]NO[/red]"
                else:
                    mark = "[dim]unchecked[/dim]"
                c.print(f"  {label}: {mark}")
            for reason in verification.reasons:
                c.print(f"  [yellow]-[/yellow] {escape(reason)}")
            if out_:
                c.print(f"  PEM written to {escape(out_)}")
        c.print(
            "  [dim]On-card generation is the service's claim; the relay cannot witness it.[/dim]"
        )
        _print_checks(c, checks)

    app.out.result(payload, human)
