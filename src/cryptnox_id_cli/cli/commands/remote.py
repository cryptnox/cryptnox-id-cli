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
from dataclasses import dataclass
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.cli.commands.info import _read_cplc
from cryptnox_id_cli.cli.commands.piv import SLOT_CERT_OBJECT, _read_cert_der
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import attest_verify as av
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import relay
from cryptnox_id_cli.remote.policy import PIV_SSD_AID, RelayPolicy
from cryptnox_id_cli.secrets.resolver import resolve_secret
from cryptnox_id_cli.state.detector import StateDetector
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import CryptnoxError, RemoteConnectError
from cryptnox_id_cli.transport.pcsc import CardSession, PCSCConnection, connect, pick_reader
from cryptnox_id_cli.util import tlv

_FULL_TRANSCRIPT_KEY = "remote.full_transcript"

#: Environment variable carrying the development access credential for
#: ``dev-reset``. Never an option: it would land in shell history.
DEV_ACCESS_ENV = "CRYPTNOX_REMOTE_DEV_TOKEN"

#: Phrases typed to confirm the irreversible operations interactively.
RESET_PHRASE = "RESET-PIV"
DEV_RESET_PHRASE = "DEV-RESET-PIV"

_READ_ONLY = ("authenticate", "inspect")


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
    reader: str
    conn: PCSCConnection
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
    reader = pick_reader(app.reader)
    app.resolved_reader = reader
    conn = connect(reader)
    session = app.make_session(conn, reader_name=reader)
    cplc = _read_cplc(session)
    return _Card(
        reader=reader,
        conn=conn,
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


def _inventory(card: _Card) -> dict[str, object]:
    """What the PIV function and its neighbours hold right now, read locally.

    Ends by re-reading the CPLC so the card manager is the selected applet
    again, which is what the relay policy assumes at the start of an operation.
    """
    state = StateDetector(
        card.session, probe_fido=True, probe_desfire=False, probe_genuine=True
    ).detect()
    ssd = _ssd_key_versions(card.session)
    _read_cplc(card.session)
    return {
        "piv_state": state.piv.label,
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
    c.print(f"  PIV data objects:    {objects_text}")
    c.print(f"  PIV security domain: {ssd_text}")
    c.print(f"  FIDO2:               {inv['fido_state']}")
    c.print(f"  Genuineness:         {inv['genuineness_state']}")


# --------------------------------------------------------------------------- #
# Read-only operations                                                        #
# --------------------------------------------------------------------------- #
def _run_read_only(ctx: click.Context, op: str) -> None:
    app: AppContext = ctx.obj
    url, production = _endpoint(op)
    card = _open_card(app)
    try:
        if not production:
            app.out.warn(f"connecting to a non-production endpoint: {url}")
        app.out.note(f"remote {op} via {url}")
        report = _relay(app, ctx, card, op, {}, url)
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

    def human(c: Console) -> None:
        _print_header(c, op, url, card_info, relay_info)
        _print_result(c, report.result)
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
_DEFAULT_KEYS_HELP = (
    "Development cards only: have the service authenticate with the publicly known "
    "GlobalPlatform default key instead of deriving this card's own. A production card "
    "will refuse it, and the failed authentication costs a card-management retry."
)


def _confirm_destructive(
    app: AppContext, op: str, phrase: str, understood: bool, card: _Card, default_keys: bool
) -> dict[str, object]:
    """Show what is about to be destroyed and obtain consent. Returns the inventory."""
    before = _inventory(card)
    app.out.warn(
        f"remote {op} wipes the PIV function on card {card.cplc_uid or card.atr}: the "
        "applet, every key and certificate in it, and its security domain are deleted and "
        "reinstalled. This cannot be undone."
    )
    if op == "dev-reset":
        app.out.warn(
            "dev-reset leaves the card manager and the PIV security domain on the PUBLIC "
            "default key: anyone with a reader can then install or delete applets, "
            "including the wallet. The card is not genuine again until it is reset through "
            "the service."
        )
    if default_keys:
        app.out.warn(
            "--default-keys: the service will authenticate with the publicly known "
            "GlobalPlatform default key. A production card holds its own derived key and "
            "will refuse this, and the failed authentication costs a card-management retry."
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
    ctx: click.Context, op: str, *, default_keys: bool, understood: bool, phrase: str
) -> None:
    app: AppContext = ctx.obj
    url, _production = _endpoint(op)  # refuses any override for these operations
    # Sent explicitly either way, so behaviour never depends on the service's own default.
    params: dict[str, object] = {"fused": not default_keys}
    if op == "dev-reset":
        credential = resolve_secret(
            redactor=app.redactor,
            env_var=DEV_ACCESS_ENV,
            prompt_label="Cryptnox remote development access",
        )
        params["dev_token"] = credential.decode("utf-8")

    card = _open_card(app)
    try:
        before = _confirm_destructive(app, op, phrase, understood, card, default_keys)
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
    relay_info = _relay_info(report)
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "fused": not default_keys,
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


@command.command("reset")
@click.option("--default-keys", "default_keys", is_flag=True, help=_DEFAULT_KEYS_HELP)
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.pass_context
def reset(ctx: click.Context, default_keys: bool, understood: bool) -> None:
    """IRREVERSIBLY wipe and reinstall the PIV function through the service.

    The service deletes the PIV applet, its package and its security domain,
    reinstalls the applet, recreates the security domain and loads the card's
    keys, so the card is genuine and remotely manageable afterwards. Every PIV
    key and certificate is destroyed. The other card functions are outside the
    operation.
    """
    _run_destructive(
        ctx, "reset", default_keys=default_keys, understood=understood, phrase=RESET_PHRASE
    )


@command.command("dev-reset")
@click.option("--default-keys", "default_keys", is_flag=True, help=_DEFAULT_KEYS_HELP)
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.pass_context
def dev_reset(ctx: click.Context, default_keys: bool, understood: bool) -> None:
    """IRREVERSIBLY wipe the PIV function and leave the card on the public default keys.

    For development cards only. Needs the development access credential in
    $CRYPTNOX_REMOTE_DEV_TOKEN. Afterwards the card manager and the PIV security
    domain are on the publicly documented GlobalPlatform key, so the PIV function
    can be pre-personalized and personalized locally; the card is not genuine
    until reset through the service again.
    """
    _run_destructive(
        ctx,
        "dev-reset",
        default_keys=default_keys,
        understood=understood,
        phrase=DEV_RESET_PHRASE,
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
    help="Signing sub-CA object in the service (hex). Omit for the key-attestation CA.",
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
        params["ca_obj"] = ca_obj

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
    if isinstance(pem, str) and pem.strip():
        try:
            leaf_der = av.leaf_from_pem(pem)
        except ValueError as exc:
            raise CryptnoxError(f"the service returned an unreadable certificate: {exc}") from exc
        verification = av.verify_returned_attestation(
            leaf_der, slot=slot_ref, cplc_uid=card.cplc_uid, on_card_der=container_after
        )
        if out_:
            Path(out_).write_bytes(pem.encode("utf-8"))

    card_info = card.to_dict()
    checks = _cross_check(card_info, report.result)
    checks["attestation_returned"] = verification is not None
    checks["attestation_verified"] = verification.verified if verification else False
    checks["attestation_container_written"] = container_after is not None
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
