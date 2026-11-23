# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``remote consumer-lock`` and ``remote key-sheet``: the card handed to its owner
alone, and the keys that run delivers."""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import os
import signal
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import FrameType

import click
from rich.console import Console
from rich.markup import escape

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import keysheet, relay
from cryptnox_id_cli.remote import protocol as proto
from cryptnox_id_cli.remote.protocol import sanitize_server_text
from cryptnox_id_cli.secrets.resolver import SecretInputError
from cryptnox_id_cli.transport.errors import CryptnoxError, RemoteError, RemoteProtocolError
from cryptnox_id_cli.util.hexutil import from_hex

from .card import Card, open_card
from .render import print_channel, print_checks, print_header, print_result, text, warn_channel
from .run import cross_check, endpoint, relay_info, relay_operation, warn_contactless_reader

#: Phrase typed to confirm the lock interactively.
SEAL_PHRASE = "SEAL-CARD"

SSD_KEY1_MODES = ("seal", "keep", "provided")
MGMT_KEY_MODES = ("generate", "provided", "skip")
PROVIDED_SSD_KEY1_ENV = "CRYPTNOX_PROVIDED_SSD_KEY1"
PROVIDED_MGMT_KEY_ENV = "CRYPTNOX_PROVIDED_MGMT_KEY"
KEYSHEET_PASSPHRASE_ENV = "CRYPTNOX_KEYSHEET_PASSWORD"
_SHEET_MARKER = "decrypted locally"
_SHEET_NOT_DECRYPTED = "not decrypted"

_SSD_KEY1_CONSEQUENCE = {
    "seal": "--ssd-key1 seal: key version 1 is replaced too and nobody keeps it, so the PIV "
    "security domain can never be opened again. The 9B management key is then the only way "
    "to manage the PIV keys.",
    "keep": "--ssd-key1 keep: key version 1 is replaced with a random key delivered to you; "
    "with it the PIV security domain stays open to you.",
    "provided": "--ssd-key1 provided: key version 1 is replaced with the value you supplied.",
}
_MGMT_KEY_CONSEQUENCE = {
    "generate": "--mgmt-key generate: the 9B management key gets a random value delivered to you.",
    "provided": "--mgmt-key provided: the 9B management key gets the value you supplied.",
    "skip": "--mgmt-key skip: the 9B management key keeps its value. The service refuses if "
    "that is the public default and key version 1 is sealed.",
}
_KEY_USES = {
    "ssd_kvn1": "PIV security domain key version 1: PIV_SCP03_ENC, _MAC and _DEK all take it",
    "mgmt_key_9b_aes128": "PIV management key 9B (AES-128): PIV_MGMT_KEY",
    "mgmt_key_9b_aes192": "PIV management key 9B (AES-192): PIV_MGMT_KEY",
    "mgmt_key_9b_aes256": "PIV management key 9B (AES-256): PIV_MGMT_KEY",
}


def _yes_no(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "not reported"


def _names(values: object) -> str:
    if isinstance(values, list):
        return ", ".join(text(v) for v in values) if values else "none"
    return "not reported"


def _stderr_is_terminal() -> bool:
    return sys.stderr.isatty()


def _provided_value(app: AppContext, env_var: str, label: str, lengths: tuple[int, ...]) -> str:
    """An owner-supplied key value, from the environment or a masked prompt, never argv."""
    raw = os.environ.get(env_var)
    if raw is None:
        if not sys.stdin.isatty():
            raise SecretInputError(f"the {label} is required; set ${env_var} (hex).")
        raw = getpass.getpass(f"{label} (hex): ")
    try:
        value = from_hex(raw)
    except ValueError:
        raise SecretInputError(f"the {label} is not valid hex.") from None
    if len(value) not in lengths:
        sizes = " or ".join(str(n) for n in lengths)
        raise SecretInputError(f"the {label} is {len(value)} bytes; it must be {sizes}.")
    app.redactor.register(value)
    return value.hex().upper()


def _sheet_passphrase(app: AppContext, *, confirm: bool) -> str:
    value = os.environ.get(KEYSHEET_PASSPHRASE_ENV)
    if value is None:
        if not sys.stdin.isatty():
            raise SecretInputError(
                f"the key sheet passphrase is required; set ${KEYSHEET_PASSPHRASE_ENV}."
            )
        value = click.prompt(
            "Key sheet passphrase", hide_input=True, confirmation_prompt=confirm, err=True
        )
    if not value:
        raise SecretInputError("the key sheet passphrase is empty.")
    app.redactor.register(value.encode("utf-8"))
    return value


@dataclass
class _SheetFile:
    """A key sheet file created before the card is touched, so it is known to be writable."""

    path: str
    fd: int
    passphrase: str
    written: bool = False
    closed: bool = False

    @staticmethod
    def create(path: str, passphrase: str) -> _SheetFile:
        # Windows opens an fd in text mode unless told otherwise, which writes each 0A as 0D 0A.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise CryptnoxError(f"{path} exists; the key sheet goes to a new file.") from None
        except OSError as exc:
            raise CryptnoxError(f"cannot create {path}: {exc.strerror}") from None
        return _SheetFile(path, fd, passphrase)

    def write(self, sheet: dict[str, object]) -> None:
        data = keysheet.seal_file(sheet, self.passphrase)
        self.closed = True
        with os.fdopen(self.fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _sync_directory(self.path)
        # The keys exist nowhere else: the file must be shown to hold them before it counts.
        try:
            stored = keysheet.open_file(Path(self.path).read_bytes(), self.passphrase)
        except keysheet.KeySheetError:
            stored = None
        if stored != sheet:
            raise OSError("the saved key sheet does not read back")
        self.written = True

    def discard_unwritten(self) -> None:
        if not self.closed:
            os.close(self.fd)
            self.closed = True
        if not self.written:
            with contextlib.suppress(OSError):
                os.unlink(self.path)


def _sync_directory(path: str) -> None:
    """Best effort: make the new file's directory entry durable as well."""
    if os.name != "posix":
        return
    with contextlib.suppress(OSError):
        dfd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _print_keys(c: Console, keys: list[tuple[str, str]]) -> None:
    for name, value in keys:
        c.print(f"  {text(name)}: {text(value)}")
        c.print(f"    [dim]{_KEY_USES.get(name, '')}[/dim]")


def _show_keys(app: AppContext, sheet: dict[str, object]) -> None:
    app.out.err.print("\n[bold]Delivered keys[/bold] (shown once: record them now)")
    _print_keys(app.out.err, keysheet.sheet_keys(sheet))


def _sheet_for_card(sheet: dict[str, object], card: Card) -> bool | None:
    expected = sheet.get("uid_sha256")
    if not isinstance(expected, str) or not card.cplc_uid:
        return None
    return hashlib.sha256(card.cplc_uid.lower().encode()).hexdigest() == expected.lower()


def _receive_sheet(
    app: AppContext,
    kex: keysheet.PrivateKey,
    result: dict[str, object],
    card: Card,
    sheet_file: _SheetFile | None,
    show_once: bool,
) -> dict[str, object]:
    """Decrypt the delivered keys, save and/or show them, and take them out of the result."""
    blob_text = result.get("key_sheet")
    if not isinstance(blob_text, str) or not blob_text:
        return {"delivered": False}
    result["key_sheet"] = _SHEET_NOT_DECRYPTED
    try:
        blob = keysheet.b64decode(blob_text, "key sheet")
        sheet = keysheet.decrypt(kex, blob, context=keysheet.KEY_SHEET_CONTEXT)
    except keysheet.KeySheetError as exc:
        return {"delivered": True, "decrypted": False, "lost": True, "error": str(exc)}
    result["key_sheet"] = _SHEET_MARKER
    keys = keysheet.sheet_keys(sheet)
    for _name, value in keys:
        with contextlib.suppress(ValueError):
            app.redactor.register(bytes.fromhex(value))
    info: dict[str, object] = {
        "delivered": True,
        "decrypted": True,
        "keys": [name for name, _value in keys],
        "kcv_match": keysheet.check_kcvs(sheet),
        "for_this_card": _sheet_for_card(sheet, card),
        "saved_to": None,
        "shown": False,
    }
    if sheet_file is not None:
        try:
            sheet_file.write(sheet)
            info["saved_to"] = sheet_file.path
        except OSError as exc:
            info["error"] = f"the key sheet could not be written to {sheet_file.path}: {exc}"
    if show_once or (info["saved_to"] is None and _stderr_is_terminal()):
        _show_keys(app, sheet)
        info["shown"] = True
    elif info["saved_to"] is None:
        info["lost"] = True
        info.setdefault(
            "error",
            "the service delivered keys this run did not ask for, and there was nowhere to "
            "put them",
        )
    return info


def _confirm_consumer_lock(
    app: AppContext, card: Card, ssd_key1: str, mgmt_key: str, understood: bool
) -> None:
    app.out.warn(
        f"remote consumer-lock takes the administration keys of card "
        f"{card.cplc_uid or card.atr} away from everyone, Cryptnox included: the card "
        "manager key and the PIV security domain's key version 2 are replaced with random "
        "keys that nobody keeps. Afterwards nobody can reset the PIV function, attest a key "
        "through the service, switch its FIPS mode or reinstall it, and a blocked PUK ends "
        "the PIV function for good. The keys and certificates on the card stay and keep "
        "working. This cannot be undone."
    )
    app.out.warn(_SSD_KEY1_CONSEQUENCE[ssd_key1])
    app.out.warn(_MGMT_KEY_CONSEQUENCE[mgmt_key])
    app.out.warn(
        "if the PIV applet is not finalized, the service first creates the cryptnox-default "
        "profile's missing objects and turns on the applet's NFC admin lock."
    )
    app.out.warn("Do not interrupt the command or remove the card until it finishes.")
    if understood:
        return
    if app.json or not sys.stdin.isatty():
        raise CryptnoxError(
            "remote consumer-lock needs --i-understand-this-is-irreversible non-interactively."
        )
    if click.prompt(f"Type {SEAL_PHRASE} to continue") != SEAL_PHRASE:
        raise click.Abort()


_INTERRUPT_NOTICE = (
    "consumer-lock is changing the card and finishes on its own; interrupt again to stop "
    "after the current command and keep the service's result"
)


@contextlib.contextmanager
def _hold_signals(app: AppContext, *, enabled: bool) -> Iterator[Callable[[], bool] | None]:
    """Keep an interrupt or a closed terminal from ending the lock between two card commands.

    Yields what the relay asks before each command: whether a second
    interrupt, or a termination request, asked it to stop.
    """
    if not enabled or threading.current_thread() is not threading.main_thread():
        yield None
        return
    interrupts = 0
    stop = False

    def on_interrupt(signum: int, frame: FrameType | None) -> None:
        nonlocal interrupts, stop
        interrupts += 1
        if interrupts > 1:
            stop = True
            return
        # An exception here would surface in the relay loop and stop it halfway.
        with contextlib.suppress(Exception, SystemExit):
            app.out.err.print(f"[yellow]warning:[/yellow] {_INTERRUPT_NOTICE}")

    def on_terminate(signum: int, frame: FrameType | None) -> None:
        nonlocal stop
        stop = True

    previous = {
        signal.SIGINT: signal.signal(signal.SIGINT, on_interrupt),
        signal.SIGTERM: signal.signal(signal.SIGTERM, on_terminate),
    }
    sighup = getattr(signal, "SIGHUP", None)
    if sighup is not None:
        previous[sighup] = signal.signal(sighup, signal.SIG_IGN)
    try:
        yield lambda: stop
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler if handler is not None else signal.SIG_DFL)


def _join(names: list[str]) -> str:
    joined = " and ".join(names)
    return joined[:1].upper() + joined[1:]


def _partly_changed_warning(
    ssd_key1: str, mgmt_key: str, sheet_info: dict[str, object], card_manager_written: bool
) -> str:
    """What may have changed when a failed run had relayed commands that write to the card."""
    nine_b, kvn1 = "the 9B management key", "key version 1 of the PIV security domain"
    random_keys = [
        name for name, on in ((nine_b, mgmt_key == "generate"), (kvn1, ssd_key1 == "keep")) if on
    ]
    supplied = [
        name
        for name, on in ((nine_b, mgmt_key == "provided"), (kvn1, ssd_key1 == "provided"))
        if on
    ]
    parts = [
        "the card may be partly changed: the run stopped after commands that write reached it."
    ]
    if random_keys:
        if sheet_info.get("saved_to") or sheet_info.get("shown"):
            values = "value" if len(random_keys) == 1 else "values"
            parts.append(f"{_join(random_keys)} may already be on the delivered {values}.")
        elif sheet_info.get("delivered"):
            parts.append(
                f"{_join(random_keys)} may hold a random value that is lost with the "
                "delivered keys."
            )
        else:
            parts.append(f"{_join(random_keys)} may hold a random value that was never delivered.")
    if supplied:
        parts.append(f"{_join(supplied)} may hold the value you supplied.")
    if card_manager_written:
        parts.append(
            "A PUT KEY reached the card manager, so Cryptnox may no longer be able to rebuild "
            "the card."
        )
    else:
        parts.append(
            "The card manager key is unchanged: Cryptnox can still rebuild the card with a "
            "reset, which reinstalls the PIV function and with it every key."
        )
    return " ".join(parts)


def _lost_message(info: dict[str, object]) -> str:
    if info.get("delivered"):
        return f"the keys the service delivered are lost: {info['error']}"
    return f"the keys this run should have received are lost: {info['error']}"


def _sheet_problem(info: dict[str, object]) -> str | None:
    """Why a lock the service reports as done still ends with exit code 17, if it does."""
    if info.get("lost"):
        return _lost_message(info)
    problems = []
    if info.get("kcv_match") is False:
        problems.append("the delivered keys do not match the check values that came with them")
    if info.get("for_this_card") is False:
        problems.append("the key sheet was made for another card")
    if not problems:
        return None
    where = " and ".join(
        label
        for label, on in (
            (f"saved to {info.get('saved_to')}", info.get("saved_to")),
            ("shown on the terminal", info.get("shown")),
        )
        if on
    )
    return f"{'; '.join(problems)}. The keys were {where} as delivered."


def _print_sheet_info(c: Console, info: dict[str, object]) -> None:
    if not info.get("delivered"):
        return
    c.print("\n[bold]Delivered keys[/bold] (checked locally)")
    if not info.get("decrypted"):
        c.print(f"  [red]not decrypted:[/red] {escape(str(info.get('error')))}")
        return
    c.print(f"  keys: {_names(info.get('keys'))}")
    c.print(f"  check values match: {_yes_no(info.get('kcv_match'))}")
    c.print(f"  made for this card: {_yes_no(info.get('for_this_card'))}")
    if info.get("saved_to"):
        c.print(f"  saved, encrypted, to {escape(str(info['saved_to']))}")
    if info.get("shown"):
        c.print("  shown once on the terminal")


@click.command("consumer-lock")
@click.option(
    "--ssd-key1",
    "ssd_key1",
    type=click.Choice(SSD_KEY1_MODES),
    default="seal",
    show_default=True,
    help="The PIV security domain's key version 1: seal (random, kept by nobody), keep "
    "(random, delivered to you) or provided (your value, from "
    f"${PROVIDED_SSD_KEY1_ENV} or a prompt).",
)
@click.option(
    "--mgmt-key",
    "mgmt_key",
    type=click.Choice(MGMT_KEY_MODES),
    default="generate",
    show_default=True,
    help="The PIV management key 9B: generate (random, delivered to you), provided (your "
    f"value, from ${PROVIDED_MGMT_KEY_ENV} or a prompt) or skip (unchanged).",
)
@click.option(
    "--sheet-out",
    "sheet_out",
    type=click.Path(dir_okay=False),
    help="Save the delivered keys to this new file, encrypted under a passphrase from "
    f"${KEYSHEET_PASSPHRASE_ENV} or a prompt.",
)
@click.option("--show-once", "show_once", is_flag=True, help="Print the delivered keys once.")
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.pass_context
def consumer_lock(
    ctx: click.Context,
    ssd_key1: str,
    mgmt_key: str,
    sheet_out: str | None,
    show_once: bool,
    understood: bool,
) -> None:
    """IRREVERSIBLY take the card's administration keys away from everyone, Cryptnox included.

    The service replaces the card manager key and the PIV security domain's key
    version 2 with random keys that nobody keeps, and handles key version 1 and
    the PIV management key 9B as the options say. Afterwards the card is a plain
    PIV token under its owner's PIN and 9B: no remote reset, attestation or FIPS
    switch, and the PIV applet can never be reinstalled. The keys and
    certificates already on the card stay. Under --dry-run the service checks the
    card and returns its plan, and the relay refuses any command that writes.
    """
    app: AppContext = ctx.obj
    op = "consumer-lock"
    url, _production = endpoint(op)
    dry_run = app.dry_run
    delivers = not dry_run and (ssd_key1 == "keep" or mgmt_key == "generate")
    if delivers and not (sheet_out or show_once):
        raise click.UsageError(
            "this run delivers keys that exist nowhere else: pass --sheet-out FILE, "
            "--show-once, or both."
        )
    if delivers and show_once and not _stderr_is_terminal():
        raise click.UsageError(
            "--show-once prints the keys on the terminal and stderr is not one; use --sheet-out."
        )

    provided: dict[str, str] = {}
    passphrase: str | None = None
    if not dry_run:
        if ssd_key1 == "provided":
            provided["ssd_kvn1"] = _provided_value(
                app, PROVIDED_SSD_KEY1_ENV, "SSD key version 1 value", (16,)
            )
        if mgmt_key == "provided":
            provided["mgmt_key_9b"] = _provided_value(
                app, PROVIDED_MGMT_KEY_ENV, "9B management key value", (16, 32)
            )
        if delivers and sheet_out:
            passphrase = _sheet_passphrase(app, confirm=True)

    kex = keysheet.generate_kex()
    params: dict[str, object] = {
        "ssd_key1": ssd_key1,
        "mgmt_key": mgmt_key,
        "client_kex_pub": keysheet.b64encode(keysheet.public_bytes(kex)),
        "confirm": SEAL_PHRASE,
        "fused": True,
        "dry_run": dry_run,
    }

    def answer_kex(frame: proto.KexRequest) -> bytes:
        if frame.context != keysheet.PROVIDED_CONTEXT.decode():
            raise RemoteProtocolError(
                "the service asked for values under an unknown context "
                f"{sanitize_server_text(frame.context)!r}"
            )
        unknown = [f for f in frame.fields if f not in provided]
        if unknown:
            raise RemoteProtocolError(
                "the service asked for "
                + ", ".join(sanitize_server_text(f) for f in unknown)
                + ", which this run does not supply"
            )
        payload = {f: provided[f] for f in frame.fields}
        return keysheet.encrypt_to(frame.public_key, payload, context=keysheet.PROVIDED_CONTEXT)

    sheet_file = (
        _SheetFile.create(sheet_out, passphrase) if passphrase is not None and sheet_out else None
    )
    failure: RemoteError | None = None
    report = relay.RelayReport(op=op, result={})
    try:
        card = open_card(app)
        try:
            warn_contactless_reader(app, card, refused=True)
            if not dry_run:
                _confirm_consumer_lock(app, card, ssd_key1, mgmt_key, understood)
            app.out.note(f"remote {op}{' (dry run)' if dry_run else ''} via {url}")
            try:
                with _hold_signals(app, enabled=not dry_run) as stop_requested:
                    relay_operation(
                        app,
                        ctx,
                        card,
                        op,
                        params,
                        url,
                        dry_run=dry_run,
                        answer_kex=answer_kex,
                        stop_requested=stop_requested,
                        report=report,
                    )
                result = report.result
            except RemoteError as exc:
                failure = exc
                result = exc.result if exc.result is not None else {}
            sheet_info = _receive_sheet(app, kex, result, card, sheet_file, show_once)
        finally:
            card.conn.disconnect()
    finally:
        if sheet_file is not None:
            sheet_file.discard_unwritten()

    if failure is None and delivers and not sheet_info.get("delivered"):
        sheet_info = {
            "delivered": False,
            "lost": True,
            "error": "the service reported success but delivered no key sheet, though "
            f"--ssd-key1 {ssd_key1} --mgmt-key {mgmt_key} deliver keys",
        }
    if sheet_info.get("error") and not sheet_info.get("lost"):
        app.out.error(
            f"{escape(str(sheet_info['error']))}; the keys were shown on the terminal instead."
        )
    if not delivers and sheet_info.get("delivered"):
        if dry_run:
            app.out.warn("the service delivered keys during a dry run, which asks for none.")
        else:
            app.out.warn(
                f"the service delivered keys, though --ssd-key1 {ssd_key1} --mgmt-key "
                f"{mgmt_key} ask for none: the card may hold keys other than the ones you chose."
            )
    if failure is not None:
        failure.key_sheet = sheet_info
        if not app.json:
            _print_sheet_info(app.out.console, sheet_info)
        if sheet_info.get("lost"):
            app.out.error(escape(_lost_message(sheet_info)))
        if report.card_written:
            app.out.warn(
                _partly_changed_warning(
                    ssd_key1, mgmt_key, sheet_info, report.card_manager_key_written
                )
            )
        recovery = result.get("recovery")
        if isinstance(recovery, str) and recovery.strip():
            app.out.warn(f"the service's recovery note: {escape(sanitize_server_text(recovery))}")
        raise failure

    card_info = card.to_dict()
    checks = cross_check(card_info, result)
    if sheet_info.get("decrypted"):
        checks["key_sheet_kcv_match"] = sheet_info["kcv_match"]
        checks["key_sheet_for_this_card"] = sheet_info["for_this_card"]
    relayed = relay_info(report)
    payload: dict[str, object] = {
        "op": op,
        "endpoint": url,
        "dry_run": dry_run,
        "modes": {"ssd_key1": ssd_key1, "mgmt_key": mgmt_key},
        "card": card_info,
        "result": result,
        "key_sheet": sheet_info,
        "verified_locally": checks,
        "relay": relayed,
    }

    def human(c: Console) -> None:
        print_header(c, op, url, card_info, relayed)
        print_channel(c, result, expected=not dry_run)
        print_result(c, result)
        _print_sheet_info(c, sheet_info)
        print_checks(c, checks)

    problem = _sheet_problem(sheet_info)
    if problem is None or not app.json:
        app.out.result(payload, human)
    warn_channel(app, result)
    if problem is not None:
        raise keysheet.KeySheetRunError(problem, report=payload)


@click.command("key-sheet")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def key_sheet(ctx: click.Context, path: str) -> None:
    """Show the keys in a key sheet file that consumer-lock saved.

    The passphrase comes from $CRYPTNOX_KEYSHEET_PASSWORD or a prompt. No card is
    needed.
    """
    app: AppContext = ctx.obj
    passphrase = _sheet_passphrase(app, confirm=False)
    sheet = keysheet.open_file(Path(path).read_bytes(), passphrase)
    keys = keysheet.sheet_keys(sheet)
    for _name, value in keys:
        with contextlib.suppress(ValueError):
            app.redactor.register(bytes.fromhex(value))
    payload: dict[str, object] = {
        "path": path,
        "op": sheet.get("op"),
        "created": sheet.get("created"),
        "scp": sheet.get("scp"),
        "uid_sha256": sheet.get("uid_sha256"),
        "keys": dict(keys),
        "kcv_match": keysheet.check_kcvs(sheet),
    }

    def human(c: Console) -> None:
        c.print(f"[bold]Key sheet[/bold] {escape(path)}")
        c.print(f"  made by: {text(sheet.get('op'))} on {text(sheet.get('created'))}")
        c.print(f"  check values match: {_yes_no(payload['kcv_match'])}")
        _print_keys(c, keys)

    app.out.result(payload, human)
