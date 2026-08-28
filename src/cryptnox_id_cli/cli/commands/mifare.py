"""``mifare`` — MIFARE DESFire EV2 (contactless; reads AND writes).

DESFire is the card's default applet; these commands need a DESFire-capable
contactless reader and the card freshly presented (no JavaCard applet selected).
Several commands modify or erase card contents (``write``, ``record clear``,
``app delete``, and the irreversible ``format``).
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli.applets.mifare import desfire as df
from cryptnox_id_cli.applets.mifare.desfire import DesfireTransport
from cryptnox_id_cli.applets.mifare.ev2 import (
    authenticate_ev2_first,
    change_file_settings,
    change_key_cross,
    change_key_same,
    command_full,
    command_macked,
    format_picc,
    sdm_decrypt_picc,
    sdm_file_read_mac,
)
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.util.hexutil import from_hex


@click.group("mifare")
def command() -> None:
    """Manage the MIFARE DESFire EV2 function (contactless; default applet)."""


@command.command("version")
@click.pass_obj
def version(app: AppContext) -> None:
    """Show the DESFire hardware/software version, storage size and UID."""
    with app.open_session() as session:
        info = DesfireTransport(session).get_version().to_dict()

    def human(c: Console) -> None:
        c.print("[bold]MIFARE DESFire[/bold]")
        c.print(f"  Vendor:   {info['vendor']}")
        c.print(f"  Hardware: v{info['hardware_version']}  software: v{info['software_version']}")
        c.print(f"  Storage:  {info['storage_bytes']} bytes")
        c.print(f"  UID:      {info['uid']}")
        c.print(f"  Protocol: {info['protocol']}  batch: {info['batch']}  {info['production']}")

    app.out.result(info, human)


@command.command("info")
@click.pass_obj
def info(app: AppContext) -> None:
    """Detect DESFire: version, free memory and application list."""
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        version_info = dtx.get_version().to_dict()
        free = None
        with contextlib.suppress(CryptnoxError):
            free = dtx.get_free_memory()
        aids = [a.hex().upper() for a in dtx.application_ids()]
    payload = {**version_info, "free_memory": free, "applications": aids}

    def human(c: Console) -> None:
        c.print("[bold]MIFARE DESFire EV2[/bold]")
        c.print(f"  Vendor/HW: {payload['vendor']} v{payload['hardware_version']}")
        c.print(f"  Storage:   {payload['storage_bytes']} bytes")
        c.print(f"  UID:       {payload['uid']}")
        c.print(f"  Free mem:  {free if free is not None else 'n/a'}")
        c.print(f"  Applications ({len(aids)}): {', '.join(aids) if aids else 'none'}")

    app.out.result(payload, human)


@command.command("free-memory")
@click.pass_obj
def free_memory(app: AppContext) -> None:
    """Show free EEPROM (bytes), if the card permits the query."""
    with app.open_session() as session:
        free = DesfireTransport(session).get_free_memory()
    app.out.result({"free_memory": free}, lambda c: c.print(f"Free memory: {free} bytes"))


@command.group("apps")
def apps() -> None:
    """DESFire applications."""


@apps.command("list")
@click.pass_obj
def apps_list(app: AppContext) -> None:
    """List application IDs (AIDs)."""
    with app.open_session() as session:
        aids = [a.hex().upper() for a in DesfireTransport(session).application_ids()]

    def human(c: Console) -> None:
        if not aids:
            c.print("No applications (only the PICC master level).")
            return
        table = app.out.table("#", "AID")
        for i, aid in enumerate(aids):
            table.add_row(str(i), aid)
        c.print(table)

    app.out.result({"applications": aids}, human)


@command.group("files")
def files() -> None:
    """DESFire files."""


@files.command("list")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex (e.g. 010203).")
@click.pass_obj
def files_list(app: AppContext, aid: str) -> None:
    """List file IDs in an application."""
    aid_bytes = from_hex(aid)
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        file_ids = dtx.file_ids()

    def human(c: Console) -> None:
        if not file_ids:
            c.print(f"No files in application {aid.upper()}.")
            return
        c.print(f"Files in {aid.upper()}: {', '.join(f'{f:02X}' for f in file_ids)}")

    app.out.result({"aid": aid.upper(), "files": [f"{f:02X}" for f in file_ids]}, human)


def _resolve_aes_key(app: AppContext, zero_key: bool, key_env: str | None) -> bytes:
    """Resolve a 16-byte AES key from --zero-key (factory default) or an env var."""
    if zero_key and key_env:
        raise click.UsageError("--zero-key and --key-env are mutually exclusive; pass only one.")
    if zero_key:
        key = bytes(16)
    elif key_env:
        value = os.environ.get(key_env)
        if not value:
            raise CryptnoxError(f"environment variable {key_env} is not set.")
        key = from_hex(value)
        if len(key) != 16:
            raise CryptnoxError("DESFire EV2 keys must be 16 bytes (AES-128).")
    else:
        raise click.UsageError("provide --zero-key (factory default) or --key-env NAME")
    app.redactor.register(key)
    return key


def _aid3(aid: str) -> bytes:
    aid_bytes = from_hex(aid)
    if len(aid_bytes) != 3:
        raise click.BadParameter("DESFire AID must be 3 bytes hex, e.g. 010203")
    return aid_bytes


@command.group("app")
def app_group() -> None:
    """Create / delete / select DESFire applications."""


@app_group.command("create")
@click.option("--aid", required=True, help="New application AID, 3 bytes hex.")
@click.option("--keys", "num_keys", default=3, show_default=True, type=int)
@click.option("--key-type", default="aes", show_default=True, help="Only 'aes' is supported.")
@click.pass_obj
def app_create(app: AppContext, aid: str, num_keys: int, key_type: str) -> None:
    """Create an application (AES keys; new keys default to all-zero)."""
    if key_type.lower() != "aes":
        raise click.BadParameter("only AES applications are supported (no legacy DES/3DES)")
    aid_bytes = _aid3(aid)
    app.out.warn("this modifies the DESFire file system.")
    if not app.yes and not click.confirm(f"Create application {aid.upper()}?", default=False):
        raise click.Abort()
    with app.open_session() as session:
        DesfireTransport(session).create_application(aid_bytes, num_keys=num_keys)
    app.out.result(
        {"aid": aid.upper(), "created": True, "keys": num_keys, "key_type": "AES"},
        lambda c: c.print(
            f"[green]Created application {aid.upper()}[/green] ({num_keys} AES keys)."
        ),
    )


@app_group.command("delete")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--key-no", default=0, show_default=True, type=int, help="App master key number.")
@click.option(
    "--zero-key",
    is_flag=True,
    help="Authenticate with the all-zero AES key (publicly known factory default) first.",
)
@click.option("--key-env", help="Authenticate with the AES key from this env var (hex).")
@click.pass_obj
def app_delete(app: AppContext, aid: str, key_no: int, zero_key: bool, key_env: str | None) -> None:
    """Delete an application and ALL its files (authenticates first if a key is given)."""
    aid_bytes = _aid3(aid)
    app.out.warn(f"this permanently deletes application {aid.upper()} and all its files.")
    if not app.yes and not click.confirm(f"Delete application {aid.upper()}?", default=False):
        raise click.Abort()
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        if zero_key or key_env:
            key = _resolve_aes_key(app, zero_key, key_env)
            dtx.select_application(aid_bytes)
            ev2 = authenticate_ev2_first(dtx, key_no, key)
            # Deleting the selected app ends the session; the OK reply carries no MAC.
            command_macked(
                dtx,
                ev2,
                df.CMD_DELETE_APPLICATION,
                bytes(aid_bytes),
                context="DeleteApplication",
                terminates_session=True,
            )
        else:
            dtx.delete_application(aid_bytes)
    app.out.result(
        {"aid": aid.upper(), "deleted": True},
        lambda c: c.print(f"[green]Deleted application {aid.upper()}.[/green]"),
    )


@command.group("keys")
def keys_group() -> None:
    """DESFire key operations."""


@keys_group.command("authenticate")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Environment variable holding the AES key (hex).")
@click.pass_obj
def keys_authenticate(
    app: AppContext, aid: str, key_no: int, zero_key: bool, key_env: str | None
) -> None:
    """AuthenticateEV2First with an AES key (proves the key and the session crypto)."""
    aid_bytes = _aid3(aid)
    key = _resolve_aes_key(app, zero_key, key_env)
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        ev2 = authenticate_ev2_first(dtx, key_no, key)
    app.out.result(
        {"aid": aid.upper(), "key_no": key_no, "authenticated": True, "ti": ev2.ti.hex().upper()},
        lambda c: c.print(
            f"[green]EV2 authentication OK[/green] (key {key_no}, TI {ev2.ti.hex().upper()})."
        ),
    )


@keys_group.command("change")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--key-no", default=0, show_default=True, type=int, help="Key number to change.")
@click.option(
    "--zero-key",
    is_flag=True,
    help="CURRENT value of the target key is all-zero (publicly known factory default).",
)
@click.option("--key-env", help="Env var with the CURRENT value of the target key (hex).")
@click.option("--new-key-env", required=True, help="Env var with the NEW 16-byte AES key (hex).")
@click.option("--key-version", default=0, show_default=True, type=int)
@click.option(
    "--auth-key-no",
    type=int,
    default=None,
    help="Cross-key change: authenticate with THIS key (e.g. 0, the app master) instead.",
)
@click.option(
    "--auth-zero-key",
    is_flag=True,
    help="Cross-key: the auth key is all-zero (publicly known factory default).",
)
@click.option("--auth-key-env", help="Cross-key: env var with the auth key (hex).")
@click.pass_obj
def keys_change(
    app: AppContext,
    aid: str,
    key_no: int,
    zero_key: bool,
    key_env: str | None,
    new_key_env: str,
    key_version: int,
    auth_key_no: int | None,
    auth_zero_key: bool,
    auth_key_env: str | None,
) -> None:
    """Change a DESFire AES key.

    Same-key (default): authenticate with the key being changed; pass its current value
    via --zero-key/--key-env. Cross-key: authenticate with a different key
    (--auth-key-no plus --auth-zero-key/--auth-key-env, typically the app master key 0)
    while --zero-key/--key-env give the CURRENT value of the target key - the card needs
    it to recover and CRC-check the new key (a wrong value is cleanly rejected).
    """
    aid_bytes = _aid3(aid)
    current = _resolve_aes_key(app, zero_key, key_env)
    new_value = os.environ.get(new_key_env)
    if not new_value:
        raise CryptnoxError(f"environment variable {new_key_env} is not set.")
    new_key = from_hex(new_value)
    if len(new_key) != 16:
        raise CryptnoxError("new AES key must be 16 bytes (AES-128).")
    app.redactor.register(new_key)
    cross = auth_key_no is not None and auth_key_no != key_no
    if (auth_zero_key or auth_key_env) and not cross:
        raise click.UsageError(
            "--auth-* options need --auth-key-no set to a key other than --key-no "
            "(that is what makes it a cross-key change)."
        )
    auth_key = None
    if cross:
        if not (auth_zero_key or auth_key_env):
            raise click.UsageError(
                "cross-key change needs --auth-zero-key or --auth-key-env "
                "(the key you authenticate with)."
            )
        auth_key = _resolve_aes_key(app, auth_zero_key, auth_key_env)
    app.out.warn(
        f"changing key {key_no} of {aid.upper()} - keep the new key safe; a lost/wrong key "
        "can lock the application (recoverable only via the PICC master key)."
    )
    if not app.yes and not click.confirm("Proceed with the key change?", default=False):
        raise click.Abort()
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        if cross and auth_key is not None and auth_key_no is not None:
            ev2 = authenticate_ev2_first(dtx, auth_key_no, auth_key)
            change_key_cross(dtx, ev2, key_no, new_key, current, key_version=key_version)
        else:
            ev2 = authenticate_ev2_first(dtx, key_no, current)
            change_key_same(dtx, ev2, key_no, new_key, key_version=key_version)
    app.out.result(
        {
            "aid": aid.upper(),
            "key_no": key_no,
            "changed": True,
            "mode": "cross" if cross else "same",
            "auth_key_no": auth_key_no if cross else key_no,
        },
        lambda c: c.print(
            f"[green]Changed key {key_no}[/green] of {aid.upper()} "
            + (f"(cross-key; authenticated with key {auth_key_no})." if cross else "(same-key).")
            + " Re-authenticate with the new key now."
        ),
    )


@files.command("create-standard")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex (e.g. 01).")
@click.option("--size", required=True, type=int, help="File size in bytes.")
@click.option("--full", is_flag=True, help="CommMode.FULL (encrypted); key-0 for read+write.")
@click.pass_obj
def files_create_standard(app: AppContext, aid: str, file_id: str, size: int, full: bool) -> None:
    """Create a standard data file. Default: MAC comm, free read / key-0 write.
    With --full: encrypted (FULL) comm, key-0 for both read and write."""
    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    comm, access = (0x03, 0x0000) if full else (0x01, 0xE000)
    app.out.warn("this modifies the DESFire file system.")
    if not app.yes and not click.confirm(
        f"Create file {file_no:02X} ({size} B) in {aid.upper()}?", default=False
    ):
        raise click.Abort()
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        dtx.create_std_data_file(file_no, size, comm=comm, access=access)
    mode = "FULL/encrypted, key-0 r+w" if full else "free read, key-0 wr"
    app.out.result(
        {"aid": aid.upper(), "file": f"{file_no:02X}", "size": size, "full": full, "created": True},
        lambda c: c.print(
            f"[green]Created standard file {file_no:02X}[/green] ({size} B, {mode})."
        ),
    )


@command.command("write")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--in", "in_", type=click.Path(exists=True, dir_okay=False), help="Data file.")
@click.option("--data", "data_hex", help="Inline data as hex (alternative to --in).")
@click.option("--offset", default=0, show_default=True, type=int)
@click.option("--full", is_flag=True, help="CommMode.FULL (encrypt the data on the wire).")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Environment variable holding the AES key (hex).")
@click.pass_obj
def write(
    app: AppContext,
    aid: str,
    file_id: str,
    in_: str | None,
    data_hex: str | None,
    offset: int,
    full: bool,
    key_no: int,
    zero_key: bool,
    key_env: str | None,
) -> None:
    """Write data to a file (EV2-authenticated). MACed by default, encrypted with --full."""
    if bool(in_) == bool(data_hex):
        raise click.UsageError("provide exactly one of --in or --data")
    payload = Path(in_).read_bytes() if in_ else from_hex(data_hex or "")
    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    key = _resolve_aes_key(app, zero_key, key_env)
    app.out.warn(f"this overwrites data in file {file_no:02X} of {aid.upper()} on the card.")
    if not app.yes and not click.confirm(
        f"Write {len(payload)} bytes to file {file_no:02X} at offset {offset}?", default=False
    ):
        raise click.Abort()
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        ev2 = authenticate_ev2_first(dtx, key_no, key)
        header = dtx.data_header(file_no, offset, len(payload))
        if full:
            command_full(
                dtx,
                ev2,
                df.CMD_WRITE_DATA,
                header=header,
                plaintext=payload,
                context="WriteData (FULL)",
            )
        else:
            # Large payloads are split automatically (0x91AF chaining) by command_macked.
            command_macked(dtx, ev2, df.CMD_WRITE_DATA, header + payload, context="WriteData")
    app.out.result(
        {
            "aid": aid.upper(),
            "file": f"{file_no:02X}",
            "written": len(payload),
            "offset": offset,
            "full": full,
        },
        lambda c: c.print(
            f"[green]Wrote {len(payload)} bytes[/green] to file {file_no:02X} "
            f"({'EV2 encrypted' if full else 'EV2 MACed'})."
        ),
    )


@command.command("read")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--offset", default=0, show_default=True, type=int)
@click.option("--length", default=0, show_default=True, type=int, help="0 = whole file.")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write bytes to FILE.")
@click.option("--full", is_flag=True, help="CommMode.FULL (decrypt); needs a key and --length.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key",
    is_flag=True,
    help="Use the all-zero AES key (publicly known factory default; FULL only).",
)
@click.option("--key-env", help="Env var holding the AES key (FULL only).")
@click.pass_obj
def read(
    app: AppContext,
    aid: str,
    file_id: str,
    offset: int,
    length: int,
    out_: str | None,
    full: bool,
    key_no: int,
    zero_key: bool,
    key_env: str | None,
) -> None:
    """Read data from a file. Plain by default (free-read files); --full decrypts (EV2)."""
    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    if full and length <= 0:
        raise click.UsageError("--full requires --length (the number of bytes to read).")
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        if full:
            key = _resolve_aes_key(app, zero_key, key_env)
            ev2 = authenticate_ev2_first(dtx, key_no, key)
            data = command_full(
                dtx,
                ev2,
                df.CMD_READ_DATA,
                header=dtx.data_header(file_no, offset, length),
                response_len=length,
                context="ReadData (FULL)",
            )
        else:
            data = dtx.read_data_plain(file_no, offset, length)
    if out_:
        Path(out_).write_bytes(data)
    # Parity with `piv objects read`: pass read-back bytes through the redactor so a
    # registered secret never echoes to stdout/JSON (file content is otherwise non-secret).
    shown_hex = None if out_ else app.redactor.mask(data.hex().upper())
    payload = {
        "aid": aid.upper(),
        "file": f"{file_no:02X}",
        "length": len(data),
        "out": out_,
        "hex": shown_hex,
    }
    app.out.result(
        payload,
        lambda c: c.print(
            f"[green]Read {len(data)} bytes -> {out_}[/green]"
            if out_
            else f"file {file_no:02X} ({len(data)} B): {shown_hex}"
        ),
    )


@command.command("format")
@click.option("--key-no", default=0, show_default=True, type=int, help="PICC master key number.")
@click.option(
    "--zero-key",
    is_flag=True,
    help="PICC master key is the all-zero AES key (publicly known factory default).",
)
@click.option("--key-env", help="Env var with the PICC master AES key (hex).")
@click.option(
    "--i-understand-this-erases-all-applications",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.pass_obj
def format_command(
    app: AppContext, key_no: int, zero_key: bool, key_env: str | None, understood: bool
) -> None:
    """IRREVERSIBLY erase ALL DESFire applications and files (the PICC master key is kept)."""
    app.out.warn(
        "This ERASES every DESFire application and file on the card. "
        "The PICC master key and its settings are kept."
    )
    if not understood:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                "mifare format needs --i-understand-this-erases-all-applications non-interactively."
            )
        if click.prompt("Type FORMAT-PICC to continue") != "FORMAT-PICC":
            raise click.Abort()
    key = _resolve_aes_key(app, zero_key, key_env)
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(bytes(3))  # AID 000000 = PICC (master application) level
        _settings, key_type, _max_keys = dtx.get_key_settings()
        if key_type != 0x80:  # not AES -> AuthenticateEV2First cannot be used
            kind = {0x00: "DES/2K3DES", 0x40: "3K3DES"}.get(key_type, f"0x{key_type:02X}")
            raise CryptnoxError(
                f"the PICC master key is {kind}, not AES. FormatPICC must authenticate with "
                "the PICC master key, and this AES-only CLI cannot use a legacy DES/3DES key. "
                "Formatting is only possible once the PICC master key is provisioned to AES."
            )
        ev2 = authenticate_ev2_first(dtx, key_no, key)
        format_picc(dtx, ev2)
    app.out.result(
        {"formatted": True},
        lambda c: c.print(
            "[green]PICC formatted.[/green] All applications and files erased; "
            "the PICC master key is unchanged."
        ),
    )


@command.group("value")
def value_group() -> None:
    """DESFire value files (credit / debit with transactions)."""


@value_group.command("create")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--initial", default=0, show_default=True, type=int, help="Initial value.")
@click.option("--lower", default=0, show_default=True, type=int, help="Lower limit.")
@click.option("--upper", default=1_000_000, show_default=True, type=int, help="Upper limit.")
@click.pass_obj
def value_create(
    app: AppContext, aid: str, file_id: str, initial: int, lower: int, upper: int
) -> None:
    """Create a value file (comm mode MAC; key-0 for get/credit/debit)."""
    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    app.out.warn("this modifies the DESFire file system.")
    if not app.yes and not click.confirm(
        f"Create value file {file_no:02X} in {aid.upper()} (initial {initial})?", default=False
    ):
        raise click.Abort()
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        dtx.create_value_file(file_no, lower, upper, initial)
    app.out.result(
        {"aid": aid.upper(), "file": f"{file_no:02X}", "initial": initial, "created": True},
        lambda c: c.print(
            f"[green]Created value file {file_no:02X}[/green] (initial {initial}, "
            f"limits {lower}..{upper})."
        ),
    )


def _value_session(
    app: AppContext, aid: str, file_id: str, key_no: int, zero_key: bool, key_env: str | None
):
    """Open a session, select the app, and EV2-authenticate; returns (dtx, ev2, file_no)."""
    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    key = _resolve_aes_key(app, zero_key, key_env)
    session = app.open_session()
    dtx = DesfireTransport(session)
    dtx.select_application(aid_bytes)
    ev2 = authenticate_ev2_first(dtx, key_no, key)
    return session, dtx, ev2, file_no


@value_group.command("get")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Env var holding the AES key (hex).")
@click.pass_obj
def value_get(
    app: AppContext, aid: str, file_id: str, key_no: int, zero_key: bool, key_env: str | None
) -> None:
    """Read a value file's current value (EV2 MACed)."""
    session, dtx, ev2, file_no = _value_session(app, aid, file_id, key_no, zero_key, key_env)
    with session:
        data = command_macked(dtx, ev2, df.CMD_GET_VALUE, bytes([file_no]), context="GetValue")
    value = df.parse_value(data)
    app.out.result(
        {"aid": aid.upper(), "file": f"{file_no:02X}", "value": value},
        lambda c: c.print(f"value file {file_no:02X}: [bold]{value}[/bold]"),
    )


def _credit_debit(app, aid, file_id, amount, key_no, zero_key, key_env, *, cmd, verb):
    session, dtx, ev2, file_no = _value_session(app, aid, file_id, key_no, zero_key, key_env)
    with session:
        command_macked(dtx, ev2, cmd, dtx.value_arg(file_no, amount), context=verb)
        command_macked(dtx, ev2, df.CMD_COMMIT_TXN, context="CommitTransaction")
    app.out.result(
        {"aid": aid.upper(), "file": f"{file_no:02X}", verb.lower(): amount, "committed": True},
        lambda c: c.print(
            f"[green]{verb} {amount}[/green] on value file {file_no:02X} (committed)."
        ),
    )


@value_group.command("credit")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--amount", required=True, type=int, help="Amount to add.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Env var holding the AES key (hex).")
@click.pass_obj
def value_credit(app, aid, file_id, amount, key_no, zero_key, key_env):
    """Credit (add to) a value file, then commit the transaction."""
    _credit_debit(
        app, aid, file_id, amount, key_no, zero_key, key_env, cmd=df.CMD_CREDIT, verb="Credit"
    )


@value_group.command("debit")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--amount", required=True, type=int, help="Amount to subtract.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Env var holding the AES key (hex).")
@click.pass_obj
def value_debit(app, aid, file_id, amount, key_no, zero_key, key_env):
    """Debit (subtract from) a value file, then commit the transaction."""
    _credit_debit(
        app, aid, file_id, amount, key_no, zero_key, key_env, cmd=df.CMD_DEBIT, verb="Debit"
    )


@command.group("record")
def record_group() -> None:
    """DESFire record files (linear / cyclic)."""


@record_group.command("create")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--record-size", required=True, type=int, help="Bytes per record.")
@click.option("--max-records", required=True, type=int, help="Max records (cyclic keeps 1 spare).")
@click.option("--cyclic", is_flag=True, help="Cyclic (ring) instead of linear.")
@click.pass_obj
def record_create(
    app: AppContext, aid: str, file_id: str, record_size: int, max_records: int, cyclic: bool
) -> None:
    """Create a record file (comm mode MAC; key-0 for write/read)."""
    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    kind = "cyclic" if cyclic else "linear"
    app.out.warn("this modifies the DESFire file system.")
    if not app.yes and not click.confirm(
        f"Create {kind} record file {file_no:02X} ({max_records}x{record_size}B)?", default=False
    ):
        raise click.Abort()
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        dtx.create_record_file(file_no, record_size, max_records, cyclic=cyclic)
    app.out.result(
        {
            "aid": aid.upper(),
            "file": f"{file_no:02X}",
            "kind": kind,
            "record_size": record_size,
            "max_records": max_records,
            "created": True,
        },
        lambda c: c.print(
            f"[green]Created {kind} record file {file_no:02X}[/green] "
            f"({max_records} x {record_size} B)."
        ),
    )


@record_group.command("write")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--in", "in_", type=click.Path(exists=True, dir_okay=False), help="Record data file.")
@click.option("--data", "data_hex", help="Inline record data as hex.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Env var holding the AES key (hex).")
@click.pass_obj
def record_write(
    app: AppContext,
    aid: str,
    file_id: str,
    in_: str | None,
    data_hex: str | None,
    key_no: int,
    zero_key: bool,
    key_env: str | None,
) -> None:
    """Append a record (EV2 MACed) and commit the transaction."""
    if bool(in_) == bool(data_hex):
        raise click.UsageError("provide exactly one of --in or --data")
    payload = Path(in_).read_bytes() if in_ else from_hex(data_hex or "")
    session, dtx, ev2, file_no = _value_session(app, aid, file_id, key_no, zero_key, key_env)
    with session:
        command_macked(
            dtx,
            ev2,
            df.CMD_WRITE_RECORD,
            dtx.data_header(file_no, 0, len(payload)) + payload,
            context="WriteRecord",
        )
        command_macked(dtx, ev2, df.CMD_COMMIT_TXN, context="CommitTransaction")
    app.out.result(
        {"aid": aid.upper(), "file": f"{file_no:02X}", "written": len(payload), "committed": True},
        lambda c: c.print(
            f"[green]Wrote a {len(payload)}-byte record[/green] to {file_no:02X} (committed)."
        ),
    )


@record_group.command("read")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--count", default=0, show_default=True, type=int, help="Records to read (0 = all).")
@click.option("--offset", default=0, show_default=True, type=int, help="Record offset.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Env var holding the AES key (hex).")
@click.pass_obj
def record_read(
    app: AppContext,
    aid: str,
    file_id: str,
    count: int,
    offset: int,
    key_no: int,
    zero_key: bool,
    key_env: str | None,
) -> None:
    """Read records (EV2 MACed)."""
    session, dtx, ev2, file_no = _value_session(app, aid, file_id, key_no, zero_key, key_env)
    with session:
        data = command_macked(
            dtx,
            ev2,
            df.CMD_READ_RECORDS,
            dtx.data_header(file_no, offset, count),
            context="ReadRecords",
        )
    app.out.result(
        {
            "aid": aid.upper(),
            "file": f"{file_no:02X}",
            "length": len(data),
            "hex": app.redactor.mask(data.hex().upper()),
        },
        lambda c: c.print(
            f"records of {file_no:02X} ({len(data)} B): {app.redactor.mask(data.hex().upper())}"
        ),
    )


@record_group.command("clear")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.option("--key-no", default=0, show_default=True, type=int)
@click.option(
    "--zero-key", is_flag=True, help="Use the all-zero AES key (publicly known factory default)."
)
@click.option("--key-env", help="Env var holding the AES key (hex).")
@click.pass_obj
def record_clear(
    app: AppContext, aid: str, file_id: str, key_no: int, zero_key: bool, key_env: str | None
) -> None:
    """Clear all records (EV2 MACed) and commit."""
    file_no = int(file_id, 16)
    app.out.warn(f"this permanently erases ALL records in file {file_no:02X} of {aid.upper()}.")
    if not app.yes and not click.confirm(f"Clear record file {file_no:02X}?", default=False):
        raise click.Abort()
    session, dtx, ev2, file_no = _value_session(app, aid, file_id, key_no, zero_key, key_env)
    with session:
        command_macked(
            dtx, ev2, df.CMD_CLEAR_RECORD_FILE, bytes([file_no]), context="ClearRecordFile"
        )
        command_macked(dtx, ev2, df.CMD_COMMIT_TXN, context="CommitTransaction")
    app.out.result(
        {"aid": aid.upper(), "file": f"{file_no:02X}", "cleared": True},
        lambda c: c.print(f"[green]Cleared record file {file_no:02X}[/green] (committed)."),
    )


@command.group("sdm")
def sdm_group() -> None:
    """DESFire EV3 Secure Dynamic Messaging (SDM / SUN) - per NXP AN12196.

    Configures a free-read NDEF file so the card mirrors an encrypted UID + read counter
    and an SDMMAC into its URL on every read; `sdm read` decrypts and verifies them. The
    application must already exist with at least 3 AES keys (SDM uses key 2 to encrypt the
    PICCData and key 1 for the MAC); on a fresh app those keys are all-zero.
    """


@sdm_group.command("setup")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex (app needs >=3 keys).")
@click.option("--file-id", required=True, type=str, help="File number, hex (e.g. 02).")
@click.option("--url", default="https://cryptnox.example/t", show_default=True)
@click.option(
    "--zero-key",
    is_flag=True,
    help="App master key 0 is the all-zero AES key (publicly known factory default).",
)
@click.option("--key-env", help="Env var holding the app master key 0 AES key (hex).")
@click.pass_obj
def sdm_setup(
    app: AppContext, aid: str, file_id: str, url: str, zero_key: bool, key_env: str | None
) -> None:
    """Create an SDM-enabled file, write its NDEF URL template, and configure SDM (EV3 only).

    ChangeFileSettings authenticates with app master key 0: pass --zero-key (the publicly
    known factory default of a fresh application) or --key-env NAME.
    """
    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    key = _resolve_aes_key(app, zero_key, key_env)
    prefix = (url + "?picc=").encode()
    picc_off = len(prefix)
    sep = b"&c="
    mac_off = picc_off + 32 + len(sep)  # PICCData mirror is 32 ASCII hex chars
    template = prefix + b"0" * 32 + sep + b"0" * 16  # CMAC mirror is 16 ASCII hex chars
    size = max(len(template), 96)
    app.out.warn("creates + configures an SDM file (EV3); needs an app with >=3 AES keys.")
    if not app.yes and not click.confirm(
        f"Set up SDM on file {file_no:02X} of {aid.upper()}?", default=False
    ):
        raise click.Abort()

    def le3(n: int) -> bytes:
        return n.to_bytes(3, "little")

    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        # SDM must be enabled at creation (FileOption bit 0x40); plain comm, free read/write,
        # key-0 change-settings. Then write the template (free, plain, chunked under one frame).
        dtx.create_std_data_file(file_no, size, comm=0x00, access=0xEEE0, sdm=True)
        for off in range(0, len(template), 40):
            chunk = template[off : off + 40]
            st, _ = dtx.raw_command(
                df.CMD_WRITE_DATA,
                DesfireTransport.data_header(file_no, off, len(chunk)) + chunk,
                context="WriteData (SDM template)",
            )
            if st != df.STATUS_OK:
                raise df.DesfireError(st, "WriteData (SDM template)")
        # SDM file settings (AN12196): SDMOptions C1 = UID + read-counter + ASCII mirroring;
        # SDMAccessRights F1 21 = MetaRead key2 / FileRead key1 / CtrRet key1; then the 3-byte
        # little-endian offsets PICCData, SDMMACInput(=MAC -> empty input), SDMMAC.
        settings = (
            bytes([0x40])
            + (0xEEE0).to_bytes(2, "little")
            + bytes([0xC1, 0xF1, 0x21])
            + le3(picc_off)
            + le3(mac_off)
            + le3(mac_off)
        )
        ev2 = authenticate_ev2_first(dtx, 0, key)
        change_file_settings(dtx, ev2, file_no, settings, context="ChangeFileSettings SDM")
    app.out.result(
        {"aid": aid.upper(), "file": f"{file_no:02X}", "sdm": True, "template": template.decode()},
        lambda c: c.print(
            f"[green]SDM configured[/green] on file {file_no:02X} of {aid.upper()}.\n"
            f"  template: {template.decode()}"
        ),
    )


@sdm_group.command("read")
@click.option("--aid", required=True, help="Application AID, 3 bytes hex.")
@click.option("--file-id", required=True, type=str, help="File number, hex.")
@click.pass_obj
def sdm_read(app: AppContext, aid: str, file_id: str) -> None:
    """Free-read the SDM file; decrypt the mirrored PICCData and verify the SDMMAC (AN12196).

    Verification assumes the SDM keys (app keys 2 and 1) still hold their all-zero value,
    the publicly known factory default of a fresh application. A tag whose SDM keys were
    rotated fails this check while being perfectly genuine.
    """
    import re

    aid_bytes = _aid3(aid)
    file_no = int(file_id, 16)
    with app.open_session() as session:
        dtx = DesfireTransport(session)
        dtx.select_application(aid_bytes)
        text = dtx.read_data_plain(file_no, 0, 0).decode("ascii", "replace")
    m_picc = re.search(r"picc=([0-9A-Fa-f]{32})", text)
    m_cmac = re.search(r"&c=([0-9A-Fa-f]{16})", text)
    if not (m_picc and m_cmac):
        raise CryptnoxError("no SDM mirrors (picc=/&c=) found in the file - is SDM configured?")
    zero = bytes(16)  # SDM keys are app keys 2/1, all-zero on a fresh app
    uid, ctr = sdm_decrypt_picc(zero, bytes.fromhex(m_picc.group(1)))
    valid = sdm_file_read_mac(zero, uid, ctr, b"") == bytes.fromhex(m_cmac.group(1))
    payload = {
        "url": text,
        "uid": uid.hex().upper(),
        "read_counter": ctr,
        "sdmmac_valid": valid,
        "keys_assumed": "all-zero factory default (app keys 2/1)",
    }

    def human(c: Console) -> None:
        c.print(f"NDEF: {text}")
        c.print(f"  decrypted UID: {uid.hex().upper()}")
        c.print(f"  read counter:  {ctr}")
        if valid:
            c.print("  SDMMAC: [green]verified[/green] (with the all-zero factory default keys)")
        else:
            c.print(
                "  SDMMAC: [red]did not verify with the all-zero factory default keys[/red]\n"
                "  a tag whose SDM keys were rotated fails this check while being genuine\n"
                "  (the decrypted UID and counter above are then garbage as well)."
            )

    app.out.result(payload, human)
