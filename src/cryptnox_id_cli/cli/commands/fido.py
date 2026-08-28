"""``fido`` — FIDO2 / CTAP 2.1 inspection and management.

``ping``, ``info``/``get-info``, ``pin status`` and ``config show`` only read;
``pin set``/``change``, the ``credential`` commands and ``config`` policy changes
write to the card, and ``reset`` irreversibly erases every credential and the PIN.

Windows reserves direct PC/SC access to the FIDO2/CTAP AID for the WebAuthn
platform API and blocks non-elevated processes (SCARD_E_NO_ACCESS). Every command
states that requirement (and the reason) up front; when not elevated it offers to
relaunch itself through a UAC prompt and surfaces the elevated result back here.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import click
from rich.console import Console

from cryptnox_id_cli.applets.fido import authdata
from cryptnox_id_cli.applets.fido import constants as fido_c
from cryptnox_id_cli.applets.fido.ctap import Ctap2Client, describe_get_info
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.elevation import (
    FIDO_WINDOWS_MESSAGE,
    fido_elevation_status,
    is_windows,
    relaunch_elevated,
)
from cryptnox_id_cli.transport.errors import CardAccessDeniedError, CryptnoxError
from cryptnox_id_cli.util.hexutil import from_hex

T = TypeVar("T")


@click.group("fido")
def command() -> None:
    """Manage the FIDO2 applet (needs an Administrator terminal on Windows).

    Inspection commands (`ping`, `info`, `pin status`, `config show`) only read;
    `pin`, `credential` and `config` commands write to the card, and `reset`
    irreversibly erases every credential and the PIN.
    """


def _with_fido(app: AppContext, action: Callable[[Ctap2Client], T]) -> T:
    """Open a session, run ``action`` with a CTAP client, translating the Windows
    OS block into the documented friendly message."""
    try:
        with app.open_session() as session:
            return action(Ctap2Client(session))
    except CardAccessDeniedError as exc:
        raise CardAccessDeniedError(FIDO_WINDOWS_MESSAGE, hresult=exc.hresult) from exc


def _render_elevated_result(app: AppContext, payload: dict) -> None:
    if app.json:
        sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
        return
    app.out.console.print("[dim]result (ran as Administrator):[/dim]")
    app.out.console.print_json(data=payload)


def _run_elevated(app: AppContext) -> None:
    """Relaunch this command via a UAC prompt, then surface the result here. Exits."""
    fd, tmp = tempfile.mkstemp(prefix="cnx-fido-", suffix=".json")
    os.close(fd)
    try:
        app.out.note("requesting elevation - approve the Windows UAC prompt...")
        code = relaunch_elevated(["--json", "--elevated-result-out", tmp])
        if code is None:
            # UAC declined or could not start: fall back to the documented guidance.
            raise CardAccessDeniedError(FIDO_WINDOWS_MESSAGE)
        text = Path(tmp).read_text(encoding="utf-8") if Path(tmp).exists() else ""
        if text.strip():
            _render_elevated_result(app, json.loads(text))
        elif code != 0:
            raise CryptnoxError(f"elevated FIDO2 command failed (exit {code}).")
        sys.exit(code)
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp)


def _ensure_fido_access(app: AppContext) -> None:
    """Surface the FIDO admin requirement (with the reason). If not elevated on
    Windows, offer to relaunch via a UAC prompt; on acceptance this does not return."""
    severity, message = fido_elevation_status()
    if severity != "warn":
        if message:
            app.out.note(message)
        return
    app.out.warn(message)
    if not is_windows():
        return
    # Offer the one-click UAC relaunch when we can interact (or --yes was given).
    offer = app.yes or (sys.stdin.isatty() and not app.json)
    if offer and (
        app.yes or click.confirm("Re-run this command as Administrator now?", default=True)
    ):
        _run_elevated(app)


@command.command("ping")
@click.pass_obj
def ping(app: AppContext) -> None:
    """Basic connectivity test: SELECT the FIDO2 applet and report its version string."""
    _ensure_fido_access(app)
    version = _with_fido(app, lambda ctap: ctap.select())
    app.out.result(
        {"selected": True, "version": version},
        lambda c: c.print(f"[green]FIDO2 applet selected.[/green] Version string: {version}"),
    )


def _get_info_payload(app: AppContext) -> dict[str, object]:
    def action(ctap: Ctap2Client) -> dict[str, object]:
        version = ctap.select()
        info = describe_get_info(ctap.get_info())
        info["select_version"] = version
        return info

    return _with_fido(app, action)


def _joined(value: object) -> str:
    if isinstance(value, list) and value:
        return ", ".join(str(v) for v in value)
    return "-"


def _render_info(app: AppContext, info: dict[str, object]) -> None:
    def human(c: Console) -> None:
        c.print("[bold]FIDO2 authenticator (authenticatorGetInfo)[/bold]")
        cryptnox = info.get("cryptnox_aaguid")
        rows = [
            ("Versions", _joined(info.get("versions"))),
            ("Extensions", _joined(info.get("extensions"))),
            ("AAGUID", str(info.get("aaguid"))),
            ("Cryptnox AAGUID", "yes" if cryptnox else ("no" if cryptnox is False else "-")),
            ("Max message size", str(info.get("max_msg_size"))),
            ("PIN/UV protocols", _joined(info.get("pin_uv_auth_protocols"))),
            ("Transports", _joined(info.get("transports"))),
            ("Min PIN length", str(info.get("min_pin_length") or "-")),
            ("Firmware", str(info.get("firmware_version") or "-")),
        ]
        table = app.out.table("Property", "Value")
        for name, value in rows:
            table.add_row(name, value)
        options = info.get("options")
        if isinstance(options, dict):
            for opt, val in sorted(options.items()):
                table.add_row(f"option {opt}", str(val))
        algorithms = info.get("algorithms")
        if isinstance(algorithms, list):
            algs = ", ".join(f"{a.get('alg')} ({a.get('type')})" for a in algorithms)
            table.add_row("Algorithms", algs)
        c.print(table)

    app.out.result(info, human)


@command.command("info")
@click.pass_obj
def info(app: AppContext) -> None:
    """Show the authenticator's capabilities (CTAP authenticatorGetInfo)."""
    _ensure_fido_access(app)
    _render_info(app, _get_info_payload(app))


@command.command("get-info")
@click.pass_obj
def get_info(app: AppContext) -> None:
    """Alias of ``fido info`` (raw CTAP authenticatorGetInfo)."""
    _ensure_fido_access(app)
    _render_info(app, _get_info_payload(app))


def _resolve_fido_pin(app: AppContext, env_var: str | None, label: str, *, confirm: bool) -> str:
    """Get a FIDO PIN from an env var or a masked prompt; register it for redaction."""
    value = os.environ.get(env_var) if env_var else None
    if value is None:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                f"{label} required: set ${env_var or 'a PIN env var'} or run interactively."
            )
        value = click.prompt(label, hide_input=True, confirmation_prompt=confirm)
    app.redactor.register(value.encode("utf-8"))
    return value


@command.group("pin")
def pin() -> None:
    """FIDO PIN: status, set (initial), change."""


@pin.command("status")
@click.pass_obj
def pin_status(app: AppContext) -> None:
    """Show whether a PIN is set and how many retries remain (non-destructive)."""
    _ensure_fido_access(app)

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        options = describe_get_info(ctap.get_info()).get("options")
        client_pin = options.get("clientPin") if isinstance(options, dict) else None
        retries: int | None = None
        power_cycle: bool | None = None
        if client_pin is not None:
            retries, power_cycle = ctap.pin_retries()
        return {
            "pin_supported": client_pin is not None,
            "pin_set": client_pin,
            "retries_remaining": retries,
            "power_cycle_required": power_cycle,
        }

    payload = _with_fido(app, action)

    def human(c: Console) -> None:
        if not payload["pin_supported"]:
            c.print("clientPin: [yellow]not supported by this authenticator[/yellow]")
            return
        state = "[green]set[/green]" if payload["pin_set"] else "[yellow]not set[/yellow]"
        c.print(f"FIDO PIN: {state}")
        if payload["retries_remaining"] is not None:
            c.print(f"  Retries remaining: {payload['retries_remaining']}")
        if payload["power_cycle_required"]:
            c.print(
                "  [yellow]PIN auth blocked for this power cycle - re-present the card.[/yellow]"
            )

    app.out.result(payload, human)


@pin.command("set")
@click.option("--pin-env", help="Env var holding the new PIN (else masked prompt).")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def pin_set(app: AppContext, pin_env: str | None, protocol: str) -> None:
    """Set the INITIAL FIDO PIN (only when none is set yet). Min 4 characters."""
    _ensure_fido_access(app)
    new_pin = _resolve_fido_pin(app, pin_env, "New FIDO PIN", confirm=True)

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        ctap.set_pin(new_pin, protocol=int(protocol))
        return {"pin_set": True, "protocol": int(protocol)}

    app.out.result(
        _with_fido(app, action),
        lambda c: c.print(
            "[green]FIDO PIN set.[/green] Keep it safe - it cannot be removed "
            "without an authenticator reset (which wipes all credentials)."
        ),
    )


@pin.command("change")
@click.option("--current-pin-env", help="Env var holding the current PIN (else prompt).")
@click.option("--new-pin-env", help="Env var holding the new PIN (else prompt).")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def pin_change(
    app: AppContext, current_pin_env: str | None, new_pin_env: str | None, protocol: str
) -> None:
    """Change the FIDO PIN. A wrong current PIN decrements the retry counter."""
    _ensure_fido_access(app)
    current_pin = _resolve_fido_pin(app, current_pin_env, "Current FIDO PIN", confirm=False)
    new_pin = _resolve_fido_pin(app, new_pin_env, "New FIDO PIN", confirm=True)

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        ctap.change_pin(current_pin, new_pin, protocol=int(protocol))
        return {"pin_changed": True, "protocol": int(protocol)}

    app.out.result(
        _with_fido(app, action),
        lambda c: c.print("[green]FIDO PIN changed.[/green]"),
    )


def _pin_token(
    app: AppContext,
    ctap: Ctap2Client,
    pin_env: str | None,
    permissions: int,
    rp_id: str | None,
    proto: int,
) -> bytes | None:
    """Obtain a pinUvAuthToken from a PIN env var, or None (let the card decide UV)."""
    if not pin_env:
        return None
    pin = os.environ.get(pin_env)
    if not pin:
        raise CryptnoxError(f"environment variable {pin_env} is not set.")
    app.redactor.register(pin.encode("utf-8"))
    return ctap.get_pin_token(pin, protocol=proto, permissions=permissions, rp_id=rp_id)


@command.group("credential")
def credential() -> None:
    """FIDO credentials: register, authenticate, end-to-end self-test.

    These are WRITE operations and require user presence (a tap). If the card has a
    PIN set, pass --pin-env NAME (an env var holding the PIN).
    """


@credential.command("self-test")
@click.option("--rp-id", default="cryptnox.local", show_default=True)
@click.option("--pin-env", help="Env var with the FIDO PIN (if the card requires UV).")
@click.option("--rk", is_flag=True, help="Use a resident (discoverable) credential.")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def credential_self_test(
    app: AppContext, rp_id: str, pin_env: str | None, rk: bool, protocol: str
) -> None:
    """Register a credential, get an assertion, and verify the signature - a full FIDO2
    round-trip proving the authenticator works. Requires a tap (user presence)."""
    _ensure_fido_access(app)
    proto = int(protocol)
    app.out.note("touch/tap the authenticator when it asks for user presence.")

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        perms = fido_c.PERM_MAKE_CREDENTIAL | fido_c.PERM_GET_ASSERTION
        token = _pin_token(app, ctap, pin_env, perms, rp_id, proto)
        cdh_reg = os.urandom(32)
        cred = ctap.make_credential(
            client_data_hash=cdh_reg,
            rp_id=rp_id,
            user_id=os.urandom(16),
            resident_key=rk,
            pin_uv_token=token,
            protocol=proto,
        )
        cred_id = cred["credential_id"]
        cdh_auth = os.urandom(32)
        token2 = _pin_token(app, ctap, pin_env, fido_c.PERM_GET_ASSERTION, rp_id, proto)
        assertion = ctap.get_assertion(
            rp_id=rp_id,
            client_data_hash=cdh_auth,
            allow_credential_ids=[cred_id] if isinstance(cred_id, bytes) else None,
            pin_uv_token=token2,
            protocol=proto,
        )
        verified = False
        pubkey = cred["credential_public_key"]
        auth_data = assertion["auth_data"]
        signature = assertion["signature"]
        if (
            isinstance(pubkey, dict)
            and isinstance(auth_data, bytes)
            and isinstance(signature, bytes)
        ):
            verified = authdata.verify_es256_assertion(pubkey, auth_data, cdh_auth, signature)
        return {
            "registered": True,
            "resident": rk,
            "credential_id": cred_id.hex().upper() if isinstance(cred_id, bytes) else None,
            "assertion_verified": verified,
        }

    payload = _with_fido(app, action)

    def human(c: Console) -> None:
        ok = payload["assertion_verified"]
        mark = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        c.print(f"FIDO2 register -> assert -> verify: {mark}")
        c.print(f"  credential id: {payload['credential_id']}")
        c.print(f"  signature verified against the registered key: {ok}")

    app.out.result(payload, human)


@credential.command("create")
@click.option("--rp-id", default="cryptnox.local", show_default=True)
@click.option("--user-name", default="cryptnox", show_default=True)
@click.option("--rk", is_flag=True, help="Resident (discoverable) credential.")
@click.option("--pin-env", help="Env var with the FIDO PIN (if required).")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def credential_create(
    app: AppContext, rp_id: str, user_name: str, rk: bool, pin_env: str | None, protocol: str
) -> None:
    """Register a credential (authenticatorMakeCredential). Requires a tap."""
    _ensure_fido_access(app)
    proto = int(protocol)
    app.out.note("touch/tap the authenticator when it asks for user presence.")

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        token = _pin_token(app, ctap, pin_env, fido_c.PERM_MAKE_CREDENTIAL, rp_id, proto)
        cred = ctap.make_credential(
            client_data_hash=os.urandom(32),
            rp_id=rp_id,
            user_id=os.urandom(16),
            user_name=user_name,
            resident_key=rk,
            pin_uv_token=token,
            protocol=proto,
        )
        cid = cred["credential_id"]
        return {
            "registered": True,
            "rp_id": rp_id,
            "credential_id": cid.hex().upper() if isinstance(cid, bytes) else None,
            "fmt": cred["fmt"],
        }

    payload = _with_fido(app, action)
    app.out.result(
        payload,
        lambda c: c.print(
            f"[green]Registered credential[/green] on {rp_id}.\n  id: {payload['credential_id']}"
        ),
    )


@credential.command("assert")
@click.option("--rp-id", default="cryptnox.local", show_default=True)
@click.option("--credential-id", help="Credential id (hex) for a non-resident credential.")
@click.option("--pin-env", help="Env var with the FIDO PIN (if required).")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def credential_assert(
    app: AppContext, rp_id: str, credential_id: str | None, pin_env: str | None, protocol: str
) -> None:
    """Get an assertion (authenticatorGetAssertion). Requires a tap."""
    _ensure_fido_access(app)
    proto = int(protocol)
    allow = [from_hex(credential_id)] if credential_id else None
    app.out.note("touch/tap the authenticator when it asks for user presence.")

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        token = _pin_token(app, ctap, pin_env, fido_c.PERM_GET_ASSERTION, rp_id, proto)
        assertion = ctap.get_assertion(
            rp_id=rp_id,
            client_data_hash=os.urandom(32),
            allow_credential_ids=allow,
            pin_uv_token=token,
            protocol=proto,
        )
        cid = assertion["credential_id"]
        signature = assertion["signature"]
        return {
            "asserted": True,
            "credential_id": cid.hex().upper() if isinstance(cid, bytes) else None,
            "signature_len": len(signature) if isinstance(signature, bytes) else 0,
            "number_of_credentials": assertion["number_of_credentials"],
        }

    payload = _with_fido(app, action)
    app.out.result(
        payload,
        lambda c: c.print(
            f"[green]Assertion OK[/green] (credential {payload['credential_id']}, "
            f"{payload['signature_len']}-byte signature)."
        ),
    )


def _user_label(user: object) -> str:
    if isinstance(user, dict):
        return str(user.get("name") or user.get("displayName") or "?")
    return "?"


@credential.command("list")
@click.option("--pin-env", required=True, help="Env var with the FIDO PIN (credMgmt needs UV).")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def credential_list(app: AppContext, pin_env: str, protocol: str) -> None:
    """List resident credentials (authenticatorCredentialManagement)."""
    _ensure_fido_access(app)
    proto = int(protocol)

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        token = _pin_token(app, ctap, pin_env, fido_c.PERM_CREDENTIAL_MGMT, None, proto)
        if token is None:
            raise CryptnoxError("credential management requires a PIN (set the --pin-env var).")
        existing, remaining = ctap.get_creds_metadata(token, protocol=proto)
        creds = ctap.enumerate_credentials(token, protocol=proto)
        return {
            "existing": existing,
            "max_remaining": remaining,
            "credentials": [
                {
                    "rp_id": x["rp_id"],
                    "user": _user_label(x["user"]),
                    "credential_id": x["credential_id"].hex().upper()
                    if isinstance(x["credential_id"], bytes)
                    else None,
                }
                for x in creds
            ],
        }

    payload = _with_fido(app, action)

    def human(c: Console) -> None:
        c.print(
            f"Resident credentials: [bold]{payload['existing']}[/bold] "
            f"(room for ~{payload['max_remaining']} more)"
        )
        for cr in payload["credentials"]:  # type: ignore[attr-defined]
            c.print(f"  - rp={cr['rp_id']}  user={cr['user']}  id={cr['credential_id']}")

    app.out.result(payload, human)


@credential.command("delete")
@click.option("--credential-id", required=True, help="Credential id (hex) to delete.")
@click.option("--pin-env", required=True, help="Env var with the FIDO PIN.")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def credential_delete(app: AppContext, credential_id: str, pin_env: str, protocol: str) -> None:
    """Delete a resident credential by id (authenticatorCredentialManagement)."""
    _ensure_fido_access(app)
    proto = int(protocol)
    cid = from_hex(credential_id)
    if not app.yes and not click.confirm(
        f"Delete credential {credential_id[:16]}...?", default=False
    ):
        raise click.Abort()

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        token = _pin_token(app, ctap, pin_env, fido_c.PERM_CREDENTIAL_MGMT, None, proto)
        if token is None:
            raise CryptnoxError("credential management requires a PIN (set the --pin-env var).")
        ctap.delete_credential(cid, token, protocol=proto)
        return {"deleted": True, "credential_id": credential_id.upper()}

    app.out.result(
        _with_fido(app, action),
        lambda c: c.print("[green]Deleted credential.[/green]"),
    )


@command.group("config")
def config() -> None:
    """authenticatorConfig: device-wide policy (alwaysUv, minimum PIN length).

    Changing policy needs the authenticatorConfiguration permission, so pass
    --pin-env NAME when a clientPIN is set. Bio enrollment, large-blob and
    enterprise attestation are not implemented by this applet (see `config show`).
    """


def _fido_options(ctap: Ctap2Client) -> dict:
    opts = describe_get_info(ctap.get_info()).get("options")
    return opts if isinstance(opts, dict) else {}


@config.command("show")
@click.pass_obj
def config_show(app: AppContext) -> None:
    """Show the configuration policy and which config operations the applet supports."""
    _ensure_fido_access(app)

    def action(ctap: Ctap2Client) -> dict[str, object]:
        version = ctap.select()
        info = describe_get_info(ctap.get_info())
        opts = info.get("options")
        opts = opts if isinstance(opts, dict) else {}
        return {
            "select_version": version,
            "authenticator_config_supported": bool(opts.get("authnrCfg")),
            "set_min_pin_length_supported": bool(opts.get("setMinPINLength")),
            "always_uv": opts.get("alwaysUv"),
            "min_pin_length": info.get("min_pin_length"),
            "make_cred_uv_not_required": opts.get("makeCredUvNotRqd"),
            "enterprise_attestation": opts.get("ep"),
            "client_pin_set": opts.get("clientPin"),
        }

    payload = _with_fido(app, action)

    def human(c: Console) -> None:
        c.print("[bold]authenticatorConfig policy[/bold]")
        ep = payload["enterprise_attestation"]
        rows = [
            ("authenticatorConfig supported", payload["authenticator_config_supported"]),
            ("alwaysUv", payload["always_uv"]),
            ("min PIN length", payload["min_pin_length"]),
            ("setMinPINLength supported", payload["set_min_pin_length_supported"]),
            ("makeCredUvNotRqd", payload["make_cred_uv_not_required"]),
            ("enterprise attestation", "not supported" if ep is None else ep),
            ("clientPIN set", payload["client_pin_set"]),
        ]
        table = app.out.table("Property", "Value")
        for name, value in rows:
            table.add_row(name, str(value))
        c.print(table)
        c.print("[dim]bio enrollment and large-blob are not implemented by this applet.[/dim]")

    app.out.result(payload, human)


@config.command("toggle-always-uv")
@click.option("--pin-env", help="Env var with the FIDO PIN (required when a clientPIN is set).")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def config_toggle_always_uv(app: AppContext, pin_env: str | None, protocol: str) -> None:
    """Toggle alwaysUv: when on, every makeCredential/getAssertion requires user verification."""
    _ensure_fido_access(app)
    app.out.warn(
        "This flips a DEVICE-WIDE authenticator policy: alwaysUv applies to every "
        "credential and every relying party using this authenticator."
    )
    if not app.yes and not click.confirm("Toggle alwaysUv now?", default=False):
        raise click.Abort()
    proto = int(protocol)

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        before = _fido_options(ctap).get("alwaysUv")
        token = _pin_token(app, ctap, pin_env, fido_c.PERM_AUTHENTICATOR_CONFIG, None, proto)
        ctap.toggle_always_uv(pin_uv_token=token, protocol=proto)
        after = _fido_options(ctap).get("alwaysUv")
        return {"always_uv_before": before, "always_uv_after": after}

    payload = _with_fido(app, action)
    app.out.result(
        payload,
        lambda c: c.print(
            f"alwaysUv: {payload['always_uv_before']} -> [bold]{payload['always_uv_after']}[/bold]"
        ),
    )


@config.command("min-pin-length")
@click.option("--length", type=int, required=True, help="New minimum PIN length (>= 4).")
@click.option("--force-change-pin", is_flag=True, help="Force a PIN change on next use.")
@click.option("--pin-env", help="Env var with the FIDO PIN (required when a clientPIN is set).")
@click.option("--protocol", type=click.Choice(["1", "2"]), default="1", show_default=True)
@click.pass_obj
def config_min_pin_length(
    app: AppContext, length: int, force_change_pin: bool, pin_env: str | None, protocol: str
) -> None:
    """Raise the minimum FIDO PIN length. ONE-WAY: it can only increase; lowering it
    again requires `fido reset` (which wipes all credentials)."""
    _ensure_fido_access(app)
    if length < 4:
        raise CryptnoxError("minimum PIN length must be at least 4.")
    proto = int(protocol)
    app.out.warn(
        "setMinPINLength only INCREASES the minimum; it cannot be lowered except by "
        "'fido reset' (which erases all credentials)."
    )
    if not app.yes:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                "fido config min-pin-length is one-way and needs confirmation: "
                "pass --yes to proceed with --json or piped stdin."
            )
        if not click.confirm(f"Set minimum PIN length to {length}?", default=False):
            raise click.Abort()

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        before = describe_get_info(ctap.get_info()).get("min_pin_length")
        token = _pin_token(app, ctap, pin_env, fido_c.PERM_AUTHENTICATOR_CONFIG, None, proto)
        ctap.set_min_pin_length(
            length, force_change_pin=force_change_pin or None, pin_uv_token=token, protocol=proto
        )
        after = describe_get_info(ctap.get_info()).get("min_pin_length")
        return {
            "min_pin_length_before": before,
            "min_pin_length_after": after,
            "force_change_pin": force_change_pin,
        }

    payload = _with_fido(app, action)
    app.out.result(
        payload,
        lambda c: c.print(
            f"min PIN length: {payload['min_pin_length_before']} -> "
            f"[bold]{payload['min_pin_length_after']}[/bold]"
        ),
    )


@command.command("reset")
@click.option(
    "--i-understand-this-wipes-all-credentials",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.pass_obj
def reset(app: AppContext, understood: bool) -> None:
    """IRREVERSIBLY reset the FIDO2 authenticator: erases ALL credentials and the PIN."""
    _ensure_fido_access(app)
    app.out.warn("This ERASES every FIDO2 credential and the PIN on this authenticator.")
    if not understood:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                "fido reset needs --i-understand-this-wipes-all-credentials non-interactively."
            )
        if click.prompt("Type RESET-FIDO to continue") != "RESET-FIDO":
            raise click.Abort()
    app.out.note(
        "authenticatorReset usually must be issued shortly after the card is presented "
        "and needs a tap (user presence); re-present the card if it is refused."
    )

    def action(ctap: Ctap2Client) -> dict[str, object]:
        ctap.select()
        ctap.reset()
        return {"reset": True}

    app.out.result(
        _with_fido(app, action),
        lambda c: c.print(
            "[green]FIDO2 authenticator reset.[/green] All credentials + PIN erased."
        ),
    )
