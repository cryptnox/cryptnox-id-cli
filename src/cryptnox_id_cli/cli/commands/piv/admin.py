# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv admin``: the SCP03 admin channel and the PIV security domain's keys."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from cryptnox_id_cli.applets.piv.admin import InitializeUpdateRejected, PivAdmin, scp_label
from cryptnox_id_cli.applets.piv.ssd import (
    CRYPTNOX_KEY_VERSION,
    CUSTOMER_KEY_VERSION,
    PIV_SSD_AID,
    SecurityDomainInfo,
    delete_key_version_apdu,
    describe_security_domain,
    kcv,
    put_key_apdu,
    select_security_domain,
)
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.secrets.resolver import (
    DEFAULT_GP_KEY,
    resolve_new_scp03_keys,
    resolve_scp03_keys,
)
from cryptnox_id_cli.transport.errors import CryptnoxError, Scp02Error, Scp03Error, StatusWordError
from cryptnox_id_cli.transport.scp02 import Scp02Session
from cryptnox_id_cli.transport.scp03 import Scp03Keys


# ------------------------------------------------------------------ admin --- #
@click.group("admin")
def admin() -> None:
    """PIV administrative operations over SCP03 (vendor: OpenFIPS201)."""


def _require_security_domain(session) -> SecurityDomainInfo:  # noqa: ANN001
    domain = describe_security_domain(session)
    if domain is None:
        raise CryptnoxError(
            "No security domain answered: neither the PIV security domain "
            f"({PIV_SSD_AID.hex().upper()}) nor the ISD is selectable on this interface."
        )
    return domain


def _print_key_table(app: AppContext, c: Console, domain: SecurityDomainInfo) -> None:
    c.print(f"PIV admin security domain {domain.aid_hex} ({scp_label(domain.scp_version)}):")
    if not domain.keys:
        c.print(f"  key table withheld (SW={domain.key_table_sw:04X})")
        return
    table = app.out.table("Key version", "Key ID", "Type", "Length")
    for k in domain.keys:
        table.add_row(str(k.key_version), str(k.key_id), k.type_name, f"{k.length} B")
    c.print(table)


@admin.command("status")
@click.pass_obj
def admin_status(app: AppContext) -> None:
    """Show the admin security domain's SCP version and key versions (no authentication)."""
    with app.open_session() as session:
        domain = _require_security_domain(session)

    def human(c: Console) -> None:
        _print_key_table(app, c, domain)
        c.print(
            "  Read without authenticating; nothing counted against the card's "
            "failed-authentication limit. Run `piv admin authenticate` to open the channel."
        )

    app.out.result(domain.to_dict(), human)


def _check_default_key(app: AppContext, session) -> dict[str, object]:  # noqa: ANN001
    """One authentication to the customer key version with the GlobalPlatform default
    key. Success is a completed authentication, so it leaves the card's
    failed-authentication count clear; a wrong key costs one."""
    keys = resolve_scp03_keys(app.redactor, default_keys=True)
    adm = PivAdmin(session)
    adm.select()
    result: dict[str, object] = {"performed": True, "key_version": CUSTOMER_KEY_VERSION}
    try:
        adm.open(keys, key_version=CUSTOMER_KEY_VERSION)
    except InitializeUpdateRejected as exc:
        return {**result, "answers_to_default": None, "detail": str(exc)}
    except (Scp02Error, Scp03Error) as exc:
        return {
            **result,
            "answers_to_default": False,
            "detail": str(exc),
            "failed_authentication_counted": True,
        }
    return {
        **result,
        "answers_to_default": True,
        "scp_version": scp_label(adm.scp_version),
        "failed_authentication_counted": False,
    }


def _default_key_verdict(check: dict[str, object] | None) -> str:
    if check is None:
        return "not checked (pass --check-default)"
    if not check["performed"]:
        return f"not checked ({check['reason']})"
    answers = check["answers_to_default"]
    if answers is True:
        return (
            "[red]YES[/red]. Anyone can administer this card's PIV applet; replace the "
            "key before deployment."
        )
    if answers is False:
        return (
            f"no ({check['detail']}). One failed authentication is now counted on the "
            "card; a successful `piv admin authenticate` clears it."
        )
    return f"undetermined ({check['detail']})"


@admin.command("keys")
@click.option(
    "--check-default",
    is_flag=True,
    help=f"Authenticate once to key version {CUSTOMER_KEY_VERSION} with the publicly known "
    "GlobalPlatform test key. A wrong key counts as one failed authentication on the card.",
)
@click.pass_obj
def admin_keys(app: AppContext, check_default: bool) -> None:
    """List the admin security domain's key table (no authentication).

    With --check-default, also test whether the customer key version still answers
    to the GlobalPlatform default key. That is one authentication attempt, never a
    search over candidate keys.
    """
    with app.open_session() as session:
        domain = _require_security_domain(session)
        check: dict[str, object] | None = None
        if check_default:
            if app.dry_run:
                check = {"performed": False, "reason": "dry-run"}
            elif CUSTOMER_KEY_VERSION not in domain.key_versions:
                check = {
                    "performed": False,
                    "reason": f"key version {CUSTOMER_KEY_VERSION} is not in the key table",
                }
            else:
                app.out.warn(
                    "a wrong key counts as one failed authentication on the card; five in a "
                    "row slow every later authentication down until one succeeds."
                )
                check = _check_default_key(app, session)

    def human(c: Console) -> None:
        _print_key_table(app, c, domain)
        c.print(
            f"  Key version {CUSTOMER_KEY_VERSION} answers to the GlobalPlatform default key: "
            f"{_default_key_verdict(check)}"
        )

    app.out.result({**domain.to_dict(), "default_key_check": check}, human)


def _open_domain_channel(session, aid: bytes, keys: Scp03Keys, key_version: int) -> PivAdmin:  # noqa: ANN001
    """A secure channel to the security domain itself (not through the PIV applet),
    which is where PUT KEY and DELETE KEY are processed."""
    resp = select_security_domain(session, aid)
    if not resp.ok:
        raise CryptnoxError(f"SELECT {aid.hex().upper()} failed (SW={resp.sw_hex()}).")
    adm = PivAdmin(session)
    adm.open(keys, key_version=key_version)
    return adm


def _key_encryption_key(adm: PivAdmin, keys: Scp03Keys) -> bytes:
    """SCP02 wraps new key values under the session DEK, SCP03 under the static one."""
    if isinstance(adm.scp, Scp02Session):
        return adm.scp.s_dek
    return keys.dek


def _hex_list(values: list[bytes]) -> list[str]:
    return [v.hex().upper() for v in values]


@admin.command("rotate-keys")
@click.option(
    "--default-keys",
    is_flag=True,
    help="The CURRENT keys are the publicly known GlobalPlatform test keys (a card as shipped).",
)
@click.option("--dry-run", is_flag=True, help="Show the plan; send nothing.")
@click.pass_obj
def admin_rotate_keys(app: AppContext, default_keys: bool, dry_run: bool) -> None:
    """Replace key version 1 of the PIV security domain in place.

    Current keys: --default-keys or PIV_SCP03_ENC/MAC/DEK. New keys: PIV_SCP03_NEW_ENC/
    MAC/DEK (hex, 16 bytes each), never the command line. Key version 2, Cryptnox's
    keyset for remote reset and attestation, is never addressed.
    """
    new_keys = resolve_new_scp03_keys(app.redactor)
    if new_keys == Scp03Keys.same(DEFAULT_GP_KEY):
        raise CryptnoxError("the new keys are the publicly known test keys; choose your own.")
    planning = dry_run or app.dry_run
    current = None if planning else resolve_scp03_keys(app.redactor, default_keys=default_keys)
    if current is not None and current == new_keys:
        raise CryptnoxError("the new keys equal the current ones; nothing to rotate.")
    with app.open_session() as session:
        before = _require_security_domain(session)
        if CUSTOMER_KEY_VERSION not in before.key_versions:
            raise CryptnoxError(
                f"key version {CUSTOMER_KEY_VERSION} is not in the key table of "
                f"{before.aid_hex}; nothing to replace."
            )
        if before.scp_version is None:
            raise CryptnoxError(
                f"cannot tell SCP02 from SCP03 from the key table of {before.aid_hex}; refusing."
            )
        label = scp_label(before.scp_version)
        new_kcvs = [kcv(before.scp_version, k) for k in (new_keys.enc, new_keys.mac, new_keys.dek)]
        if planning:
            plan = {
                "dry_run": True,
                "aid": before.aid_hex,
                "scp_version": label,
                "replace_version": CUSTOMER_KEY_VERSION,
                "new_version": CUSTOMER_KEY_VERSION,
                "new_key_kcvs": _hex_list(new_kcvs),
                "key_versions": before.key_versions,
            }

            def plan_human(c: Console) -> None:
                c.print(
                    f"[bold]DRY RUN[/bold] - would replace key version {CUSTOMER_KEY_VERSION} of "
                    f"{before.aid_hex} ({label}) in place with one PUT KEY."
                )
                c.print(f"  New key check values: {' '.join(_hex_list(new_kcvs))} (ENC MAC DEK)")
                c.print(f"  Key versions on the card: {before.key_versions}; only 1 is addressed.")
                c.print("\n  [dim]Nothing was sent to the card.[/dim]")

            app.out.result(plan, plan_human)
            return

        if current is None:  # unreachable: resolved above whenever not planning
            raise RuntimeError("current keys were not resolved")
        app.out.warn(
            f"this replaces key version {CUSTOMER_KEY_VERSION} of {before.aid_hex}; the current "
            "keys stop working the moment the card accepts the command."
        )
        if not app.yes and not click.confirm("Proceed with the rotation?", default=False):
            raise click.Abort()

        adm = _open_domain_channel(session, before.aid, current, CUSTOMER_KEY_VERSION)
        apdu, kcvs = put_key_apdu(
            before.scp_version,
            _key_encryption_key(adm, current),
            new_keys,
            replace_version=CUSTOMER_KEY_VERSION,
            new_version=CUSTOMER_KEY_VERSION,
        )
        resp = adm.send(apdu, context="PUT KEY")
        if not resp.ok:
            # The card writes nothing when it refuses PUT KEY; the current keys still work.
            raise StatusWordError(resp.sw1, resp.sw2, context="PUT KEY (rotate-keys)")
        card_kcvs_match = resp.data == bytes([CUSTOMER_KEY_VERSION]) + b"".join(kcvs)

        adm.forget_channel()
        verify_error: str | None = None
        try:
            _open_domain_channel(session, before.aid, new_keys, CUSTOMER_KEY_VERSION)
        except CryptnoxError as exc:
            verify_error = str(exc)
        after = describe_security_domain(session, (before.aid,))

    factory_before = before.keys_for(CRYPTNOX_KEY_VERSION)
    factory_after = after.keys_for(CRYPTNOX_KEY_VERSION) if after else None
    factory_unchanged = factory_after == factory_before
    payload = {
        "aid": before.aid_hex,
        "scp_version": label,
        "replaced_version": CUSTOMER_KEY_VERSION,
        "new_key_kcvs": _hex_list(kcvs),
        "card_kcvs_match": card_kcvs_match,
        "new_keys_authenticate": verify_error is None,
        "key_versions_before": before.key_versions,
        "key_versions_after": after.key_versions if after else None,
        "factory_keyset_unchanged": factory_unchanged,
    }

    def human(c: Console) -> None:
        c.print(
            f"[green]Replaced key version {CUSTOMER_KEY_VERSION}[/green] of {before.aid_hex} "
            f"({label})."
        )
        agree = "card agrees" if card_kcvs_match else "[red]card echoed different values[/red]"
        c.print(f"  Key check values: {' '.join(_hex_list(kcvs))} (ENC MAC DEK); {agree}")
        auth = "yes" if verify_error is None else f"[red]no[/red] ({verify_error})"
        c.print(f"  New keys authenticate: {auth}")
        if factory_before:
            word = "unchanged" if factory_unchanged else "[red]CHANGED[/red]"
            c.print(f"  Key version {CRYPTNOX_KEY_VERSION} (Cryptnox): {word}")
        else:
            c.print(f"  Key version {CRYPTNOX_KEY_VERSION} (Cryptnox): not on this card")
        c.print(
            "  From now on set PIV_SCP03_ENC / PIV_SCP03_MAC / PIV_SCP03_DEK to the new values."
        )

    app.out.result(payload, human)
    if not (card_kcvs_match and verify_error is None and factory_unchanged):
        raise CryptnoxError(
            "PUT KEY was accepted (SW 9000) but a post-check failed; see the lines above. "
            f"Key version {CUSTOMER_KEY_VERSION} now expects the new keys: confirm with "
            "`piv admin authenticate` using the PIV_SCP03_NEW_* values as PIV_SCP03_*."
        )


@admin.command("delete-factory-keyset")
@click.option(
    "--i-understand-this-is-irreversible",
    "understood",
    is_flag=True,
    help="Required for non-interactive use.",
)
@click.option("--dry-run", is_flag=True, help="Show the plan; send nothing.")
@click.pass_obj
def admin_delete_factory_keyset(app: AppContext, understood: bool, dry_run: bool) -> None:
    """IRREVERSIBLY delete key version 2, Cryptnox's keyset, from the PIV security domain.

    Cryptnox uses key version 2 for remote reset and attestation; without it those
    services cannot reach this card again. Authenticates with key version 1 from
    PIV_SCP03_ENC/MAC/DEK, which must no longer be the GlobalPlatform test keys.
    """
    planning = dry_run or app.dry_run
    keys = None if planning else resolve_scp03_keys(app.redactor)
    if keys is not None and keys == Scp03Keys.same(DEFAULT_GP_KEY):
        raise CryptnoxError(
            f"key version {CUSTOMER_KEY_VERSION} is still the publicly known test key; rotate "
            "it first (`piv admin rotate-keys`)."
        )
    with app.open_session() as session:
        before = _require_security_domain(session)
        factory = before.keys_for(CRYPTNOX_KEY_VERSION)
        if not factory:
            app.out.result(
                {"aid": before.aid_hex, "deleted": False, "key_versions": before.key_versions},
                lambda c: c.print(
                    f"Key version {CRYPTNOX_KEY_VERSION} is not on {before.aid_hex}; nothing to "
                    f"delete (key versions: {before.key_versions})."
                ),
            )
            return
        if planning:
            app.out.result(
                {
                    "dry_run": True,
                    "aid": before.aid_hex,
                    "would_delete_version": CRYPTNOX_KEY_VERSION,
                    "keys": [k.to_dict() for k in factory],
                },
                lambda c: c.print(
                    f"[bold]DRY RUN[/bold] - would delete key version {CRYPTNOX_KEY_VERSION} "
                    f"({len(factory)} keys) from {before.aid_hex}. Nothing was sent to the card."
                ),
            )
            return
        if keys is None:  # unreachable: resolved above whenever not planning
            raise RuntimeError("current keys were not resolved")
        if not understood:
            if app.json or not sys.stdin.isatty():
                raise CryptnoxError(
                    "delete-factory-keyset requires --i-understand-this-is-irreversible in "
                    "non-interactive mode."
                )
            app.out.warn(
                "This is IRREVERSIBLE: Cryptnox's remote reset and attestation will no longer "
                "reach this card."
            )
            if click.prompt("Type DELETE-FACTORY-KEYSET to continue") != "DELETE-FACTORY-KEYSET":
                raise click.Abort()

        adm = _open_domain_channel(session, before.aid, keys, CUSTOMER_KEY_VERSION)
        resp = adm.send(delete_key_version_apdu(CRYPTNOX_KEY_VERSION), context="DELETE KEY")
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context="DELETE KEY (delete-factory-keyset)")
        adm.forget_channel()
        after = describe_security_domain(session, (before.aid,))

    gone = after is not None and CRYPTNOX_KEY_VERSION not in after.key_versions
    payload = {
        "aid": before.aid_hex,
        "deleted": True,
        "sw": resp.sw_hex(),
        "key_versions_after": after.key_versions if after else None,
        "verified": gone,
    }

    def human(c: Console) -> None:
        c.print(
            f"[green]Deleted key version {CRYPTNOX_KEY_VERSION}[/green] from {before.aid_hex} "
            f"(SW={resp.sw_hex()})."
        )
        remaining = after.key_versions if after else "unknown"
        state = "confirmed" if gone else "[red]not confirmed[/red]"
        c.print(f"  Key table re-read: versions {remaining}; removal {state}.")

    app.out.result(payload, human)
    if not gone:
        raise CryptnoxError(
            f"DELETE KEY was accepted but key version {CRYPTNOX_KEY_VERSION} is still listed; "
            "re-run `piv admin keys`."
        )


@admin.command("authenticate")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option("--key-version", default=0, type=int, help="SCP03 key version (default 0).")
@click.pass_obj
def admin_authenticate(app: AppContext, default_keys: bool, key_version: int) -> None:
    """Open the PIV admin channel (mutual auth, auto-detecting SCP02/SCP03) and self-test."""
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    security_level = 0x03  # C-MAC + C-ENC
    with app.open_session() as session:
        adm = PivAdmin(session)
        adm.select()
        adm.open(keys, key_version=key_version, security_level=security_level)
        scp_ver_label = scp_label(adm.scp_version)
        resp = adm.self_test_read()
    self_ok = resp.ok or resp.sw == 0x6A82
    payload: dict[str, object] = {
        "authenticated": True,
        "scp_version": scp_ver_label,
        "security_level": f"{security_level:#04x}",
        "self_test_sw": resp.sw_hex(),
        "self_test_ok": self_ok,
    }

    def human(c: Console) -> None:
        c.print(
            f"[green]{scp_ver_label} secure channel established[/green] (mutual authentication OK)."
        )
        c.print(f"  Security level: {security_level:#04x} (C-MAC + C-ENC)")
        verdict = "OK" if self_ok else "unexpected"
        c.print(f"  Admin round-trip (wrapped GET DATA): SW={resp.sw_hex()} -> {verdict}")

    app.out.result(payload, human)
