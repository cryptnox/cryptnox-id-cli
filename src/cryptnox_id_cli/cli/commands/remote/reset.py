# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``remote reset`` and ``remote dev-reset``: the irreversible rewrite of the PIV
function, and the applet build the service installs."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import relay
from cryptnox_id_cli.transport.errors import CryptnoxError, RemoteError

from .card import BUILD_NAMES, Card, build_matches, build_text, inventory, open_card
from .render import (
    print_channel,
    print_checks,
    print_header,
    print_inventory,
    print_nfc_admin_lock,
    print_result,
    warn_channel,
    warn_nfc_admin_lock,
)
from .run import (
    cross_check,
    endpoint,
    exit_if_unverified,
    relay_info,
    relay_operation,
    warn_contactless_reader,
)

#: Phrases typed to confirm the irreversible operations interactively.
RESET_PHRASE = "RESET-PIV"
DEV_RESET_PHRASE = "DEV-RESET-PIV"

#: PIV applet builds the service can install, by the name its protocol uses
#: (``piv_variant``). Both are built from the same source and carry the same
#: applet and package identifiers; the applet reports which one it is.
PIV_BUILDS = ("fips", "fipsoff")
DEFAULT_PIV_BUILD = "fips"

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
    "and commands are the same. The build with FIPS mode off holds no FIPS 140-3 "
    "validation."
)


def resolve_piv_build(piv_variant: str | None, fips_off: bool) -> str:
    """The build to request from ``--piv-variant`` and ``--fips-off``."""
    if fips_off and piv_variant is not None and piv_variant.lower() != "fipsoff":
        raise click.UsageError("--fips-off and --piv-variant fips contradict each other.")
    if fips_off:
        return "fipsoff"
    return (piv_variant or DEFAULT_PIV_BUILD).lower()


def service_offers_build(url: str, build: str) -> bool | None:
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


def confirm_destructive(
    app: AppContext,
    op: str,
    phrase: str,
    understood: bool,
    card: Card,
    default_keys: bool,
    piv_build: str = DEFAULT_PIV_BUILD,
) -> dict[str, object]:
    """Show what is about to be destroyed and obtain consent. Returns the inventory."""
    before = inventory(card)
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
    elif build_matches("fipsoff", before.get("piv_build")):
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
        print_inventory(app.out.console, "Before", before)
    if not understood:
        if app.json or not sys.stdin.isatty():
            raise CryptnoxError(
                f"remote {op} needs --i-understand-this-is-irreversible non-interactively."
            )
        if click.prompt(f"Type {phrase} to continue") != phrase:
            raise click.Abort()
    return before


def run_destructive(
    ctx: click.Context,
    op: str,
    *,
    default_keys: bool,
    understood: bool,
    phrase: str,
    piv_build: str = DEFAULT_PIV_BUILD,
) -> None:
    app: AppContext = ctx.obj
    url, _production = endpoint(op)  # refuses any override for these operations
    # Sent explicitly either way, so behaviour never depends on the service's own default.
    params: dict[str, object] = {"fused": not default_keys, "piv_variant": piv_build}
    if piv_build != DEFAULT_PIV_BUILD and service_offers_build(url, piv_build) is False:
        raise CryptnoxError(
            f"the service does not offer the PIV applet {BUILD_NAMES[piv_build]} at the "
            "moment (`remote ping` lists what it offers). Nothing was sent to the card."
        )

    card = open_card(app)
    try:
        warn_contactless_reader(app, card, refused=False)
        before = confirm_destructive(app, op, phrase, understood, card, default_keys, piv_build)
        app.out.note(f"remote {op} via {url}")
        report = relay_operation(app, ctx, card, op, params, url)
        after = inventory(card)
    finally:
        card.conn.disconnect()

    card_info = card.to_dict()
    checks = cross_check(card_info, report.result)
    checks["piv_present_after"] = after["piv_state"] not in ("PivNotPresent", "PivUnknown")
    ssd_after = after.get("piv_ssd_key_versions")
    checks["piv_ssd_present_after"] = ssd_after is not None
    # The applet says which build it is; the service's word alone is not the check.
    checks["piv_build_matches"] = build_matches(piv_build, after.get("piv_build"))
    if checks["piv_build_matches"] is False:
        app.out.warn(
            f"the card does not carry the requested PIV applet {BUILD_NAMES[piv_build]}: "
            f"it reports {build_text(after.get('piv_build'))}."
        )
    relayed = relay_info(report)
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
        "relay": relayed,
    }

    def human(c: Console) -> None:
        print_header(c, op, url, card_info, relayed)
        print_channel(c, report.result, expected=True)
        print_result(c, report.result)
        print_nfc_admin_lock(c, report.result)
        c.print()
        print_inventory(c, "After", after)
        print_checks(c, checks)

    app.out.result(payload, human)
    warn_channel(app, report.result)
    warn_nfc_admin_lock(app, report.result)
    if build_matches("fipsoff", after.get("piv_build")):
        app.out.warn(
            "the card now carries the PIV applet build with FIPS mode off, which holds no "
            "FIPS 140-3 validation."
        )
    exit_if_unverified(app, checks)


def piv_build_options(fn):  # noqa: ANN001, ANN202 - a click decorator stack
    fn = click.option("--fips-off", "fips_off", is_flag=True, help=_FIPS_OFF_HELP)(fn)
    return click.option(
        "--piv-variant",
        "piv_variant",
        type=click.Choice(PIV_BUILDS, case_sensitive=False),
        default=None,
        help=_PIV_VARIANT_HELP,
    )(fn)


@click.command("reset")
@click.option("--default-keys", "default_keys", is_flag=True, help=_RESET_DEFAULT_KEYS_HELP)
@piv_build_options
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
    run_destructive(
        ctx,
        "reset",
        default_keys=default_keys,
        understood=understood,
        phrase=RESET_PHRASE,
        piv_build=resolve_piv_build(piv_variant, fips_off),
    )


@click.command("dev-reset")
@click.option("--default-keys", "default_keys", is_flag=True, help=_DEV_RESET_DEFAULT_KEYS_HELP)
@piv_build_options
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
    run_destructive(
        ctx,
        "dev-reset",
        default_keys=default_keys,
        understood=understood,
        phrase=DEV_RESET_PHRASE,
        piv_build=resolve_piv_build(piv_variant, fips_off),
    )
