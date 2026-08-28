"""CLI root group, global options and the error funnel."""

from __future__ import annotations

import json as _json
import sys

import click

from cryptnox_id_cli import CLI_NAME, __version__
from cryptnox_id_cli.cli import dryrun
from cryptnox_id_cli.cli.commands import apdu as apdu_cmd
from cryptnox_id_cli.cli.commands import doctor as doctor_cmd
from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.cli.commands import fido as fido_cmd
from cryptnox_id_cli.cli.commands import genuine as genuine_cmd
from cryptnox_id_cli.cli.commands import info as info_cmd
from cryptnox_id_cli.cli.commands import mifare as mifare_cmd
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.cli.commands import readers as readers_cmd
from cryptnox_id_cli.cli.commands import report as report_cmd
from cryptnox_id_cli.cli.commands import shell as shell_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.errors import CryptnoxError


def _report(app: AppContext | None, exc: CryptnoxError) -> None:
    if app is not None and app.json:
        sys.stdout.write(_json.dumps(exc.to_dict(), indent=2) + "\n")
    elif app is not None:
        app.out.error(str(exc))
    else:  # error before context creation
        click.echo(f"error: {exc}", err=True)


class CryptnoxCLI(click.Group):
    """Group that routes our own exceptions through the friendly error funnel."""

    def invoke(self, ctx: click.Context) -> object:
        try:
            return super().invoke(ctx)
        except CryptnoxError as exc:
            app = ctx.obj if isinstance(ctx.obj, AppContext) else None
            _report(app, exc)
            sys.exit(getattr(exc, "exit_code", 1))


@click.group(cls=CryptnoxCLI, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name=CLI_NAME)
@click.option("--reader", metavar="NAME|INDEX", help="Select PC/SC reader (default: Cryptnox/ACS).")
@click.option("--json", "json_", is_flag=True, help="Machine-readable JSON output.")
@click.option("--verbose", is_flag=True, help="Human-readable debug output (APDU trace to stderr).")
@click.option("--apdu-log", metavar="FILE", help="Append a redacted APDU transcript to FILE.")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Write nothing to the card: commands that can plan show the intended actions; "
    "commands that cannot refuse to run (fail-closed).",
)
@click.option("--yes", is_flag=True, help="Skip destructive confirmation prompts.")
@click.option("--timeout", type=int, default=15, show_default=True, help="Reader/card timeout (s).")
@click.option("--no-color", is_flag=True, help="Disable coloured output.")
@click.option(
    "--elevated-result-out", hidden=True, help="Internal: capture result JSON (elevation)."
)
@click.pass_context
def main(
    ctx: click.Context,
    reader: str | None,
    json_: bool,
    verbose: bool,
    apdu_log: str | None,
    dry_run: bool,
    yes: bool,
    timeout: int,
    no_color: bool,
    elevated_result_out: str | None,
) -> None:
    """Manage the Cryptnox multi-applet smartcard (PIV / FIDO2 / DESFire).

    PIV management, factory pre-personalization and personalization run over a
    contact or contactless reader; MIFARE DESFire needs a contactless reader; FIDO2
    needs an Administrator terminal on Windows. Cryptnox/ACS readers are picked by default.
    """
    ctx.obj = AppContext(
        reader=reader,
        json=json_,
        verbose=verbose,
        apdu_log_path=apdu_log,
        dry_run=dry_run,
        yes=yes,
        timeout=timeout,
        no_color=no_color,
        elevated_result_out=elevated_result_out,
    )
    ctx.call_on_close(ctx.obj.close)


main.add_command(readers_cmd.command)
main.add_command(info_cmd.command)
main.add_command(doctor_cmd.command)
main.add_command(apdu_cmd.command)
main.add_command(piv_cmd.command)
main.add_command(mifare_cmd.command)
main.add_command(fido_cmd.command)
main.add_command(genuine_cmd.command)
main.add_command(report_cmd.command)
main.add_command(factory_cmd.command)
main.add_command(shell_cmd.command)

# Enforce the --dry-run promise fail-closed: commands that cannot plan their card
# operations refuse to run under --dry-run instead of silently executing for real.
dryrun.install_guard(main)


if __name__ == "__main__":
    main()
