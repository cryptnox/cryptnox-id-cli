# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The ``shell`` command — a captive interactive prompt.

Launched from a Start-menu shortcut or by hand, it reads a line, runs it as a
subcommand (type ``piv info`` — no program-name prefix), and loops. Only this
CLI's own commands run; it is not an OS shell. Global options passed when
launching the shell (``--reader``, ``--json``, …) carry into every command.
"""

from __future__ import annotations

import contextlib
import shlex
import sys

import click

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.cli.context import AppContext

_PROMPT = f"{CLI_NAME}> "
_BANNER = (
    f"{CLI_NAME} interactive shell. Type a command without the "
    f"'{CLI_NAME}' prefix (e.g. 'piv info').\n"
    "  help            show available commands\n"
    "  <command> -h    help for a command\n"
    "  clear           clear the screen\n"
    "  exit / quit     leave the shell\n"
)


def _global_args(app: AppContext) -> list[str]:
    """Reconstruct the global options the shell was launched with, so every command
    inherits them (the reader choice above all)."""
    args: list[str] = []
    if app.reader:
        args += ["--reader", app.reader]
    if app.json:
        args.append("--json")
    if app.verbose:
        args.append("--verbose")
    if app.apdu_log_path:
        args += ["--apdu-log", app.apdu_log_path]
    if app.dry_run:
        args.append("--dry-run")
    if app.yes:
        args.append("--yes")
    if app.timeout != 15:
        args += ["--timeout", str(app.timeout)]
    if app.no_color:
        args.append("--no-color")
    return args


@click.command("shell")
@click.pass_context
def command(ctx: click.Context) -> None:
    """Start an interactive prompt that runs this CLI's subcommands."""
    root = ctx.find_root().command  # the top-level group; avoids importing main (circular)
    app = ctx.obj
    base = _global_args(app)

    # Line editing / history only when attached to a real terminal. Two reasons: readline
    # is pointless on piped input, and (crucially) an imported readline makes input() read
    # the terminal fd directly, which would bypass a redirected sys.stdin - so a piped or
    # test-driven stdin must go through sys.stdin.readline() instead.
    interactive = sys.stdin.isatty()
    if interactive:  # pragma: no cover - terminal-only
        # Windows stdlib has no readline; input() still works, just without history.
        with contextlib.suppress(ImportError):
            import readline  # noqa: F401

    def _next_line() -> str:
        if interactive:
            return input(_PROMPT)
        line = sys.stdin.readline()
        if not line:  # EOF on a pipe
            raise EOFError
        return line.rstrip("\n")

    click.echo(_BANNER)
    while True:
        try:
            line = _next_line().strip()
        except EOFError:  # Ctrl-D / end of pipe
            click.echo()
            break
        except KeyboardInterrupt:  # Ctrl-C cancels the line, not the shell
            click.echo()
            continue

        if not line:
            continue
        low = line.lower()
        if low in ("exit", "quit"):
            break
        if low == "help":
            line = "--help"
        elif low == "clear":
            click.clear()
            continue

        try:
            argv = base + shlex.split(line)
        except ValueError as exc:  # unbalanced quotes
            click.echo(f"error: {exc}", err=True)
            continue

        # A fresh root invocation per line gives each command its own AppContext and SCP03 session.
        # Workaround: the Windows FIDO elevation relaunch rebuilds its command from sys.argv, and
        # relaunching "shell" elevated hangs both processes, so swap in the typed line.
        saved_argv = sys.argv
        try:
            sys.argv = [saved_argv[0], *argv]
            root.main(args=argv, prog_name=CLI_NAME, standalone_mode=False)
        except SystemExit:
            pass  # error already reported via the group's funnel; keep the shell alive
        except click.ClickException as exc:
            exc.show()
        except click.exceptions.Abort:
            # Click turns Ctrl-C and end of input into Abort, the same as a declined prompt.
            click.echo("Aborted!", err=True)
        finally:
            sys.argv = saved_argv
