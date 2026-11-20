# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Interactive shell: loop survives bad input, exits cleanly, inherits globals."""

import click
import pytest
from click.testing import CliRunner

from cryptnox_id_cli.cli.commands.shell import _global_args
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main


def _run(stdin: str, args=None):
    return CliRunner().invoke(main, [*(args or []), "shell"], input=stdin)


def test_shell_shows_banner_and_exits():
    r = _run("exit\n")
    assert r.exit_code == 0
    assert "interactive shell" in r.output


def test_shell_exits_on_eof():
    r = _run("")  # empty stdin -> EOF
    assert r.exit_code == 0


def test_shell_survives_unknown_command_then_exits():
    r = _run("boguscmd\nexit\n")
    assert r.exit_code == 0
    assert "No such command" in r.output


def test_shell_help_lists_subcommands():
    r = _run("help\nexit\n")
    assert r.exit_code == 0
    assert "piv" in r.output and "fido" in r.output


def test_shell_blank_lines_are_skipped():
    r = _run("\n\n\nquit\n")
    assert r.exit_code == 0


def test_shell_swaps_sys_argv_while_running_a_line():
    """The Windows FIDO elevation offer rebuilds its UAC relaunch from sys.argv
    (transport/elevation.relaunch_command); inside the shell it must see the typed
    command, not 'shell' — relaunching 'shell' elevated would hang both processes."""
    import sys as _sys

    import click

    seen: list[list[str]] = []

    @click.command("argvprobe", hidden=True)
    def probe() -> None:
        seen.append(list(_sys.argv))

    main.add_command(probe)
    try:
        before = list(_sys.argv)
        r = _run("argvprobe\nexit\n")
        assert r.exit_code == 0
        assert seen and seen[0][1:] == ["argvprobe"]
        assert _sys.argv == before  # restored after the line
    finally:
        main.commands.pop("argvprobe", None)


def test_global_args_reconstructs_launch_options():
    app = AppContext(reader="Generic", json=True, dry_run=True, timeout=30)
    args = _global_args(app)
    assert args[:2] == ["--reader", "Generic"]
    assert "--json" in args and "--dry-run" in args
    assert "--timeout" in args and "30" in args


def test_global_args_empty_for_defaults():
    assert _global_args(AppContext()) == []


def test_shell_survives_a_declined_confirmation():
    r = _run("mifare app delete --aid 010203\nn\nboguscmd\nexit\n")
    assert r.exit_code == 0, r.output
    assert "Aborted!" in r.output
    assert "No such command" in r.output


@pytest.mark.parametrize("raised", [KeyboardInterrupt, EOFError], ids=["ctrl-c", "eof"])
def test_shell_survives_an_interrupted_command(raised):
    @click.command("interruptprobe", hidden=True)
    def probe() -> None:
        raise raised

    main.add_command(probe)
    try:
        r = _run("interruptprobe\nboguscmd\nexit\n")
    finally:
        main.commands.pop("interruptprobe", None)
    assert r.exit_code == 0, r.output
    assert "No such command" in r.output


def test_global_args_carries_every_launch_option():
    app = AppContext(
        reader="R",
        json=True,
        verbose=True,
        apdu_log_path="t.log",
        dry_run=True,
        yes=True,
        timeout=30,
        no_color=True,
    )
    assert _global_args(app) == [
        "--reader",
        "R",
        "--json",
        "--verbose",
        "--apdu-log",
        "t.log",
        "--dry-run",
        "--yes",
        "--timeout",
        "30",
        "--no-color",
    ]


def test_shell_clears_the_screen_and_keeps_going():
    r = _run("clear\nexit\n")
    assert r.exit_code == 0, r.output


def test_shell_reports_unbalanced_quotes_and_keeps_going():
    r = _run('piv info "unclosed\nexit\n')
    assert r.exit_code == 0, r.output
    assert "error: No closing quotation" in r.output


def test_shell_survives_a_command_that_exits():
    r = _run("fido config min-pin-length --length 3\nexit\n", args=["--yes"])
    assert r.exit_code == 0, r.output
    assert "minimum PIN length must be at least 4" in r.output


def test_ctrl_c_at_the_prompt_cancels_the_line_not_the_shell(monkeypatch):
    from cryptnox_id_cli.cli.commands import shell as shell_cmd

    class _Stdin:
        lines = iter([KeyboardInterrupt, "exit\n"])

        def isatty(self):
            return False

        def readline(self):
            line = next(self.lines)
            if line is KeyboardInterrupt:
                raise KeyboardInterrupt
            return line

    class _Sys:
        stdin = _Stdin()

        def __getattr__(self, name):
            return getattr(__import__("sys"), name)

    monkeypatch.setattr(shell_cmd, "sys", _Sys())
    r = _run("")
    assert r.exit_code == 0, r.output
