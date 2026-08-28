"""Interactive shell: loop survives bad input, exits cleanly, inherits globals."""

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
