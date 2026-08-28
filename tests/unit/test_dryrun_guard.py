"""Fail-closed --dry-run enforcement.

Safety review 2026-08-21, finding 1 (high): the global --dry-run was honored by only a
handful of commands; everything else executed for real, so `--dry-run fido reset ...`
actually wiped the authenticator. The guard makes every command that cannot plan its
card operations REFUSE under --dry-run, before a card session is opened.
"""

from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from cryptnox_id_cli.cli import dryrun
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root


def _leaves() -> set[str]:
    out: set[str] = set()

    def walk(group: click.Group, prefix: str) -> None:
        for name, cmd in group.commands.items():
            path = f"{prefix}{name}"
            if isinstance(cmd, click.Group):
                walk(cmd, path + " ")
            else:
                out.add(path)

    walk(root, "")
    return out


def test_every_command_is_classified_exactly_once():
    """Adding a command without deciding its dry-run class must break this test."""
    leaves = _leaves()
    classified = dryrun.PLANS_OWN | dryrun.READ_ONLY | dryrun.NO_DRY_RUN
    assert leaves - classified == set(), f"unclassified commands: {sorted(leaves - classified)}"
    assert classified - leaves == set(), f"stale entries: {sorted(classified - leaves)}"
    assert set() == dryrun.PLANS_OWN & dryrun.READ_ONLY
    assert set() == dryrun.PLANS_OWN & dryrun.NO_DRY_RUN
    assert set() == dryrun.READ_ONLY & dryrun.NO_DRY_RUN


@pytest.fixture
def no_session(monkeypatch):
    """Any attempt to open a card session fails the test."""

    def boom(self):  # pragma: no cover - only on regression
        raise AssertionError("a card session was opened under --dry-run")

    monkeypatch.setattr(AppContext, "open_session", boom)


@pytest.mark.parametrize(
    "argv",
    [
        ["--dry-run", "fido", "reset", "--i-understand-this-wipes-all-credentials"],
        ["--dry-run", "mifare", "format", "--i-understand-this-erases-all-applications"],
        ["--dry-run", "piv", "perso", "set-pin"],
        ["--dry-run", "fido", "pin", "set"],
    ],
)
def test_unplannable_mutating_commands_refuse_under_dry_run(no_session, argv):
    result = CliRunner().invoke(root, argv)
    assert result.exit_code != 0
    assert "nothing was sent to the card" in result.output
    # The refusal names the command so the user knows the flag was seen, not ignored.
    assert "--dry-run" in result.output


def test_read_only_command_still_runs_under_dry_run(monkeypatch):
    """`piv status` must reach open_session (i.e. NOT be refused) under --dry-run."""
    sentinel = RuntimeError("reached open_session")

    def opened(self):
        raise sentinel

    monkeypatch.setattr(AppContext, "open_session", opened)
    result = CliRunner().invoke(root, ["--dry-run", "piv", "status"])
    assert "nothing was sent to the card" not in result.output
    assert result.exit_code != 0 and isinstance(result.exception, RuntimeError)


def test_planning_command_still_plans_under_dry_run(tmp_path, no_session):
    """apdu transcript plans under --dry-run without a card - must stay allowed."""
    f = tmp_path / "t.json"
    f.write_text('["00A4040000"]')
    result = CliRunner().invoke(root, ["--dry-run", "apdu", "transcript", "--file", str(f)])
    assert result.exit_code == 0, result.output


def test_without_dry_run_the_guard_is_inert(monkeypatch):
    """The wrapper must not change normal execution: fido reset still reaches its gate."""
    sentinel = RuntimeError("reached open_session")

    def opened(self):
        raise sentinel

    monkeypatch.setattr(AppContext, "open_session", opened)
    result = CliRunner().invoke(
        root, ["fido", "reset", "--i-understand-this-wipes-all-credentials"]
    )
    # Not refused by the dry-run guard; it proceeded into the command body.
    assert "nothing was sent to the card" not in result.output
    assert isinstance(result.exception, RuntimeError)
