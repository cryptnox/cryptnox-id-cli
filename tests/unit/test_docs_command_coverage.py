"""Drift guard: the hand-maintained public command reference must cover the
real Click tree. The public docs build without importing this package (see the
documentation plan), so accuracy is enforced here, where the code lives."""

from pathlib import Path

import click

from cryptnox_id_cli.cli.main import main

DOCS_DIR = Path(__file__).resolve().parents[2] / "docs"


def _command_paths(group: click.Group, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    for name, cmd in group.commands.items():
        if getattr(cmd, "hidden", False):
            continue
        path = f"{prefix}{name}"
        paths.add(path)
        if isinstance(cmd, click.Group):
            paths |= _command_paths(cmd, f"{path} ")
    return paths


def test_every_command_appears_in_the_public_reference():
    # The command reference is spread across the per-applet "* commands" pages
    # (docs/<applet>/*-commands.rst) plus the top-level cli-basics page.
    rst_files = sorted(DOCS_DIR.glob("*/*commands.rst")) + [DOCS_DIR / "cli-basics.rst"]
    assert all(p.exists() for p in rst_files), f"missing reference pages: {rst_files}"
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in rst_files)
    missing = sorted(p for p in _command_paths(main) if p not in corpus)
    assert not missing, (
        "commands missing from the command reference pages: "
        f"{missing} - document them (or mark them hidden) before shipping"
    )
