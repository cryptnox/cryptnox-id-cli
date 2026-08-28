"""Unified output: each command builds a JSON-able payload plus a human renderer."""

from __future__ import annotations

import json as _json
import sys
from collections.abc import Callable

from rich.console import Console
from rich.table import Table


class Output:
    """Holds the rendering policy (JSON vs human, colour) for one CLI invocation."""

    def __init__(
        self,
        *,
        json: bool = False,
        no_color: bool = False,
        verbose: bool = False,
        result_path: str | None = None,
    ) -> None:
        self.json = json
        self.verbose = verbose
        # When set (elevated child), the result payload is also written here as JSON so
        # the non-elevated parent can surface it in the original console.
        self.result_path = result_path
        # In JSON mode we keep stdout pure (no rich), so diagnostics go to stderr.
        self.console = Console(no_color=no_color, highlight=False, soft_wrap=True)
        self.err = Console(stderr=True, no_color=no_color, highlight=False, soft_wrap=True)

    # -- results ------------------------------------------------------------ #
    def result(self, payload: dict, render_human: Callable[[Console], None]) -> None:
        if self.result_path:
            with open(self.result_path, "w", encoding="utf-8") as fh:
                fh.write(_json.dumps(payload, indent=2, default=str) + "\n")
        if self.json:
            sys.stdout.write(_json.dumps(payload, indent=2, default=str) + "\n")
        else:
            render_human(self.console)

    # -- ad-hoc messages (suppressed or routed to stderr in JSON mode) ------ #
    def info(self, message: str) -> None:
        if not self.json:
            self.console.print(message)

    def detail(self, message: str) -> None:
        if self.verbose and not self.json:
            self.console.print(f"[dim]{message}[/dim]")

    def note(self, message: str) -> None:
        """A dim, always-shown informational line (e.g. a satisfied requirement)."""
        target = self.err if self.json else self.console
        target.print(f"[dim]note: {message}[/dim]")

    def warn(self, message: str) -> None:
        target = self.err if self.json else self.console
        target.print(f"[yellow]warning:[/yellow] {message}")

    def error(self, message: str) -> None:
        self.err.print(f"[red]error:[/red] {message}")

    def success(self, message: str) -> None:
        if not self.json:
            self.console.print(f"[green]OK[/green] {message}")

    # -- helpers ------------------------------------------------------------ #
    def table(self, *headers: str, title: str | None = None) -> Table:
        table = Table(title=title, show_lines=False, header_style="bold")
        for h in headers:
            table.add_column(h)
        return table

    def print(self, renderable: object) -> None:
        if not self.json:
            self.console.print(renderable)


def state_style(label: str) -> str:
    """Colour a state label for human output."""
    good = {
        "PivPersonalized",
        "FidoPersonalized",
        "DesfireReachable",
        "CardPresent",
        "GenuinenessPersonalized",
    }
    warn = {
        "PivPrePersonalized",
        "PivPartiallyPersonalized",
        "PivSelectable",
        "FidoSelectable",
        "DesfireNeedsContactlessReader",
        "DesfireNoAnswerContactless",
        "FidoBlockedByOS",
        "GenuinenessPresent",
        "GenuinenessNeedsContactReader",
    }
    if label in good:
        return f"[green]{label}[/green]"
    if label in warn:
        return f"[yellow]{label}[/yellow]"
    if label in {"Unknown"} or label.endswith("NotPresent"):
        return f"[dim]{label}[/dim]"
    return label
