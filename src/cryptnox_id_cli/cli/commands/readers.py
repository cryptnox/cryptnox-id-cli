"""``readers`` — list PC/SC readers (passive, no card session)."""

from __future__ import annotations

import click
from rich.console import Console

from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.pcsc import ReaderInfo, reader_states


@click.command("readers")
@click.pass_obj
def command(app: AppContext) -> None:
    """List all PC/SC readers, card presence, ATR and the recommended --reader."""
    infos: list[ReaderInfo] = reader_states()
    preferred_with_card = [r for r in infos if r.is_preferred and r.present]
    first_preferred = next((r for r in infos if r.is_preferred), None)
    # Recommend a single reader only when it is unambiguous (one Cryptnox/ACS reader has a card).
    recommended = preferred_with_card[0] if len(preferred_with_card) == 1 else None
    payload = {
        "readers": [
            {
                "index": r.index,
                "name": r.name,
                "card_present": r.present,
                "atr": r.atr_hex or None,
                "preferred": r.is_preferred,
            }
            for r in infos
        ],
        "recommended_reader": recommended.name if recommended else None,
        "preferred_with_card": [r.index for r in preferred_with_card],
    }

    def human(c: Console) -> None:
        if not infos:
            c.print("[yellow]No PC/SC readers found.[/yellow]")
            return
        table = app.out.table("#", "Reader", "Card", "ATR", title="PC/SC readers")
        for r in infos:
            name = r.name + (" [green](preferred)[/green]" if r.is_preferred else "")
            card = "[green]present[/green]" if r.present else "[dim]empty[/dim]"
            table.add_row(str(r.index), name, card, r.atr_hex or "-")
        c.print(table)
        if recommended is not None:
            c.print(
                f"\nRecommended: [bold]--reader {recommended.index}[/bold]  ({recommended.name})"
            )
        elif len(preferred_with_card) > 1:
            picks = "  ".join(f"--reader {r.index} ({r.name})" for r in preferred_with_card)
            c.print(
                f"\n[yellow]Multiple Cryptnox/ACS readers have a card[/yellow] - choose one "
                f"(PICC = contactless, ICC = contact):\n  {picks}"
            )
        elif first_preferred is not None:
            c.print(
                f"\n[yellow]Cryptnox/ACS reader {first_preferred.index} has no card[/yellow]; "
                "insert one or pass --reader."
            )
        else:
            c.print("\n[yellow]No Cryptnox/ACS reader detected; pass --reader explicitly.[/yellow]")

    app.out.result(payload, human)
