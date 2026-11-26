# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What quickstart prints: the dry-run plan and the result."""

from __future__ import annotations

from rich.console import Console

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.cli.context import AppContext

from .plan import PlannedStep
from .steps import _Run


def _show_dry_run(app: AppContext, steps: list[PlannedStep], state_before: str) -> None:
    """Print the plan; nothing reaches the card."""
    planned = [
        {"step": s.step, "status": "would-run" if s.run else "skip", "reason": s.reason}
        for s in steps
    ]

    def human_dry(c: Console) -> None:
        c.print(f"[bold]DRY RUN[/bold] - card state: {state_before}")
        table = app.out.table("Step", "Plan", "Reason")
        for p in planned:
            mark = "[cyan]would run[/cyan]" if p["status"] == "would-run" else "[dim]skip[/dim]"
            table.add_row(str(p["step"]), mark, str(p["reason"] or ""))
        c.print(table)
        c.print("\n  [dim]Nothing was sent to the card.[/dim]")

    app.out.result(
        {
            "quickstart": True,
            "dry_run": True,
            "state_before": state_before,
            "steps": planned,
        },
        human_dry,
    )


def _show_result(
    run: _Run,
    executed: list[dict[str, object]],
    state_before: str,
    state_after: str,
    failed: bool,
) -> None:
    app = run.app
    reader = app.resolved_reader or "<your contact reader>"
    slot_lc = run.slot.lower()
    next_cmds = [
        f'yubico-piv-tool -r "{reader}" -a status',
        f'yubico-piv-tool -r "{reader}" -a read-certificate -s {slot_lc} -o {slot_lc}.crt.pem',
        f'yubico-piv-tool -r "{reader}" -a verify-pin',
    ]
    payload = {
        "quickstart": True,
        "dry_run": False,
        "slot": run.slot,
        "algorithm": run.alg,
        "cert_mode": run.cert_mode,
        "preperso_profile": run.profile.name,
        "state_before": state_before,
        "steps": executed,
        "state_after": state_after,
        "outputs": run.outputs,
        "next": next_cmds if not failed else [],
    }

    def human(c: Console) -> None:
        table = app.out.table("Step", "Result", "Note")
        for e in executed:
            mark = {
                "ok": "[green]ok[/green]",
                "skipped": "[dim]skipped[/dim]",
                "failed": "[red]failed[/red]",
            }[str(e["status"])]
            note = e.get("reason") or e.get("sw") or ""
            detail = e.get("detail")
            if isinstance(detail, dict) and detail.get("note"):
                note = detail["note"]
            table.add_row(str(e["step"]), mark, str(note))
        c.print(table)
        c.print(f"\n  Card state: {state_before} -> {state_after}")
        if failed:
            c.print(
                "[red]quickstart stopped at the first failure[/red]; completed steps are "
                "kept - fix the cause and re-run (it skips what is already done)."
            )
            return
        c.print("\n[bold]Verify with standard PIV tooling:[/bold]")
        for cmd_line in next_cmds:
            c.print(f"  {cmd_line}")
        c.print(
            "[dim]Yubico-proprietary actions (version, attest, set-mgm-key, and writes via "
            "yubico-piv-tool) do not apply: this card administers over SCP03 via "
            f"{CLI_NAME}.[/dim]"
        )

    app.out.result(payload, human)
