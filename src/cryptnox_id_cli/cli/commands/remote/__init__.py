# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``remote`` — operations carried out by the Cryptnox remote PIV service.

The card stays in the local reader. The service holds the keys that make a card
genuine and drives the operation over a relayed command channel; this tool
relays what the service asks for, under a fail-closed policy, and shows the
outcome. What the service asserts and what this tool verified locally are kept
apart in the output.

The package splits along what varies on its own: what the tool reads from the
card itself (``card``), how a result is shown (``render``), the plumbing every
operation shares (``run``), and one module per command.
"""

from __future__ import annotations

import click

from . import attest, ping, read_only, reset
from .attest import ATTEST_ALGORITHMS
from .reset import DEV_RESET_PHRASE, PIV_BUILDS, RESET_PHRASE
from .run import FULL_TRANSCRIPT_KEY

__all__ = ["ATTEST_ALGORITHMS", "DEV_RESET_PHRASE", "PIV_BUILDS", "RESET_PHRASE", "command"]


@click.group("remote")
@click.option(
    "--full-transcript",
    is_flag=True,
    help=(
        "Write relayed commands to --apdu-log and --verbose without the extra masking "
        "the relay applies by default. The standard secret masking still applies."
    ),
)
@click.pass_context
def command(ctx: click.Context, full_transcript: bool) -> None:
    """Run operations through the Cryptnox remote PIV service.

    Every command but `ping` opens the local reader, connects to the service
    over TLS, answers a small proof-of-work, and relays the commands the service
    sends to the card. Only the PIV function and its security domains are reachable; the
    other card functions are fenced off by the relay policy.
    """
    ctx.meta[FULL_TRANSCRIPT_KEY] = full_transcript


command.add_command(ping.ping)
command.add_command(read_only.authenticate)
command.add_command(read_only.inspect)
command.add_command(reset.reset)
command.add_command(reset.dev_reset)
command.add_command(attest.attest)
