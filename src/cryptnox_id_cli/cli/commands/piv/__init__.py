# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The ``piv`` command — PIV management and personalization.

Read-only inspection (info/status/slots/certs/objects), PIN operations, the SCP03
admin channel, and the ``perso`` namespace (PIN/PUK values, on-card key generation,
CSR / certificates, data objects, validate/smoke-test). The pre-personalization
commands (``cli/commands/piv/preperso.py``) are registered into ``perso`` as well.
"""

from __future__ import annotations

import click

from . import admin, attestation, certs, objects, perso, pin, preperso, quickstart, views


@click.group("piv")
def command() -> None:
    """Manage the PIV applet (status, PIN, certs, objects, personalization)."""


command.add_command(views.info)
command.add_command(views.status)
command.add_command(views.discover)
command.add_command(views.slots)
command.add_command(views.inventory)
command.add_command(certs.certs)
command.add_command(attestation.export_attestation)
command.add_command(attestation.verify_attestation)
command.add_command(objects.objects)
command.add_command(pin.pin)
command.add_command(pin.puk)
command.add_command(admin.admin)
command.add_command(perso.preperso_redirect)
command.add_command(perso.perso)
command.add_command(views.validate)
command.add_command(quickstart.quickstart)

for _cmd in preperso.COMMANDS:
    perso.perso.add_command(_cmd)
