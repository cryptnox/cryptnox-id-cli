# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``piv perso``: the group and the redirect for the retired ``piv preperso``."""

from __future__ import annotations

import click

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.transport.errors import CryptnoxError

from . import certificates, data_objects, key_import, keys, signing, verifiers


# ------------------------------------------------------ legacy redirect --- #
@click.command(
    "preperso",
    hidden=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def preperso_redirect(args: tuple[str, ...]) -> None:
    """(moved) Pre-personalization is under `piv perso`."""
    raise preperso_moved(args)


_PREPERSO_COMMANDS = (
    "status",
    "inspect-defaults",
    "init-config",
    "export-config",
    "load-config",
    "set-mgmt-key",
    "finalize",
)


def preperso_moved(args: tuple[str, ...]) -> CryptnoxError:
    """The error for the retired ``piv preperso`` and ``factory piv preperso`` spellings."""
    name = next((a for a in args if a in _PREPERSO_COMMANDS), None)
    hint = f"run `{CLI_NAME} piv perso {name}`" if name else f"see `{CLI_NAME} piv perso --help`"
    return CryptnoxError(f"Pre-personalization commands are now under `piv perso`: {hint}.")


# ------------------------------------------------------------------ perso --- #
@click.group("perso")
def perso() -> None:
    """PIV pre-personalization and personalization: structure, PIN/PUK, keys, objects."""


perso.add_command(keys.perso_generate_key)
perso.add_command(keys.perso_create_key_object)
perso.add_command(key_import.perso_import_key)
perso.add_command(key_import.perso_import_p12)
perso.add_command(verifiers.perso_set_pin)
perso.add_command(verifiers.perso_set_puk)
perso.add_command(certificates.perso_generate_csr)
perso.add_command(certificates.perso_self_sign_cert)
perso.add_command(certificates.perso_import_cert)
perso.add_command(data_objects.perso_generate_chuid)
perso.add_command(data_objects.perso_generate_ccc)
perso.add_command(data_objects.perso_generate_discovery)
perso.add_command(data_objects.perso_write_object)
perso.add_command(data_objects.perso_write_standard_objects)
perso.add_command(signing.perso_smoke_test)
