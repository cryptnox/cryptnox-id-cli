"""Resolve secret values for card operations.

PIN/PUK/password resolution order: an explicit CLI option value when the caller
passed one (options like ``--pin``, ``--puk``, and ``--password`` exist, but a
value given on the command line lands in shell history and is visible in process
listings while the command runs), then the environment variable, then a masked
prompt. Prefer the environment variable or the prompt for exactly that reason.

SCP03 admin channel keys never come from the command line: ``--default-keys``
(the publicly known GlobalPlatform test keys) or the three env vars only. Every
resolved secret is registered with the redactor before use.
"""

from __future__ import annotations

import getpass
import os
import sys

from cryptnox_id_cli.secrets.redaction import Redactor
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.scp03 import Scp03Keys
from cryptnox_id_cli.util.hexutil import from_hex

DEFAULT_GP_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")


class SecretInputError(CryptnoxError):
    """Raised when a required secret cannot be obtained safely."""

    code = "secret_input"
    exit_code = 3


def resolve_secret(
    *,
    redactor: Redactor,
    env_var: str | None = None,
    prompt_label: str = "Secret",
    provided: str | None = None,
) -> bytes:
    """Resolve a secret as bytes (ASCII), registering it for redaction.

    Order: explicit ``provided`` (discouraged, dev only) → ``env_var`` → masked prompt.
    """
    value: str | None = provided
    source = "argument"
    if value is None and env_var:
        value = os.environ.get(env_var)
        source = f"${env_var}"
    if value is None:
        if not sys.stdin.isatty():
            raise SecretInputError(
                f"{prompt_label} required but no TTY for prompting; set ${env_var} instead."
                if env_var
                else f"{prompt_label} required."
            )
        value = getpass.getpass(f"{prompt_label}: ")
        source = "prompt"
    _ = source
    secret = value.encode("utf-8")
    redactor.register(secret)
    return secret


def resolve_scp03_keys(
    redactor: Redactor,
    *,
    default_keys: bool = False,
    enc_env: str = "PIV_SCP03_ENC",
    mac_env: str = "PIV_SCP03_MAC",
    dek_env: str = "PIV_SCP03_DEK",
) -> Scp03Keys:
    """Resolve the SCP03 static keys (never from the command line).

    Order: ``--default-keys`` (the publicly known GlobalPlatform test key) -> the
    three env vars (hex) -> error. All resolved key bytes are registered for redaction.
    """
    if default_keys:
        redactor.register(DEFAULT_GP_KEY)
        return Scp03Keys.same(DEFAULT_GP_KEY)
    enc, mac, dek = (os.environ.get(v) for v in (enc_env, mac_env, dek_env))
    if enc and mac and dek:
        keys = Scp03Keys(from_hex(enc), from_hex(mac), from_hex(dek))
        for k in (keys.enc, keys.mac, keys.dek):
            redactor.register(k)
        return keys
    raise SecretInputError(
        "SCP03 keys required to open the admin channel: pass --default-keys if this "
        "card is still on the publicly known GlobalPlatform test keys (development/"
        f"evaluation cards), or set ${enc_env}/${mac_env}/${dek_env} (hex) with the "
        "card's real keys."
    )
