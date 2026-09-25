"""Resolve secret values for card operations.

PIN/PUK/password resolution order: an explicit CLI option value when the caller
passed one (options like ``--pin``, ``--puk``, and ``--password`` exist, but a
value given on the command line lands in shell history and is visible in process
listings while the command runs), then the environment variable, then a masked
prompt. Prefer the environment variable or the prompt for exactly that reason.

SCP03 admin channel keys never come from the command line: ``--default-keys``
(the publicly known GlobalPlatform test keys) or the three env vars only. The PIV
management key (9B) follows the same rule: ``--default-keys`` or ``$PIV_MGMT_KEY``,
never the command line. Every resolved secret is registered with the redactor
before use.
"""

from __future__ import annotations

import getpass
import os
import sys

from cryptnox_id_cli.applets.piv.mgmt_auth import MgmtKeyMaterial, mechanism_for_key_length
from cryptnox_id_cli.secrets.redaction import Redactor
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.scp03 import Scp03Keys
from cryptnox_id_cli.util.hexutil import from_hex

DEFAULT_GP_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")

#: Environment variable carrying the PIV management key (9B) value, as hex.
MGMT_KEY_ENV = "PIV_MGMT_KEY"
#: Accepted when the primary variable is unset (the name used by factory tooling).
MGMT_KEY_ENV_ALIAS = "CARD_PIV_MGMT_KEY"


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


def resolve_mgmt_key(
    redactor: Redactor,
    *,
    default_keys: bool = False,
    env_var: str = MGMT_KEY_ENV,
    env_alias: str = MGMT_KEY_ENV_ALIAS,
    missing_message: str | None = None,
) -> MgmtKeyMaterial:
    """Resolve the PIV management key (9B) value, never from the command line.

    Order: ``--default-keys`` (the publicly known GlobalPlatform test value: as-is for
    an AES-128 key object, doubled for AES-256; there is no published AES-192 value)
    -> ``$PIV_MGMT_KEY`` (hex) -> ``$CARD_PIV_MGMT_KEY`` (hex) -> ``SecretInputError``.
    A hex value must be 16, 24 or 32 bytes; its length selects the mechanism. Every
    resolved value is registered for redaction before it is returned.

    ``missing_message`` replaces the "nothing supplied" text, so the caller can say why
    the value is needed at the moment it turns out to be.
    """
    if default_keys:
        doubled = DEFAULT_GP_KEY + DEFAULT_GP_KEY
        redactor.register(DEFAULT_GP_KEY)
        redactor.register(doubled)
        return MgmtKeyMaterial("--default-keys", {0x08: DEFAULT_GP_KEY, 0x0C: doubled})
    raw, source = os.environ.get(env_var), f"${env_var}"
    if raw is None:
        raw, source = os.environ.get(env_alias), f"${env_alias}"
    if raw is not None:
        value = from_hex(raw)
        mechanism = mechanism_for_key_length(len(value))
        if mechanism is None:
            raise SecretInputError(
                f"{source} is {len(value)} bytes; the PIV management key must be 16, 24 "
                "or 32 bytes (AES-128/192/256)."
            )
        redactor.register(value)
        return MgmtKeyMaterial(source, {mechanism: value})
    raise SecretInputError(
        missing_message
        or (
            f"PIV management key value required: pass --default-keys (development cards) "
            f"or set ${env_var} (hex)."
        )
    )
