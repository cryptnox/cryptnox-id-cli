# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The quickstart options that are settled before the card is opened."""

from __future__ import annotations

import click

from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.cli.context import AppContext

# Built-in profiles whose 9A is made for Windows logon: a signing key, with an RSA-2048
# object next to the ECC one. ms-logon-nfc is ms-logon for a card presented over NFC.
WINDOWS_LOGON_PROFILES = ("ms-logon", "ms-logon-nfc")


def _resolve_algorithm(
    app: AppContext, profile_name: str, ref: int, algorithm: str
) -> tuple[str, int, bool]:
    """The algorithm name, its mechanism, and whether this is the Windows logon shape."""
    # The Windows inbox minidriver enumerates no EC keys, so an ECC 9A cannot log on there.
    windows_rsa_shape = profile_name in WINDOWS_LOGON_PROFILES and ref == pivc.KEYREF_PIV_AUTH
    algorithm_defaulted = (
        click.get_current_context().get_parameter_source("algorithm")
        == click.core.ParameterSource.DEFAULT
    )
    if windows_rsa_shape and algorithm_defaulted:
        algorithm = "RSA2048"
        app.out.note(
            f"profile {profile_name} on slot 9A: defaulting to RSA2048, which Windows needs "
            "(the inbox minidriver does not enumerate EC keys); pass --algorithm to override."
        )
    alg = algorithm.upper()
    mech = perso_mod.ALGORITHMS.get(alg)
    if mech is None or mech not in pivc.SUPPORTED_ALGORITHMS:
        raise click.BadParameter(f"algorithm {algorithm!r} not supported by this applet")
    return alg, mech, windows_rsa_shape


def _check_certificate_options(
    ref: int, cert_mode: str, csr_out: str | None, cert_out: str | None
) -> None:
    """Refuse certificate options that cannot work on this slot or together."""
    if cert_mode != "none" and ref not in (
        pivc.KEYREF_PIV_AUTH,
        pivc.KEYREF_DIGITAL_SIGNATURE,
    ):
        raise click.BadParameter(
            "certificate modes sign on-card and need a SIGN-capable slot: 9C always; "
            "9A only on cards pre-personalized with a SIGN-capable 9A (the ms-logon "
            "profile) - a default-profile 9A fails the certificate step with 6985.",
            param_hint="--slot",
        )
    if cert_mode == "csr" and not csr_out:
        raise click.BadParameter("--cert-mode csr requires --csr-out", param_hint="--csr-out")
    if cert_out and cert_mode != "self-signed":
        raise click.BadParameter(
            "--cert-out applies to --cert-mode self-signed", param_hint="--cert-out"
        )
