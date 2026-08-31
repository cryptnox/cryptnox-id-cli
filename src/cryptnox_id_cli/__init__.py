"""cryptnox-id — CLI for the Cryptnox multi-applet smartcard.

Three independent functions live on one physical card and are managed by
separate, isolated modules (see ``applets/``):

* PIV     — OpenFIPS201 2.0.0 FIPS JavaCard applet (contact).
* FIDO2   — CTAP 2.1 JavaCard applet (needs Administrator elevation on Windows).
* DESFire — MIFARE DESFire EV2/EV3 contactless function (needs a contactless reader).

Covered: PC/SC transport and diagnostics (``readers``/``info``/``doctor``), full
PIV personalization and factory pre-personalization over SCP02/SCP03, FIDO2
credential and policy management, DESFire application/file/key operations
including EV3 Secure Dynamic Messaging, and read-only genuineness/attestation
verification.
"""

__version__ = "1.0.2"

#: Primary console command name. Single source of truth for every user-facing
#: render of the CLI's name (usage/version, prompt, banner, messages). The
#: ``cnx-id`` and ``cryptnox-id-card`` aliases are declared in pyproject.
CLI_NAME = "cryptnox-id"
