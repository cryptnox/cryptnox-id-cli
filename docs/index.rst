|product|
=========

Command-line management for the Cryptnox multi-applet smart card: PIV
(SP 800-73 identity credentials), FIDO2/CTAP 2.1 (passkeys), and MIFARE
DESFire contactless — three independent functions on one physical card,
driven by one tool: |cli|.

.. only:: html

   📄 `Download this documentation as PDF <cryptnox-id-cli.pdf>`__

.. toctree::
   :maxdepth: 2
   :caption: General

   overview
   installation
   getting-started
   interactive-shell
   cli-basics
   json-output
   exit-codes
   troubleshooting
   factory/index
   license

.. toctree::
   :maxdepth: 2
   :caption: PIV

   Quick start <piv/quick-start-a-working-piv-card>
   piv/windows-logon-and-remote-desktop
   piv/ssh-public-key-authentication
   piv/ssh-user-certificates
   piv/tls-client-authentication
   piv/macos-smart-card-login
   piv/piv-personalization
   Commands <piv/piv-commands>

.. toctree::
   :maxdepth: 2
   :caption: FIDO2

   Quick start <fido2/quick-start-a-passkey-on-the-card>
   Guide <fido2/fido2-guide>
   Commands <fido2/fido2-commands>

.. toctree::
   :maxdepth: 2
   :caption: MIFARE DESFire

   Quick start <mifare/quick-start-a-tamper-evident-nfc-tag-sdm-sun>
   Guide <mifare/mifare-desfire-guide>
   Commands <mifare/mifare-desfire-commands>

.. toctree::
   :maxdepth: 2
   :caption: Genuineness

   Quick start <genuine/quick-start-prove-a-card-is-genuine>
   Guide <genuine/genuineness-guide>
   Commands <genuine/genuineness-commands>

.. API Reference — RESERVED: autodoc of the Python package, if/when it is
   publicly pip-installable (see the internal documentation plan, decision D4).
