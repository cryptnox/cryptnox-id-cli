Overview
========

The Cryptnox ID card carries three independent functions on one chip:

* **PIV** — SP 800-73 identity credentials: PIN-protected keys and X.509
  certificates for signing, authentication and encryption, usable by standard
  PIV tooling (yubico-piv-tool, OpenSC, OS smart-card stacks).
* **FIDO2 / CTAP 2.1** — passkeys over NFC for WebAuthn sign-in.
* **MIFARE DESFire** — contactless applications: access control, closed-loop
  counters, and EV3 Secure Dynamic Messaging (self-authenticating NFC tags).

|product| (the |cli| command) manages all three from one terminal.

A fourth applet, **genuineness**, is Cryptnox's factory attestation: it proves
the card is authentic. Unlike the three functions above it is *inspected*, never
provisioned — see :doc:`/genuine/genuineness-guide`.

Reachability at a glance
--------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Function
     - Interface
     - Notes
   * - PIV
     - contact (admin), contact/contactless (use)
     - All personalization/administration is contact-only.
   * - FIDO2
     - contactless (NFC)
     - Windows: requires an Administrator terminal.
   * - DESFire
     - contactless (NFC)
     - Requires a DESFire-capable reader (ACS ACR1252 verified).
   * - Genuineness
     - contact
     - Cryptnox attestation applet; read-only (:doc:`/genuine/genuineness-guide`).

The **same physical card** exposes **different applets** depending on the
interface it is reached over. If PIV looks present but MIFARE does not, you are
on a contact reader — and vice versa.

Readers
---------

The |readers-link| are the recommended choice and cover every function of the
card. Any PC/SC reader also works for PIV and FIDO2; MIFARE DESFire additionally
needs a reader that passes *native* DESFire APDUs — not all contactless readers
do.

.. list-table::
   :header-rows: 1
   :widths: 34 25 41

   * - Reader
     - Use
     - Status
   * - |reader-contact| (contact)
     - PIV, FIDO2, genuineness
     - Cryptnox — recommended
   * - |reader-mini| (contact)
     - PIV, FIDO2, genuineness
     - Cryptnox — recommended
   * - |reader-contactless| (NFC)
     - DESFire, PIV/FIDO2 over NFC
     - Cryptnox — recommended
   * - ACS ACR39U (contact)
     - PIV, FIDO2, genuineness
     - verified
   * - ACS ACR1252 (contactless)
     - DESFire, PIV/FIDO2 over NFC
     - verified (native DESFire OK)
   * - Feitian R502 (contactless)
     - DESFire, PIV/FIDO2 over NFC
     - observed working
   * - HID OMNIKEY 5422CL
     - PIV / GlobalPlatform only
     - **DESFire not supported** (frames unanswered)

Reader names differ across units, operating systems and drivers, so the CLI
selects by name substring as well as index — see :doc:`/getting-started`. A
Cryptnox reader may report a Cryptnox-branded name ("CryptnoxCR" contact,
"Cryptnox NFC" contactless) or the ACS model name of the underlying unit; run
``readers`` to see yours — the no-``--reader`` default auto-selects both
families.

Platforms
-----------

The CLI is pure Python over PC/SC and runs on Windows, Linux and macOS. All
three card functions are verified on real hardware on each. The one
platform-specific behaviour is **FIDO2 on Windows**, which requires an
Administrator terminal (Windows reserves the CTAP interface for its WebAuthn
API); Linux and macOS have no such restriction. See :doc:`/installation` for
per-OS setup.
