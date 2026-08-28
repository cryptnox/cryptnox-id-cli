Quick start: a working PIV card
===============================

This guide takes a blank (pre-personalized) Cryptnox card to a PIV credential
that standard tooling — ``yubico-piv-tool``, OpenSC/PKCS#11 — can read, verify
and sign with. About ten minutes, one command if you let it.

Prerequisites
-------------

* A **contact** smart-card reader. PIV administration is gated to the contact
  interface on this card; contactless works for reading once personalized.
* |cli| installed, and ``yubico-piv-tool`` if you want to run the verification
  step (any recent version).
* The card's SCP03 administration keys. **Development/evaluation cards** use the
  GlobalPlatform test keys — pass ``--default-keys``. **Provisioned cards** take
  their keys from the ``PIV_SCP03_ENC`` / ``PIV_SCP03_MAC`` / ``PIV_SCP03_DEK``
  environment variables (hex). Keys never go on the command line, and the
  default keys are for development cards only — see the warning in
  :doc:`/getting-started`.

Check what you have:

.. code-block:: console

   $ cryptnox-id readers
   $ cryptnox-id piv status

The one-command path
--------------------

.. code-block:: console

   $ cryptnox-id piv quickstart --default-keys --dry-run   # show the plan first
   $ cryptnox-id piv quickstart --default-keys

``piv quickstart`` detects the card state, then runs whatever is still needed
of: PIN → PUK → key in slot 9C (ECC P-256, generated **on-card** — the private
key never exists outside the card) → self-signed certificate → CHUID/CCC →
smoke-test. Steps already done are skipped, so re-runs converge. New PIN/PUK
values come from masked prompts or ``CRYPTNOX_PIV_NEW_PIN`` /
``CRYPTNOX_PIV_NEW_PUK``.

On a factory-blank card that has never had its PIV structure laid down, add
``--include-preperso`` (a manufacturing-style step, intended for development
cards), and for a CA-issued certificate instead of a self-signed one use
``--cert-mode csr --csr-out 9c.csr.pem``.

The steps, by hand
------------------

The same sequence as individual commands — useful to understand what quickstart
does, or to vary it.

**Step 0 — lay down the PIV structure (once per card).** If ``piv status``
reports a pre-personalized applet with no containers/verifiers:

.. code-block:: console

   $ cryptnox-id factory piv preperso load-config --profile cryptnox-default --dry-run
   $ cryptnox-id factory piv preperso load-config --profile cryptnox-default --default-keys

**Step 1 — set the PIN and PUK** (values prompted, never echoed):

.. code-block:: console

   $ cryptnox-id piv perso set-puk --default-keys
   $ cryptnox-id piv perso set-pin --default-keys
   $ cryptnox-id piv pin status

**Step 2 — put a key in slot 9C.** Slot 9C (Digital Signature) is the SIGN-role
slot on this card — certificate signing needs it (9A is AUTHENTICATE-role and
returns ``6985`` for sign operations).

.. code-block:: console

   $ cryptnox-id piv perso generate-key --slot 9C --algorithm ECCP256 \
        --out 9c.pub.pem --default-keys

.. note::

   ``quickstart`` defaults to **ECC** (P-256) everywhere. ``--algorithm
   RSA2048`` is accepted for ``--profile ms-logon`` on slot 9A — the one
   built-in profile/slot combination with an RSA key object — and pass it
   there for Windows, whose inbox PIV minidriver does not enumerate EC keys
   (see :doc:`/piv/windows-logon-and-remote-desktop`); left on the ECC default, that combination prints a
   warning saying exactly that.

   A slot can be generated on-card with any mechanism it has a **key object**
   for, and the pre-personalization profile decides which those are. Every key
   object in ``cryptnox-default`` is ECC, so RSA must be imported on such a
   card. A profile that provides an RSA object (``ms-logon`` does, on 9A) can
   generate RSA on-card instead, with the private key never leaving the chip:

   .. code-block:: console

      $ cryptnox-id piv perso generate-key --slot 9A --algorithm RSA2048 \
           --out 9a.pub.pem

   Asking for a mechanism the slot has no object for returns ``6A80``.

   To place an **externally generated** RSA key instead:

   .. code-block:: console

      $ openssl genrsa -out rsa2048.key.pem 2048
      $ cryptnox-id piv perso import-key --slot 9C --key rsa2048.key.pem \
           --create-key-object --default-keys

   ``import-key`` also accepts ECC keys (escrow/migration scenarios). See
   :doc:`/piv/piv-personalization`.

**Step 3 — a certificate for 9C.** Fastest (development/testing):

.. code-block:: console

   $ cryptnox-id piv perso self-sign-cert --slot 9C --subject "CN=Test User" \
        --public-key 9c.pub.pem --out 9c.crt.pem
   $ cryptnox-id piv perso import-cert --slot 9C --cert 9c.crt.pem

Or CA-issued: ``generate-csr`` → have your CA sign it → ``import-cert``.
Large certificates are written with ISO command chaining automatically.

**Step 4 — standard data objects.** Most PIV clients (including
``yubico-piv-tool -a status`` and the Windows minidriver) treat a card without a
CHUID as unpersonalized:

.. code-block:: console

   $ cryptnox-id piv perso write-standard-objects --default-keys

**Step 5 — validate from our side:**

.. code-block:: console

   $ cryptnox-id piv perso smoke-test     # verify PIN + one on-card signature
   $ cryptnox-id piv validate             # consistency check (NOT a FIPS/NIST validation)

Verify with yubico-piv-tool
---------------------------

.. note::

   ``yubico-piv-tool`` auto-connects only to readers whose name contains
   "Yubikey" — always pass your reader with ``-r`` (any unique substring of the
   reader name works). ``ACR39`` below matches the verified ACS contact reader;
   substitute your own reader's name as shown by ``cryptnox-id readers`` — a
   Cryptnox reader shows either its Cryptnox name (``CryptnoxCR`` contact,
   ``Cryptnox NFC`` contactless) or the ACS model name of the unit.

.. code-block:: console

   $ yubico-piv-tool -r "ACR39" -a status
   $ yubico-piv-tool -r "ACR39" -a read-certificate -s 9c -o 9c-readback.pem
   $ yubico-piv-tool -r "ACR39" -a verify-pin

For PKCS#11 (SSH, TLS client auth, code signing through OpenSC):

.. code-block:: console

   $ pkcs11-tool --module opensc-pkcs11 --list-objects
   $ pkcs15-tool --list-certificates

Interoperability matrix
-----------------------

The card is a standards-compliant SP 800-73 PIV target for *reading, PIN
operations and signing*. *Provisioning* is done with |cli| over an SCP03 secure
channel, by design — Yubico-proprietary management does not apply.

.. note::

   ``yubico-piv-tool`` checks the Yubico firmware-version query **at connect
   time** and refuses any card that does not answer it ("Failed to connect to
   yubikey: Not supported."). The rows below were validated against a card
   whose applet includes that compatibility responder; a card running the
   plain PIV applet without it is refused outright. It is the only tool with
   that requirement: OpenSC and the Windows smart-card stack use standard PIV
   discovery and work against the PIV function regardless.

.. list-table::
   :header-rows: 1
   :widths: 34 22 44

   * - yubico-piv-tool action
     - On this card
     - Why
   * - ``-a status``
     - works
     - Standard SELECT + GET DATA. Containers that hold no parseable
       certificate print cosmetic ``Parse error`` lines — populated slots
       render normally.
   * - ``-a read-certificate -s 9c``
     - works
     - Standard GET DATA on the certificate object
   * - ``-a version``
     - works (with the compatibility responder — see note)
     - Answers the Yubico version query with a YubiKey-compatible firmware
       version; the tool requires this to connect at all
   * - ``-a verify-pin``
     - works
     - Standard VERIFY
   * - ``-a change-pin`` / ``-a change-puk`` / ``-a unblock-pin``
     - works
     - Standard CHANGE REFERENCE DATA / RESET RETRY COUNTER
   * - OpenSC: ``pkcs15-tool --list-certificates``, ``pkcs15-crypt --sign``,
       PKCS#11 signing
     - works
     - Pure SP 800-73: OpenSC identifies the card as a "Personal Identity
       Verification Card" and signs with the slot key after PIN verification —
       no vendor extensions involved
   * - ``-a attest``
     - not applicable
     - Yubico vendor attestation; no attestation key/certificate on this
       applet (``Failed to attest data.``)
   * - ``-a set-mgm-key``
     - not applicable
     - Yubico management-key model; this card administers over a GlobalPlatform
       SCP03 channel instead
   * - ``-a authenticate`` + writes (``-a generate``, ``-a import-key``,
       ``-a import-certificate``, ``-a set-chuid``)
     - use |cli| instead
     - Writes require Yubico-style management-key authentication; on this card
       every write goes over SCP03 via ``cryptnox-id piv perso ...``

If something fails
------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Symptom
     - Cause / fix
   * - ``6985`` when signing or self-signing
     - Wrong slot role — sign operations need the SIGN slot (9C)
   * - ``set-pin`` fails ``6A88``/``6A82``
     - The PIV structure is missing — run step 0
   * - yubico-piv-tool sees no card
     - Pass the reader explicitly: ``-r <substring>``
   * - Admin command fails over NFC
     - PIV administration is contact-only — move the card to a contact reader
   * - SCP03 mutual authentication fails
     - Wrong admin keys — ``--default-keys`` is for development cards only

More: :doc:`/troubleshooting`.

Next steps
----------

* :doc:`/piv/piv-personalization` — the full lifecycle, key import, finalize
* :doc:`/factory/pre-personalization-profiles` — customizing the pre-personalization profile
* :doc:`/piv/piv-commands` — every ``piv`` command
