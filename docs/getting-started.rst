Getting started
===============

First contact with the card:

.. code-block:: console

   $ cryptnox-id readers       # which reader to use (note the --reader hint)
   $ cryptnox-id info          # all three functions on one screen
   $ cryptnox-id doctor        # if anything looks off

``info`` and ``doctor`` are read-only and safe to run any time. ``doctor`` exits
with code **2** if a blocking check fails (useful in scripts); FIDO/DESFire
warnings on a contact or non-elevated setup are **not** blocking.

Then pick your path: :doc:`/piv/quick-start-a-working-piv-card`, :doc:`/mifare/quick-start-a-tamper-evident-nfc-tag-sdm-sun` or
:doc:`/fido2/quick-start-a-passkey-on-the-card`.

Choosing a reader
-------------------

Every command talks to exactly one reader.

* **Default (no ``--reader``)** — the tool picks the single **Cryptnox or ACS**
  reader that has a card. This is deliberate: it avoids touching another
  project's card in some other reader.
* If there is **no Cryptnox/ACS reader**, or **several** readers with cards,
  the tool **refuses to guess** and asks you to pass ``--reader``.
* **``--reader <index>``** — the number from ``cryptnox-id readers`` (e.g.
  ``--reader 0``).
* **``--reader <name>``** — a case-insensitive substring of the reader name
  (e.g. ``--reader CryptnoxCR``, ``--reader ACR39``, ``--reader PICC``); an
  ambiguous substring is an error.

Two things to know:

* Virtual readers such as **"Windows Hello for Business"** show up in
  ``readers`` — ignore them; they are not Cryptnox cards.
* The **same physical card** over a contact vs a contactless reader exposes
  **different applets**. If PIV looks present but MIFARE does not, you are on a
  contact reader — and vice versa. Reader names also differ per unit and
  OS/driver (``PICC`` = contactless, ``ICC`` / ``ACR39U`` = contact; some
  Cryptnox units report ``CryptnoxCR`` / ``Cryptnox NFC`` instead), so prefer
  selecting by name substring.

A bench with both a contact and a contactless reader loaded:

.. code-block:: console

   $ cryptnox-id readers
   #  0 | ACS ACR39U ICC Reader 0 (ACS) | present | 3B...     <- contact
   #  1 | Feitian R502 0                | present | 3B...     <- contactless
   $ cryptnox-id --reader 0 piv info        # PIV over contact
   $ cryptnox-id --reader 1 mifare info     # DESFire over contactless

Global options
----------------

These sit before the command and apply to it:

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Option
     - Meaning
   * - ``--reader <name|index>``
     - Select the PC/SC reader (default: the ACS reader with a card).
   * - ``--json``
     - Machine-readable JSON to stdout; diagnostics go to stderr.
   * - ``--verbose``
     - Human debug output; a redacted APDU trace to stderr.
   * - ``--apdu-log <file>``
     - Append a redacted APDU transcript to a file.
   * - ``--dry-run``
     - Write nothing to the card. Commands that can plan (``piv quickstart``,
       ``apdu``, ``factory``, the key imports) show the intended actions; every
       other command refuses to run under the flag rather than executing for
       real (fail-closed).
   * - ``--yes``
     - Skip destructive confirmation prompts.
   * - ``--timeout <seconds>``
     - Reader/card timeout.
   * - ``--no-color``
     - Disable coloured output.

One card operation at a time
------------------------------

Each ``cryptnox-id`` invocation opens the reader, does one thing, and releases
it. Admin and personalization commands each open their **own** SCP03 session
(this card accepts one application APDU per applet-directed session), so there is
nothing to "keep open" between commands. For a running prompt that issues many
commands in a row without re-typing the prefix, use :ref:`the interactive shell
<cli-shell>` (``cryptnox-id shell``).

Development keys
------------------

.. warning::

   Development and evaluation cards use well-known **default** keys, and the
   examples in this documentation use them too:

   * **SCP03 / GlobalPlatform ISD** — the published GlobalPlatform test key
     ``40 41 42 … 4F`` (``--default-keys``);
   * **DESFire** application keys after ``app create`` — all-zero AES
     (``--zero-key``);
   * **PIV PIN / PUK** in the examples — ``123456`` / ``12345678``.

   These are **not secrets** — they are public, published values. A production
   deployment must rotate all of them, which is exactly what the
   environment-variable key input is for: ``PIV_SCP03_ENC`` /
   ``PIV_SCP03_MAC`` / ``PIV_SCP03_DEK`` for the admin channel,
   ``CRYPTNOX_PIV_PIN`` / ``CRYPTNOX_PIV_NEW_PIN`` / ``CRYPTNOX_PIV_NEW_PUK``
   for PINs and PUKs, and the DESFire ``--key-env NAME`` form.

Next
------

* :doc:`/piv/quick-start-a-working-piv-card` — provision a PIV credential end to end
* :doc:`/fido2/quick-start-a-passkey-on-the-card` — FIDO2 / CTAP2 walkthrough
* :doc:`/mifare/quick-start-a-tamper-evident-nfc-tag-sdm-sun` — DESFire EV3 Secure Dynamic Messaging
* :doc:`/troubleshooting` — when something looks off
