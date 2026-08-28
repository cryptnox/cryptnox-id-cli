Quick start: a tamper-evident NFC tag (SDM/SUN)
===============================================

MIFARE DESFire EV3 **Secure Dynamic Messaging** (SDM), also marketed as
**Secure Unique NFC** (SUN), turns a free-read file into a self-authenticating
tag: on *every* read, the card mirrors a freshly encrypted copy of its UID and
an incrementing read counter into the file content, plus a MAC over them. A
backend that knows the key can prove each read came from the genuine card — and
detect replayed or cloned URLs — without any session or pairing.

This guide configures SDM on a Cryptnox card and verifies the whole loop with
|cli|. It follows the public NXP application note `AN12196
<https://www.nxp.com/docs/en/application-note/AN12196.pdf>`_.

Prerequisites
-------------

* A **DESFire-capable contactless reader** (the ACS ACR1252 is verified; some
  contactless readers do not pass native DESFire commands through).
* A Cryptnox card with the DESFire EV3 function — check with:

.. code-block:: console

   $ cryptnox-id mifare version

Step 1 — create an application
------------------------------

SDM uses two application keys besides the master key: one to encrypt the
mirrored UID + counter (key 2) and one for the MAC (key 1). Create the
application with at least 3 AES keys — on a fresh application all keys are
all-zero:

.. code-block:: console

   $ cryptnox-id mifare app create --aid CC0102 --keys 3

Step 2 — set up the SDM file
----------------------------

One command creates the file (SDM must be enabled at file creation on EV3),
writes an NDEF-style URL template with placeholders for the two mirrors, and
configures the SDM options:

.. code-block:: console

   $ cryptnox-id mifare sdm setup --aid CC0102 --file-id 02 --zero-key \
        --url "https://example.com/t"

(``--zero-key`` authenticates with the publicly known all-zero factory-default
key - right for a fresh application; use ``--key-env`` once keys are rotated.)

The stored content becomes::

   https://example.com/t?picc=00000000000000000000000000000000&c=0000000000000000

``picc=`` receives the encrypted UID + read counter (32 hex characters) and
``c=`` the SDMMAC (16 hex characters), re-computed by the card on every read.

Step 3 — read and verify
------------------------

.. code-block:: console

   $ cryptnox-id mifare sdm read --aid CC0102 --file-id 02
   NDEF: https://example.com/t?picc=1F44...&c=9A02...
     decrypted UID: 046F9C6A7B7180
     read counter:  3
     SDMMAC: verified (with the all-zero factory default keys)

``sdm read`` does exactly what a verification backend would: free-read the
file, decrypt the ``picc=`` mirror into the card UID and read counter, derive
the per-read session key, and check the ``c=`` MAC. Run it twice — the
ciphertext changes completely, the counter increments, and the MAC stays valid.
That is the SUN property: every read is a fresh, verifiable proof.

Scope and production notes
--------------------------

* **What this demonstrates** is the complete SDM/SUN mechanism, with |cli|
  acting as both tag programmer and verification backend. Exposing the file
  as a *phone-tappable* NFC tag additionally requires the standard NDEF
  Type 4 application layout — that is an
  integration step outside this quick start.
* **Rotate the keys.** The demo runs with the factory all-zero application
  keys. For production, change keys 1 and 2 (and the application master key)
  first — ``mifare keys change``, see :doc:`/mifare/mifare-desfire-guide` — and keep
  the verification keys server-side only.
* A verification backend should also check the read counter is **strictly
  increasing** per UID to reject replays of older URLs.

Next steps
----------

* :doc:`/mifare/mifare-desfire-guide` — applications, files, authentication, value and
  record files, key rotation
* :doc:`/mifare/mifare-desfire-commands` — every ``mifare`` command
