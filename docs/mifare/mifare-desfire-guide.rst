MIFARE DESFire guide
====================

The DESFire function is the card's **default applet** — it answers a fresh
contactless connection before any JavaCard applet is selected. All ``mifare``
commands need a **DESFire-capable contactless reader** (the ACS ACR1252 is
verified; some contactless readers do not pass native DESFire commands
through).

The CLI speaks authenticated DESFire (EV2 secure messaging: AES session keys,
command/response MACs, optional full encryption) and the DESFire EV3
Secure Dynamic Messaging feature, implemented against public NXP documentation
(application note `AN12196
<https://www.nxp.com/docs/en/application-note/AN12196.pdf>`_ and the DESFire
EV3 short data sheet).

Inspect (read-only)
-------------------

.. code-block:: console

   $ cryptnox-id mifare info          # version + free memory + applications
   $ cryptnox-id mifare version       # hardware/software version, storage, UID
   $ cryptnox-id mifare free-memory
   $ cryptnox-id mifare apps list
   $ cryptnox-id mifare files list --aid CC0102

Applications and files
----------------------

.. code-block:: console

   # 3 AES keys (key 0 = application master); new keys default to all-zero
   $ cryptnox-id mifare app create --aid CC0102 --keys 3

   # standard data file 0x01, 32 bytes, free read / keyed write
   $ cryptnox-id mifare files create-standard --aid CC0102 --file-id 01 --size 32

Authenticate, write, read
-------------------------

``AuthenticateEV2First`` establishes AES session keys and a transaction
identifier. Writes are sent MAC-protected (command and response MACs verified
by the CLI); free-read files read without authentication.

.. code-block:: console

   $ cryptnox-id mifare keys authenticate --aid CC0102 --key-no 0 --zero-key

   $ cryptnox-id mifare write --aid CC0102 --file-id 01 --data CAFEBABE --zero-key
   $ cryptnox-id mifare write --aid CC0102 --file-id 01 --in payload.bin --zero-key

   $ cryptnox-id mifare read --aid CC0102 --file-id 01 --length 4
   $ cryptnox-id mifare read --aid CC0102 --file-id 01 --out dump.bin

Writes larger than one native frame are split into command-chaining frames
automatically — the only ceiling is the file size.

Standard data files also support **fully encrypted** transfer: create the file
with ``--full``, then ``write --full`` / ``read --full --length N --zero-key``
(encrypted reads need the key too).

Delete (authenticated)
----------------------

Deleting an application requires authentication with the application master
key; the CLI authenticates and sends a MAC-protected ``DeleteApplication``:

.. code-block:: console

   $ cryptnox-id mifare app delete --aid CC0102 --zero-key

Value files
-----------

A value file holds a signed integer changed by credit/debit, persisted with a
transaction commit (issued by the CLI in the same authenticated session):

.. code-block:: console

   $ cryptnox-id mifare value create --aid CC0102 --file-id 02 \
        --initial 100 --lower 0 --upper 1000000
   $ cryptnox-id mifare value get    --aid CC0102 --file-id 02 --zero-key
   $ cryptnox-id mifare value credit --aid CC0102 --file-id 02 --amount 50 --zero-key
   $ cryptnox-id mifare value debit  --aid CC0102 --file-id 02 --amount 30 --zero-key

Record files
------------

Linear or cyclic record files; write and clear commit a transaction:

.. code-block:: console

   $ cryptnox-id mifare record create --aid CC0102 --file-id 03 \
        --record-size 8 --max-records 4 [--cyclic]
   $ cryptnox-id mifare record write  --aid CC0102 --file-id 03 \
        --data AABBCCDDEEFF0011 --zero-key
   $ cryptnox-id mifare record read   --aid CC0102 --file-id 03 --zero-key
   $ cryptnox-id mifare record clear  --aid CC0102 --file-id 03 --zero-key

Reading an empty record file returns ``BOUNDARY_ERROR (0xBE)`` — expected, it
simply has no records yet.

Keys
----

DESFire AES keys come from ``--zero-key`` (the all-zero factory default of a
new application) or ``--key-env NAME`` (hex in an environment variable) —
never on the command line. Keys are AES-128; legacy DES/3DES is intentionally
not supported.

Rotate a key (same-key change — authenticate with the key being changed):

.. code-block:: console

   $ cryptnox-id mifare keys change --aid CC0102 --key-no 0 --zero-key \
        --new-key-env NEWKEY
   $ cryptnox-id mifare keys authenticate --aid CC0102 --key-no 0 --key-env NEWKEY

**Cross-key change** — authenticate with a *different* key (typically the
application master, key 0) to change another key. The card requires the target
key's **current value** to authorize the change — supply it via
``--zero-key`` / ``--key-env``:

.. code-block:: console

   $ cryptnox-id mifare keys change --aid CC0102 --key-no 1 --zero-key \
        --new-key-env NEWKEY1 --auth-key-no 0 --auth-zero-key
   $ cryptnox-id mifare keys authenticate --aid CC0102 --key-no 1 --key-env NEWKEY1

A wrong current value is cleanly rejected (``INTEGRITY_ERROR (0x1E)``) and the
key is left unchanged. A lost application key is recoverable only via the PICC
master key.

Secure Dynamic Messaging (SDM / SUN)
------------------------------------

DESFire EV3 cards can mirror an encrypted UID + read counter and a MAC into a
free-read file on every read — a self-authenticating NFC tag. The
:doc:`/mifare/quick-start-a-tamper-evident-nfc-tag-sdm-sun` walks through it end to end; the short form:

.. code-block:: console

   $ cryptnox-id mifare sdm setup --aid CC0102 --file-id 02 --zero-key \
        --url "https://example.com/t"
   $ cryptnox-id mifare sdm read  --aid CC0102 --file-id 02

``sdm setup`` creates the file with the SDM option enabled (an EV3 file-creation
property), writes the URL template, and configures UID + read-counter mirroring
with the application's key 2 encrypting the mirrored data and key 1 keyed into
the MAC. ``sdm read`` plays verification backend: it decrypts the mirror,
checks the MAC, and reports the UID and read counter. Configuration and
verification follow the public NXP application note AN12196.

For production, rotate keys 1 and 2 away from the factory zero key first and
keep them server-side; verify reads by checking the MAC **and** a strictly
increasing counter per UID.

Format the PICC (destructive)
-----------------------------

``mifare format`` erases **every** application and file on the card via
``FormatPICC``; the PICC master key and its settings survive. It is gated by
``--i-understand-this-erases-all-applications`` (or a typed confirmation) and
authenticates with the PICC master key:

.. code-block:: console

   $ cryptnox-id mifare format --zero-key --i-understand-this-erases-all-applications

.. note::

   ``FormatPICC`` authenticates with the **PICC master key**. On factory cards
   that key is 2K3DES, and this CLI is AES-only by design — ``format`` checks
   the key type first and refuses with a clear message until the PICC master
   key has been provisioned to AES.

Scope
-----

Covered: read-only inspection; standard data files (plain, MAC-protected and
fully encrypted transfer, chunked writes); value files; record files
(linear/cyclic) — all with transaction commit; same-key and cross-key
``ChangeKey``; SDM/SUN configuration and host-side verification; ``FormatPICC``
(AES PICC master key required). Legacy DES/3DES authentication is intentionally
not supported.
