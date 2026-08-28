JSON output
===========

Every command accepts the global ``--json`` flag for machine consumption.

The contract
------------

* The **result payload** is printed to **stdout** as a single JSON document.
* Notes, warnings and progress go to **stderr** — never merge the two streams
  into one parser (no ``2>&1``).
* Errors produce a JSON **error object** and a non-zero exit code (see
  :doc:`/exit-codes`).
* Secrets never appear in any output stream — every transcript and log line
  passes a redaction layer that masks PINs, keys and other registered secrets.

``--json`` is a **global** option: it goes before the command
(``cryptnox-id --json fido info``), not after it.

Result envelope
-----------------

On success, each command writes one JSON object whose fields are specific to
that command. For example, ``cryptnox-id --json doctor``:

.. code-block:: json

   {
     "checks": [
       {"check": "PC/SC service", "status": "ok", "detail": "1 reader(s) detected"},
       {"check": "Card present", "status": "ok", "detail": "ATR 3BFA1300..."}
     ],
     "ok": true
   }

Read-only inspection commands (``info``, ``piv info``/``status``, ``fido info``,
``mifare info`` …) each return the same fields their human output shows,
serialized as an object. Write commands return a small confirmation object
(what was done, and any public identifier produced — never a secret).

Error object
--------------

On failure the payload is an error object and the process exits non-zero:

.. code-block:: json

   {
     "error": "card_access_denied",
     "message": "FIDO2 access was blocked by Windows. ..."
   }

``error`` is a stable token (see :doc:`/exit-codes` for the token/exit-code
taxonomy); ``message`` is human-readable. Errors that carry an ISO status word
add three fields:

.. code-block:: json

   {
     "error": "status_word_error",
     "message": "...",
     "sw": "6A82",
     "sw_name": "FILE_NOT_FOUND",
     "context": "SELECT PIV"
   }

Snapshot reports
------------------

``report card`` / ``report piv`` / ``report mifare`` / ``report fido`` /
``report genuine`` / ``report full`` emit **secret-safe** JSON snapshots of the
detected state, suitable for fleet inventory or support tickets (``--out FILE``
writes to a file). These are the primary machine-consumption shapes and are kept
stable.

Every report is wrapped in a common envelope:

.. code-block:: json

   {
     "generated_by": "cryptnox-id 0.1.0",
     "generated_at": "2026-08-18T12:00:00+00:00",
     "safe_to_share": true,
     "<section>": {}
   }

``report full`` carries all sections at once; the single-function reports carry
just theirs. The section shapes:

**card**

.. code-block:: json

   {"reader": "<reader name>", "state": {}, "cplc": "<hex or null>"}

**piv**

.. code-block:: json

   {
     "state": "PivPersonalized",
     "apt": {"aid": "...", "label": "OpenFIPS201", "url": "..."},
     "pin": {"configured": true, "retries": 6},
     "puk": {"configured": true, "retries": 6},
     "objects_present": ["chuid", "ccc", "auth-cert"],
     "notes": []
   }

``apt`` / ``pin`` / ``puk`` are ``null`` when not available.

**mifare** — one of:

.. code-block:: json

   {"state": "DesfireReachable", "version": {}, "free_memory": 1234,
    "applications": ["CC0102"]}

.. code-block:: json

   {"state": "DesfireNeedsContactlessReader",
    "note": "DESFire ... use a DESFire-capable contactless PC/SC reader."}

.. code-block:: json

   {"state": "DesfireNoAnswerContactless",
    "note": "DESFire did not answer on this contactless interface. Re-present the card ..."}

``DesfireNeedsContactlessReader`` means the session is on a contact interface, which
cannot reach DESFire at all; ``DesfireNoAnswerContactless`` means the interface is
already contactless (reader name / ATR evidence) and the card simply did not answer —
re-present the card, and check the reader passes native DESFire APDUs.

**fido** — one of:

.. code-block:: json

   {"state": "FidoPersonalized", "select_version": "U2F_V2", "get_info": {}}

.. code-block:: json

   {"state": "FidoBlockedByOS", "note": "<Windows elevation guidance>"}

.. code-block:: json

   {"state": "FidoNotPresent"}

**genuine** — one of:

.. code-block:: json

   {"state": "GenuinenessPersonalized", "leaf_subject": "...",
    "info": "<hex>", "note": "state only; run `genuine verify` to prove ..."}

.. code-block:: json

   {"state": "GenuinenessNotPresent",
    "note": "genuineness applet not found (contact-only; absent over contactless)."}

A section may also report ``{"state": "Unknown", "error": "<message>"}`` when a
probe fails. Nothing in any report contains a PIN, key, or private material —
``safe_to_share`` is always ``true``.
