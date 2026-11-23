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

A refused PIN, PUK or write
---------------------------

Nine commands answer a question the card may answer with "no": ``piv pin
verify``, ``piv pin change``, ``piv pin unblock``, ``piv puk change``, ``piv
perso set-pin``, ``piv perso set-puk``, ``piv perso import-cert``, ``piv perso
write-object`` and ``piv perso write-standard-objects``. When the card refuses,
they print their **result object**, not an error object, and exit with code 6:

.. code-block:: json

   {
     "verified": false,
     "sw": "63C5",
     "message": "Verification failed; 5 attempt(s) remaining.",
     "retries_remaining": 5
   }

The object is the one the command prints on success, with its outcome field
(``verified``, ``changed``, ``set``, ``imported``, ``written``, or ``ok`` per
object) set to ``false`` and the card's status word in ``sw``. A script can
test the exit code alone; one that reads the object gets the retries left
without a second command.

``piv pin verify``, ``pin change``, ``pin unblock`` and ``puk change`` add these
keys when they apply (for ``pin unblock`` the tries and the block are the PUK's):

- ``retries_remaining``: a wrong value, with that many tries left on this
  interface.
- ``blocked`` (``true``) and ``recovery``: ``6983`` over the contact interface,
  where it means the verifier is blocked.
- ``hint``: ``6983`` over contactless, or where the interface is not known: no
  tries are left on this interface, and the contact interface may still have
  some.

``63C0`` comes from a PIN or PUK without a retry limit: a wrong value, never a
block, so none of these keys is added.

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
     "pin": {"ref": "80", "configured": true, "blocked": false, "verified": false,
             "retries_remaining": 6, "refused_on_interface": false,
             "state": "tries_left", "interface": "contact"},
     "puk": {"ref": "81", "configured": true, "blocked": false, "verified": false,
             "retries_remaining": 6, "refused_on_interface": false,
             "state": "tries_left", "interface": "contact"},
     "objects_present": {"chuid": true, "ccc": true, "auth-cert": false},
     "notes": []
   }

``apt`` / ``pin`` / ``puk`` are ``null`` when not available. An entry in
``objects_present`` is ``null`` when its read failed, so the object may exist.
``refused_on_interface`` is ``true`` when the card answered the PIN or PUK probe
with 6982, which a contactless reader gets because every built-in profile but
``ms-logon-nfc`` makes both contact-only; ``configured``, ``blocked`` and
``retries_remaining`` are then ``null``: unknown, not false.

``state`` names what the card answered, and ``interface`` is ``contact``,
``contactless`` or ``unknown``. ``contact`` comes only from the applet's own
status report, so ``interface`` is ``unknown`` whenever the command did not read
that report. ``piv status``, ``info``, ``report`` and ``export-config`` always
ask for it; ``piv pin status`` asks only after a 6983 or 6982 answer.

- ``ok``: verified in this session.
- ``tries_left``: ``retries_remaining`` tries on this interface.
- ``no_retry_limit``: the verifier has no retry limit; ``blocked`` is
  ``false`` and ``retries_remaining`` is ``null``.
- ``blocked``: no tries left over the contact interface; ``blocked`` is
  ``true``.
- ``no_tries_on_interface``: no tries left over contactless, or where the
  interface is not known; ``retries_remaining`` is ``0`` and ``blocked`` is
  ``null``, because the contact interface may still have tries.
- ``refused_on_interface``: see above.
- ``not_configured``: the card has no such verifier.
- ``other``: an answer this tool does not read; ``configured`` and
  ``blocked`` are ``null``.

The same ``pin`` / ``puk`` objects appear in ``info --json`` and
``piv status --json``; ``piv pin status --json`` adds a top-level ``note``
string when either is refused. On a card set up with ``ms-logon-nfc`` a
contactless reader shows the PIN usable (with the tries that interface may
use) and the PUK refused, and the note is about the PUK alone.

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

Remote service operations
-------------------------

``remote`` commands return one object with a fixed top level: ``op``,
``endpoint``, ``card`` (reader, ATR, CPLC UID and serial, all read locally),
``result`` (the service's own result object, passed through unchanged),
``verified_locally`` (each cross-check as ``true``, ``false`` or ``null`` when
the service reported nothing to compare) and ``relay`` (commands relayed,
seconds, proof-of-work bits, the service's log lines, and
``open_initialize_updates``: per security domain, the INITIALIZE UPDATEs the
operation left without a completed authentication). ``reset`` and
``dev-reset`` add ``before`` and ``after`` inventories; ``attest`` adds
``verification`` with every binding checked on the returned certificate.
Fields under ``result`` are the service's assertions; only ``verified_locally``,
``before``, ``after`` and ``verification`` are the tool's own findings.
``reset`` and ``dev-reset`` add ``piv_variant``, and their inventories
``piv_build``; ``verified_locally`` carries ``piv_build_matches`` for
``reset``, ``dev-reset`` and ``inspect``, and for ``attest``
``attestation_returned``, ``attestation_verified``,
``attestation_container_written``, ``certificate_serial_matches``,
``certificate_sha256_matches``, ``public_key_sha256_matches`` and, with
``--out``, ``certificate_written_to_out``; ``out`` is the file written, or
``null``. A failed operation's error object gains ``reason`` and, when the
service gave them, ``retry_in_seconds`` or ``ref``. ``remote ping`` is the one
command without a card: it returns ``op``, ``endpoint``, ``client``,
``service`` (the service's answer, sanitised), ``operations_available``,
``operations_not_in_this_client`` and ``clock_skew_seconds``.
A ``false`` under ``verified_locally`` ends the command with exit code 17
after the object is printed; no error object follows it. ``null`` is not a
failure. ``channel`` and ``nfc_admin_lock`` under ``result`` are the
service's account of the admin channel it used and of the applet's
contactless-administration lock; ``public_key_authenticated`` is its claim
that the certified key reached it authenticated by the card.

``consumer-lock`` adds ``dry_run``, ``modes`` (``ssd_key1`` and ``mgmt_key`` as
asked for) and ``key_sheet``, the tool's account of the delivered keys.
``key_sheet.delivered`` says whether the service sent any. When it did,
``decrypted`` says whether they opened with this run's key, and when they did,
``keys`` (names only), ``kcv_match``, ``for_this_card``, ``saved_to`` and
``shown`` follow. ``lost`` is ``true`` when the keys are gone: they did not
decrypt, they could be neither saved nor shown, or a run that delivers keys
received none. ``error`` then says why; it also names a sheet file that could
not be written when the keys were shown on the terminal instead. The service's
``result.key_sheet`` is replaced by ``"decrypted locally"``, or by
``"not decrypted"`` when it did not open; no key value ever appears in the
output. ``verified_locally`` gains ``key_sheet_kcv_match`` and
``key_sheet_for_this_card``. A ``consumer-lock`` that ends with a
``key_sheet`` error (exit code 17) still writes one document: the error object
carries the whole result envelope (``op``, ``endpoint``, ``dry_run``,
``modes``, ``card``, ``result``, ``key_sheet``, ``verified_locally`` and
``relay``) beside ``error`` and ``message``. A failed ``consumer-lock`` carries
``key_sheet`` in its error object as well, with the same fields as on
success. ``remote key-sheet`` returns ``path``, ``op``,
``created``, ``scp``, ``uid_sha256``, ``kcv_match`` and ``keys``, which maps
each key's name to its value: that command exists to show them. When |cli|
stops a ``consumer-lock`` itself and the service still sends its result, the
error object carries it as ``result``, as a ``remote_failed`` error does.
