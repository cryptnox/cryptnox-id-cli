Command syntax & conventions
============================

|cli| (aliases: ``cnx-id``, ``cryptnox-id-card``) manages the three
independent functions of the Cryptnox multi-applet smart card. Every command
supports ``-h``/``--help``.

Global options
--------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Meaning
   * - ``--reader <name|index>``
     - Select the PC/SC reader by substring or index (default: first ACS
       reader). When several candidate readers hold a card, the CLI refuses to
       guess — pass this explicitly.
   * - ``--json``
     - Machine-readable JSON on stdout; notes and warnings go to stderr. See
       :doc:`/json-output`.
   * - ``--verbose``
     - Human debug output; a redacted APDU trace on stderr.
   * - ``--apdu-log <file>``
     - Append a redacted APDU transcript to a file.
   * - ``--dry-run``
     - Write nothing to the card. Planning-capable commands (``piv quickstart``,
       ``apdu send``/``select``/``transcript``, ``factory piv preperso
       load-config``/``finalize``, ``piv perso import-key``/``import-p12``) show
       the intended actions; read-only commands run normally; every other
       command refuses to run under the flag (fail-closed) instead of silently
       executing.
   * - ``--yes``
     - Skip confirmation prompts (use deliberately).
   * - ``--timeout <seconds>``
     - Reader/card timeout.
   * - ``--no-color``
     - Disable coloured output.

Reader requirements per function: PIV works over contact (administration is
contact-only) or contactless (reading). **MIFARE DESFire needs a
DESFire-capable contactless reader.** **FIDO2 needs an Administrator terminal
on Windows** (the OS reserves the CTAP AID otherwise).

Top-level commands
------------------

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Command
     - Description
   * - ``readers``
     - List PC/SC readers, card presence and ATR; recommends a ``--reader``
       value.
   * - ``info``
     - Detect the card and summarize all three functions on one screen.
   * - ``doctor``
     - Diagnostics: PC/SC service, reader, transport, per-function
       reachability, platform notes.
   * - ``apdu send``
     - Developer raw-APDU access (transcripts are redacted; sensitive command
       data is never logged).
   * - ``apdu select``
     - SELECT an application by AID.
   * - ``apdu transcript``
     - Show the redacted APDU transcript of the session.
   * - ``report card`` / ``report piv`` / ``report mifare`` / ``report fido`` /
       ``report genuine`` / ``report full``
     - Secret-safe JSON reports (``--out FILE``).
   * - ``shell``
     - Interactive prompt: run subcommands without the ``cryptnox-id`` prefix
       (type ``piv info``); global options passed when launching carry into every
       command. ``help`` / ``clear`` / ``exit`` — see :doc:`/interactive-shell`.
