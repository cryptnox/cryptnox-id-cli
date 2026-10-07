Exit codes
==========

|cli| exits non-zero on any failure; the code identifies the failure class.
With ``--json``, errors are also emitted as a JSON object carrying the matching
machine token (see :doc:`/json-output`).

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - Code
     - Token
     - Meaning
   * - 0
     - —
     - Success.
   * - 1
     - ``error`` (and specific tokens such as ``key_import``)
     - Generic CLI error not covered by a more specific class.
   * - 2
     - — / ``desfire_frame_too_large``
     - Command-line usage error (unknown option, bad parameter). Also used by
       one DESFire transport-limit error.
   * - 3
     - ``no_readers`` / ``reader_not_found`` / ``no_card`` / ``secret_input``
     - No usable reader/card, or a required secret could not be obtained
       safely (e.g. no TTY for a prompt and no environment variable).
   * - 4
     - ``card_access_denied``
     - The OS refused card access — on Windows this is the FIDO applet without
       an Administrator terminal.
   * - 5
     - ``applet_not_found`` / ``desfire_not_selected``
     - The requested function is not reachable on this card/interface.
   * - 6
     - ``status_word``
     - The card rejected a command (the message carries the ISO status word).
   * - 7
     - ``scp03_error``
     - SCP03 secure-channel failure (wrong admin keys, cryptogram mismatch).
   * - 8
     - ``profile_error``
     - Pre-personalization profile parse/validation failure.
   * - 9
     - ``desfire_error``
     - A DESFire command returned an error status.
   * - 10
     - ``ctap_error``
     - A FIDO2/CTAP command returned an error status.
   * - 11
     - ``ev2_error``
     - DESFire secure-messaging (session/MAC) failure.
