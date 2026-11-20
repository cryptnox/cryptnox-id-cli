Remote service commands
=======================

The ``remote`` commands run operations through the Cryptnox remote PIV
service. The card stays in the local reader; |cli| relays the commands the
service sends to the card and reports the outcome. What the service asserts
and what |cli| verified locally are shown apart. The service, the relay policy
and what each operation does to the card are described in
:doc:`/remote/remote-guide`.

Every command except ``remote ping`` opens the local reader first, then
connects to the service over TLS and answers a small proof-of-work before any
command is relayed. Only the PIV function and its security domains are
reachable through the relay; the other card functions are refused by the relay
policy.

Group options
-------------

.. code-block:: text

   remote [--full-transcript] COMMAND

   Options:
     --full-transcript   write relayed commands to --apdu-log and --verbose
                         without the extra masking the relay applies by
                         default; the standard secret masking still applies

The service itself
------------------

.. code-block:: text

   remote ping           ask the service what it runs and what it offers: its
                         build, the operations it serves, the PIV applet builds
                         it can install, its secure-channel policy. No card is
                         needed, the reader is not opened, and the call does
                         not count toward a card's operation limit.

Operations the service offers and |cli| does not run are listed apart; they
are reserved to Cryptnox's own tooling.

Identification and inspection
-----------------------------

.. code-block:: text

   remote authenticate   identify the card to the service: ATR and CPLC UID,
                         nothing else; key-free on both sides

   remote inspect        probe the PIV function through the service: whether
                         the PIV applet and its security domain are present
                         and which key versions they carry, read from the
                         key information template; a card that withholds it
                         may be probed with INITIALIZE UPDATE, which it counts
                         as a failed authentication (see the guide)

Both commands report the card as read locally (reader, ATR, CPLC UID), the
service's result as the service asserted it, and a cross-check of the fields
the two have in common.

``remote inspect`` also reads the PIV applet's build from the applet itself and
shows it: the FIPS-mode build, or the build with FIPS mode off. The service
reads the same flag through the relay; ``piv_build_matches`` under "Verified
locally" says whether the two agree.

Key attestation
---------------

.. code-block:: text

   remote attest [--slot 9C] [--algorithm ECCP256] [--out FILE]

                         generate a key in the slot through the service and
                         receive its key-attestation certificate; the service
                         also stores the certificate in the card's attestation
                         container. The slot's previous key and the container's
                         previous certificate are replaced: when either holds
                         something, the command asks, or needs --yes.

   Options:
     --slot HEX          9A, 9C, 9D, 9E or a retired slot 82 to 95 (default 9C)
     --algorithm NAME    ECCP256 (default), ECCP384, RSA2048, RSA3072, RSA4096
     --out FILE          write the returned certificate (PEM)

The returned certificate is verified locally before success is reported: the
chain must end at a pinned trust anchor, the subject serial number must be the
card's CPLC UID, the ``cryptnoxPivSlot`` extension must name the requested
slot, the trust model must be the server-driven value, and the certified
public key must equal the certificate read back from the card's attestation
container. That the key was generated on the card is the service's claim; the
tool cannot witness it and says so.

The service also names what it signed: the certificate's serial number and
SHA-256, and the SHA-256 of the certified public key. |cli| recomputes the
three from the returned certificate and reports them as
``certificate_serial_matches``, ``certificate_sha256_matches`` and
``public_key_sha256_matches``.

The service signs key attestations with one fixed CA key; there is no option
to choose another.

The result also names the admin channel the service drove the card over
(hardened or legacy, see :doc:`/remote/remote-guide`) and whether the public
key it certified reached it authenticated by the card. When it did not, or the
service does not say, |cli| warns that something between the service and the
card could have substituted the key. |cli| also warns before connecting when
the selected reader looks contactless: the service refuses ``attest`` over
that interface.

**On a finalized applet** nothing can be added, so the service generates the
new key in the slot's existing key object: the key now in the slot is
overwritten and cannot be recovered, and a certificate issued for it stops
matching the slot. The command reads the applet's state first, says so, and
asks before anything is sent (``--yes`` answers for a script); only then does
it send the confirmation the service requires. The slot must already have a
key object for the algorithm. The key attestation is stored on the card only
if the applet has an attestation container, which the built-in profiles do
not create; otherwise it is returned and not stored: the command says so and
prints the certificate unless ``--out`` was given. Nothing on the card can
then be compared with the certificate, so ``attestation_verified`` and
``attestation_container_written`` are ``null``, unchecked rather than failed,
and the run is not a failure. ``--out`` is checked for a writable directory
before anything is sent, so a mistyped path costs the card nothing.

Reset
-----

.. code-block:: text

   remote reset [--default-keys] [--piv-variant fips|fipsoff] [--fips-off]
                [--i-understand-this-is-irreversible]

                         IRREVERSIBLY wipe and reinstall the PIV function: the
                         service deletes the PIV applet, its package and its
                         security domain, reinstalls the applet, recreates the
                         security domain and loads the card's keys. Every PIV
                         key and certificate is destroyed. Interactively the
                         phrase RESET-PIV must be typed; non-interactively the
                         flag is required. --yes is not accepted.

   remote dev-reset [--default-keys] [--piv-variant fips|fipsoff] [--fips-off]
                    [--i-understand-this-is-irreversible]

                         Development cards only. As reset, but the card manager
                         and the PIV security domain are left on the public
                         default key, so the PIV function can be worked on
                         locally. Before anything is deleted the card must
                         prove it is genuine with one of its own keys; a card
                         that cannot is refused untouched and must be
                         re-provisioned by Cryptnox support. Only Cryptnox can
                         make the card genuine again. The phrase is
                         DEV-RESET-PIV.

   Options:
     --default-keys      on reset: reserved to Cryptnox. The service would
                         authenticate with the publicly known GlobalPlatform
                         default key and make the card genuine; it refuses
                         without a Cryptnox factory token and leaves the card
                         untouched.
                         On dev-reset: the card proves it is genuine with key
                         version 2 of its PIV security domain instead of its
                         card-manager key.
     --piv-variant NAME  the PIV applet build the service installs: fips, the
                         FIPS-mode build (default), or fipsoff, the same applet
                         with FIPS mode off
     --fips-off          short for --piv-variant fipsoff

Both builds come from the same applet source and carry the same identifiers;
the applet reports which one it is. With FIPS mode off the applet accepts
pre-personalization profiles the FIPS-mode build refuses (a PIN shorter than 6
digits, more than 15 retries, a PIN usable over the contactless interface
without secure messaging) and skips the FIPS power-up self-tests. Keys,
algorithms and commands are the same. After the operation |cli| asks the
applet which build it is and reports ``piv_build_matches``; a ``reset`` without
the option installs the FIPS-mode build again.

When the build with FIPS mode off is asked for, |cli| first asks the service
whether it offers that build (``remote ping``) and stops before opening the
reader when it does not.

Before asking for consent, both commands read and show what the card holds:
the PIV personalization state and data objects, the PIV security domain and
its key versions, and the state of the FIDO2 and genuineness functions, which
stay outside the operation. The same inventory is read again afterwards and
shown next to the service's result.

The service's result also names the admin channel it used and, after
``reset``, whether the applet's contactless-administration lock was set
(``nfc_admin_lock``). Both commands warn before asking for consent when the
selected reader looks contactless: the service administers the PIV function
over the contact interface.

When the service refuses
------------------------

A refused or failed operation exits with code 16. The message says what
happened and what to do next; with ``--json`` the error object carries a
``reason`` a script can branch on, the service's own answer under ``result``,
and ``retry_in_seconds`` or ``ref`` when the service gave them.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - ``reason``
     - Meaning
   * - ``rate_limited_card``
     - The service's limit of operations for this card is reached.
       ``retry_in_seconds`` says when the next one is accepted. Every operation
       on a card counts, ``inspect`` and ``authenticate`` included; ``ping``
       does not.
   * - ``rate_limited_source``
     - Too many connections from this network address.
   * - ``busy``
     - The service is running as many operations as it accepts at once.
   * - ``timeout``
     - The service stopped waiting for the card or the connection. The
       operation may be half done: inspect, then repeat.
   * - ``internal_error``
     - A fault on the service's side. ``ref`` is the reference to quote to
       Cryptnox support.
   * - ``legacy_channel``
     - The card's PIV security domain speaks a secure channel that cannot
       authenticate the card's answers. Key attestation is not issued on it,
       and other operations are reserved to Cryptnox.
   * - ``contactless``
     - The card answered over the contactless interface; the service
       administers the PIV function over the contact interface only.
   * - ``piv_build_unavailable``
     - The service does not offer the requested PIV applet build.
   * - ``factory_token_required``
     - This form of the operation is reserved to Cryptnox.
   * - ``card_not_genuine``
     - The card did not prove it is genuine with its own keys.
   * - ``applet_finalized``
     - The PIV applet is finalized and the operation could not go on: the
       slot has no key object for the algorithm (nothing can be added to a
       finalized applet), or the overwriting of the key in the slot was not
       confirmed. Nothing was changed.
   * - ``answer_altered``
     - An answer from the card was altered between the service and the card
       (the service reports an R-MAC mismatch). Check the relay path and
       report it; do not retry in a loop.
   * - ``unsupported_operation`` / ``unsupported_request``
     - The service does not offer the operation, or does not accept the slot
       or algorithm asked for.
   * - ``proof_of_work``
     - The service rejected the proof-of-work answer.
   * - ``refused``
     - Anything else; the message carries the service's own sentence.

When a local check fails
------------------------

Every command compares what the service asserts with what |cli| reads from
the card itself, under "Verified locally": the card's identity, the applet
build after a rewrite, the attestation after ``attest``. A check that does not
hold is printed as ``MISMATCH`` and the command exits with code 17 after
printing its result; with ``--json`` the result object carries the ``false``
and no error object follows it. A check with nothing to compare against is
``null``, printed as unchecked, and not a failure.

Endpoint
--------

The service endpoint is fixed to ``wss://piv.cryptnox.com``. For development
against a local stand-in, ``CRYPTNOX_REMOTE_URL`` redirects ``ping`` and the
identification and inspection commands only; it must be a ``wss://`` URL, or
``ws://`` to loopback. ``reset`` and ``dev-reset`` refuse to run while it is
set.
