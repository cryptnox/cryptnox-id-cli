FIDO2 guide
===========

The FIDO2 applet (AID ``A0000006472F0001``) is reached with CTAP messages
tunnelled over ISO 7816 APDUs (``80 10 00 00 [CTAP cmd][CBOR]``). For the
condensed version, see :doc:`/fido2/quick-start-a-passkey-on-the-card`.

Windows: run elevated
-------------------------

On Windows the OS **blocks non-elevated processes** from talking to the
FIDO CTAP AID over PC/SC — you get ``SCARD_E_NO_ACCESS (0x80100027)``. This
is enforced by Windows itself (to reserve FIDO for the WebAuthn platform
API), not by the card, and it applies on **every** reader, contact or
contactless.

Run ``fido`` commands from an **Administrator terminal**. Every ``fido``
command surfaces this requirement up front — a warning if the process
isn't elevated (the call then fails with the error above), or a
confirmation that it is. In ``--json`` mode the note goes to stderr so
stdout stays pure JSON. ``doctor`` also reports the elevation state.

Read-only commands
----------------------

.. code-block:: console

   $ cryptnox-id fido ping            # SELECT the applet, show its version string
   $ cryptnox-id fido info            # authenticatorGetInfo (capabilities)
   $ cryptnox-id fido get-info        # alias of `info`
   $ cryptnox-id fido pin status      # is a clientPIN set? retries remaining?

``fido info`` decodes the CTAP ``authenticatorGetInfo`` map: supported
versions (``FIDO_2_0``, ``FIDO_2_1``, …), extensions, the 16-byte
**AAGUID** (matched against the known Cryptnox AAGUIDs), options (``rk``,
``clientPin``, ``credMgmt``, …), max message size, PIN/UV protocols,
transports, algorithms, and firmware version.

``fido pin status`` reads the ``clientPin`` option and, when a PIN is
configured, queries ``clientPIN.getPinRetries`` — non-destructive, it
doesn't consume a retry.

Write operations
--------------------

These use the CTAP2 **PIN/UV Auth Protocol** (ECDH key agreement →
AES/HMAC under protocol 1 or 2). PINs are entered by masked prompt or a
``--*-env`` variable, never on the command line, and are registered with
the redactor.

.. code-block:: console

   # PIN management
   $ cryptnox-id fido pin set                      # set the INITIAL PIN (masked, confirmed)
   $ cryptnox-id fido pin change                    # change an existing PIN

   # Credentials (require user presence - a tap)
   $ cryptnox-id fido credential create  --rp-id example.com [--rk] [--pin-env P]
   $ cryptnox-id fido credential assert  --rp-id example.com [--credential-id HEX] [--pin-env P]
   $ cryptnox-id fido credential self-test --rp-id example.com [--pin-env P]   # register->assert->verify

   # Credential management (resident credentials; PIN required)
   $ cryptnox-id fido credential list   --pin-env P            # enumerate resident credentials
   $ cryptnox-id fido credential delete --credential-id HEX --pin-env P

   # Destructive
   $ cryptnox-id fido reset --i-understand-this-wipes-all-credentials   # + typed RESET-FIDO

``credential self-test`` is the quickest end-to-end check: it registers a
credential, gets an assertion, and verifies the ES256 signature against the
registered key, reporting PASS/FAIL.

.. note::

   A FIDO PIN cannot be removed except by ``fido reset``, which erases
   **all** credentials and the PIN along with it. ``reset`` is gated by a
   flag and a typed ``RESET-FIDO`` confirmation, and — like most
   authenticators — only works shortly after the card is presented, with a
   tap; if it's refused, remove and reinsert the card and try again
   immediately. ``--protocol 1|2`` selects the PIN/UV auth protocol (1 is
   the universal default).

Credential management
-------------------------

``fido credential list`` enumerates resident (discoverable) credentials —
relying party, user, and credential ID for each. ``fido credential delete
--credential-id HEX`` removes one; the count reported by a follow-up
``list`` drops immediately. ``delete`` asks for interactive confirmation;
script it with the global ``--yes`` flag.

``fido pin change`` requires the current PIN as well as the new one — a
wrong current PIN decrements the retry counter, same as any other failed
PIN attempt, while a successful change doesn't cost a retry.

authenticatorConfig policy
------------------------------

``authenticatorConfig`` (CTAP ``0x0D``) changes device-wide policy. This
applet exposes two subcommands; each is authorized by a pinUvAuthToken
carrying the **authenticatorConfiguration** permission, so pass
``--pin-env NAME`` when a clientPIN is set. (The pinUvAuthParam is MACed
over a mandatory ``32×0xFF`` prefix — per the CTAP 2.1 spec, not a card
quirk.)

.. code-block:: console

   $ cryptnox-id fido config show                                   # read-only policy view
   $ cryptnox-id fido config toggle-always-uv --pin-env P           # flip alwaysUv (reversible)
   $ cryptnox-id fido config min-pin-length --length 6 --pin-env P  # raise the minimum (one-way)

* **``config show``** reports ``alwaysUv``, the minimum PIN length, and
  which config operations the applet exposes (``authnrCfg``,
  ``setMinPINLength``); it also flags that bio enrollment, large-blob, and
  enterprise attestation are **not** implemented by this applet.
* **``toggle-always-uv``** flips ``alwaysUv``; when on, every
  ``makeCredential``/``getAssertion`` requires user verification. Running
  it twice restores the original state.
* **``min-pin-length``** raises the minimum PIN length. It is **one-way**:
  the value can only increase; lowering it again requires ``fido reset``,
  which also erases every credential.

Scope
--------

Implemented: read-only inspection, PIN set/change, ``makeCredential``,
``getAssertion``, ``reset``, credential management (metadata, enumerate,
delete), and ``authenticatorConfig`` (``alwaysUv`` toggle +
``setMinPINLength``).

Not implemented by this applet: **bio enrollment** and **large-blob**
(confirmed via ``getInfo``: no ``bioEnroll``/``largeBlobs`` option, and the
card has no fingerprint sensor); **enterprise attestation** is likewise not
advertised (``ep`` absent).

Next steps
------------

* :doc:`/fido2/quick-start-a-passkey-on-the-card` — the condensed walkthrough this guide expands on
