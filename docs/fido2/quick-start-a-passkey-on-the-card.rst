Quick start: a passkey on the card
==================================

Create a credential and prove the whole loop:

.. code-block:: console

   $ cryptnox-id fido info
   $ cryptnox-id fido credential self-test

``credential self-test`` registers a credential, requests an assertion, and
verifies the returned signature — the full WebAuthn round trip against the
real authenticator. A plain (non-resident, no user-verification) credential
doesn't need a PIN set at all on this authenticator (``fido info`` reports
``option alwaysUv: False``).

For a **resident (discoverable), PIN-verified** credential instead:

.. code-block:: console

   $ cryptnox-id fido pin set
   $ cryptnox-id fido credential self-test --rk --pin-env CRYPTNOX_FIDO_PIN
   $ cryptnox-id fido credential list --pin-env CRYPTNOX_FIDO_PIN

``credential list`` shows the credential stored and discoverable on the
card. Setting the PIN is one-way: it can only be changed afterward, not
removed, short of a full ``fido reset`` (which erases every credential).

.. note::

   If more than one PC/SC reader is present, the CLI's default reader
   auto-pick can grab the wrong one — pass ``--reader <substring>``
   explicitly (matching your reader's name) rather than assume it found the
   card you meant.

.. note::

   On **Windows**, run from an **Administrator** terminal: the OS reserves the
   FIDO applet from non-elevated processes. macOS and Linux need no elevation.
   User presence is satisfied automatically over the interface this was
   tested on (contact) without a separate physical tap.

Credential management
------------------------

.. code-block:: console

   $ cryptnox-id fido credential list --pin-env CRYPTNOX_FIDO_PIN
   $ cryptnox-id --yes fido credential delete --credential-id <id> --pin-env CRYPTNOX_FIDO_PIN

Deleting a credential drops the count reported by ``list`` immediately.
``delete`` asks for interactive confirmation; script it with the global
``--yes`` flag.

authenticatorConfig policy
-----------------------------

.. code-block:: console

   $ cryptnox-id fido config show
   $ cryptnox-id fido config toggle-always-uv --pin-env CRYPTNOX_FIDO_PIN

``config show`` is read-only. ``toggle-always-uv`` flips ``alwaysUv`` each
call, so running it twice restores the original state; when on, every
credential operation requires user verification regardless of what the
relying party asks for.

.. code-block:: console

   $ cryptnox-id fido config min-pin-length --length 5 --pin-env CRYPTNOX_FIDO_PIN

Unlike ``toggle-always-uv``, this is one-way: it only raises the minimum,
and the only way back down is a full reset.

Reset
--------

.. code-block:: console

   $ cryptnox-id fido reset --i-understand-this-wipes-all-credentials

Erases every credential and the PIN, and drops the minimum PIN length back
to its default. ``authenticatorReset`` normally has to be sent shortly after
the card is presented (a CTAP2 anti-remote-reset protection); if it's
refused, remove and reinsert the card and try again immediately.
