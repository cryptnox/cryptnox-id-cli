FIDO2 commands
==============

FIDO2 authenticator management over NFC (PC/SC). **Windows requires an
Administrator terminal** — the OS reserves the FIDO applet identifier from
non-elevated processes; the CLI detects this and says so. PINs come from
``--pin-env`` variables or masked prompts.

Inspection
----------

.. code-block:: text

   fido ping          SELECT + version string
   fido info          authenticatorGetInfo, summarized
   fido get-info      authenticatorGetInfo, raw decoded map

PIN
---

.. code-block:: text

   fido pin status    PIN set? retries left? (non-destructive)
   fido pin set       set the initial PIN
   fido pin change    change the PIN

Credentials
-----------

.. code-block:: text

   fido credential create      makeCredential (WebAuthn registration)
   fido credential assert      getAssertion (WebAuthn authentication)
   fido credential self-test   register -> assert -> verify the signature
   fido credential list        resident (discoverable) credentials
   fido credential delete      delete a resident credential

User presence over NFC is satisfied by card presence on the reader. A usable
credential requires user verification — set a PIN first.

Configuration
-------------

.. code-block:: text

   fido config show              authenticator options and policy
   fido config toggle-always-uv  flip the alwaysUv policy (reversible)
   fido config min-pin-length    raise the minimum PIN length (one-way)

Destructive
-----------

.. code-block:: text

   fido reset    authenticatorReset: wipes ALL credentials and the PIN
                 (gated by --i-understand-this-wipes-all-credentials)

Not exposed by this card: bio enrollment, large blobs, enterprise attestation.
