SSH public-key authentication
=============================

SSH via PIV means the private key never leaves the card: ``ssh-agent`` loads
it through PKCS#11 (OpenSC), signs the challenge on-card after a PIN prompt,
and the server authorizes it like any other public key in
``authorized_keys``. No card-specific server-side support needed.

.. note::

   Everything below that references ``cryptnox-default`` applies to a card
   provisioned with that specific built-in profile — one option among
   several (see :doc:`/factory/pre-personalization-profiles`), not necessarily what any given
   card actually has. Check which profile your card was provisioned with
   (``factory piv preperso export-config``, or ask whoever personalized it)
   before assuming this section applies to you.

.. warning::

   **9C cannot be used for SSH on the ``cryptnox-default`` profile.**
   Steps 3/4 below fail with ``Permission denied (publickey)`` /
   ``agent refused operation`` even with the correct PIN, with or without
   ``ssh-agent`` in the loop — see `Why it fails on cryptnox-default`_. Use
   **9A with the SIGN role added** instead — the built-in ``ssh`` profile
   does exactly this — see `Fixing it: give 9A the SIGN role`_ below.

How it has to look
-------------------

The applet only performs challenge-response signing (what SSH auth needs)
for keys created with a **SIGN-capable role**. On ``cryptnox-default`` that's
slot 9C — but 9C's PIN policy makes it unusable for SSH regardless (see
below). 9A (PIV Authentication) is ``AUTHENTICATE``-role only on
``cryptnox-default`` and returns ``6985`` on a sign attempt, so it needs a
profile change before it can be used — the built-in **ssh** profile changes
only 9A's role (no extra objects, unlike **ms-logon**, which also adds
``SIGN+AUTHENTICATE`` to 9A but includes an importable RSA-2048 object for
AD-issued credentials you don't need here) — see :doc:`/factory/pre-personalization-profiles`
and `Fixing it: give 9A the SIGN role`_.

This guide's steps below use whichever slot has your key + certificate —
:doc:`/piv/quick-start-a-working-piv-card` puts them on 9C by default, which per the warning
above will not work for SSH. Provision 9A instead (next section) before
following Steps 0–4.

.. _ssh-why-it-fails-cryptnox-default:

Why it fails on cryptnox-default
-----------------------------------

- ``pkcs11-tool --login --sign`` against the 9C key succeeds, but prompts
  for the PIN **twice** — once for normal login, then again for
  "context specific PIN". That second prompt is PKCS#11's
  ``CKA_ALWAYS_AUTHENTICATE``: a fresh re-login is required immediately
  before *every single* signing operation, not just once per session.
- ``ssh-add -s`` then ``ssh -I`` (agent-mediated) fails: the agent only ever
  prompts once, at load time, and has no way to supply that second
  re-authentication later when a connection actually needs a signature —
  hence ``agent refused operation``.
- Bypassing the agent entirely — ``ssh -I "$PKCS11_MODULE"`` run directly,
  foreground, no agent involved — fails the same way. OpenSSH's own built-in
  PKCS#11 client only performs the normal login, not the context-specific
  re-login ``CKA_ALWAYS_AUTHENTICATE`` demands before signing. Only tools
  that explicitly implement that second step (like ``pkcs11-tool``) can use
  this key at all.

**Why it has to be 9A specifically:** ``pkcs15-tool --dump`` shows why 9C
behaves this way — its private key object reports
``Usage: [0x204], sign, nonRepudiation``. The ``nonRepudiation`` bit is what
triggers OpenSC's always-reauth handling; it matches PIV convention (slot
9C, "Digital Signature", is spec'd for non-repudiation, so the standard
expects fresh PIN verification before each signature). This is assigned by
OpenSC's PIV driver for key reference 0x9C specifically, independent of the
card's own profile or certificate — 9A's private key object reports plain
``Usage: [0x04], sign``, with no ``nonRepudiation`` bit, so it is not
subject to the always-reauth requirement. 9A is also the slot PIV itself
designates for cardholder-to-system authentication, and its access mode on
``cryptnox-default`` requires a PIN — **over the contact interface only**;
9A's contactless access mode is ``NEVER``, so none of this works over a
contactless-only reader (see Prerequisites below).

.. _ssh-fix-9a-sign-role:

Fixing it: give 9A the SIGN role
------------------------------------

You don't need the full ``ms-logon`` profile for this — the built-in ``ssh``
profile changes only 9A's ``role`` (``AUTHENTICATE`` -> ``AUTHENTICATE,
SIGN``); everything else is identical to ``cryptnox-default``. See
:doc:`/factory/pre-personalization-profiles` for the full built-in profile list.

This only applies at **pre-personalization** — it defines the key's role at
the structural level, not something a later ``piv perso`` step can change.
If your card already has a different profile applied (e.g. it already went
through :doc:`/piv/quick-start-a-working-piv-card` on 9C), it needs a factory-level applet
reinstall before this profile can be loaded — that's a manufacturing
operation outside this guide's (and this CLI's) scope; a blank/pre-perso
card needs no such step.

.. code-block:: console

   $ cryptnox-id factory piv preperso load-config --profile ssh --default-keys
   $ cryptnox-id piv perso set-puk --default-keys
   $ cryptnox-id piv perso set-pin --default-keys
   $ cryptnox-id piv perso generate-key --slot 9A --algorithm ECCP256 \
        --out 9a.pub.pem --default-keys
   $ cryptnox-id piv perso self-sign-cert --slot 9A --subject "CN=Test User" \
        --public-key 9a.pub.pem --out 9a.crt.pem
   $ cryptnox-id piv perso import-cert --slot 9A --cert 9a.crt.pem
   $ cryptnox-id piv perso write-standard-objects --default-keys

.. warning::

   Every step above must explicitly say ``--slot 9A``. :doc:`/piv/quick-start-a-working-piv-card`
   defaults everywhere to 9C, and copy-pasting those defaults here silently
   provisions the wrong slot.

.. note::

   ``piv perso smoke-test`` defaults to ``--slot 9C``. On this profile 9C
   was never populated, so the plain command fails with a **misleading**
   ``Authentication method blocked`` / "PIN or PUK is likely blocked" error —
   the PIN is not actually blocked; there's simply no key on 9C. Always run
   ``piv perso smoke-test --slot 9A`` here.

With that done, the card has a SIGN-capable, PIN-protected key on 9A and
Steps 0–4 below work as written.

Prerequisites
-------------

* A card already through :doc:`/piv/quick-start-a-working-piv-card` (PIN set, a key + certificate
  in the slot you're using).
* OpenSC (``opensc-pkcs11.so``) installed on the client. Debian/Ubuntu:
  ``apt install opensc``; Fedora: ``dnf install opensc``; macOS:
  ``brew install opensc``.
* ``ssh-agent`` running (``eval "$(ssh-agent)"``).
* **A contact reader** — 9A's contactless access mode is ``NEVER`` on both
  ``cryptnox-default`` and ``ssh``, so every step below fails over a
  contactless-only reader, distinctly from the 9C issue above. The card
  behaves identically whether inserted or read by a different physical
  reader, as long as it's the contact interface — reader model doesn't
  matter, only contact vs. contactless.

Step 0 — find the PKCS#11 module path
--------------------------------------

.. code-block:: console

   $ find / -name "opensc-pkcs11.so" 2>/dev/null

Typical locations: ``/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`` (Debian/Ubuntu),
``/usr/lib64/pkcs11/opensc-pkcs11.so`` (Fedora), ``/usr/local/lib/opensc-pkcs11.so``
(Homebrew). The rest of this guide calls it ``$PKCS11_MODULE``.

Step 1 — get the SSH public key off the card
----------------------------------------------

.. code-block:: console

   $ ssh-keygen -D "$PKCS11_MODULE" -e

This lists every card object OpenSC can present as an SSH key — one line per
certificate/key pair. If the card has more than one usable slot populated
(e.g. both 9C and a retired key-management slot), match by fingerprint/label
against ``pkcs15-tool --list-certificates``.

Step 2 — authorize it
-----------------------

Append that public-key line to the target account's
``~/.ssh/authorized_keys`` — same as any other SSH key, nothing card-specific
on the server side:

.. code-block:: console

   $ ssh-keygen -D "$PKCS11_MODULE" -e >> ~/.ssh/authorized_keys   # on the server, or copy manually

Step 3 — load it into ssh-agent
---------------------------------

.. code-block:: console

   $ ssh-add -s "$PKCS11_MODULE"

Prompts for the PIV PIN once (per ``ssh-agent`` lifetime, not per connection —
the applet's PIN state persists until the card is removed or the session
ends). ``ssh-add -l`` confirms the card key is loaded.

.. note::

   On ``cryptnox-default`` this step succeeds (``Card added``) and the key
   *lists* in ``ssh-add -l`` — but see the warning at the top of this guide:
   the actual sign at connection time still fails for 9C. A successful
   ``ssh-add -s`` does not mean the setup will work end-to-end.

Step 4 — connect
------------------

.. code-block:: console

   $ ssh -I "$PKCS11_MODULE" user@host

Or make it permanent in ``~/.ssh/config`` so plain ``ssh user@host`` picks it
up automatically:

.. code-block:: text

   Host host
       PKCS11Provider /usr/lib64/pkcs11/opensc-pkcs11.so

Troubleshooting
-----------------

* **No keys listed in Step 1** — the slot has a key but no certificate (or
  vice versa); OpenSC needs both to expose an SSH-usable object. Check
  ``pkcs15-tool --list-certificates`` and ``pkcs15-tool --list-keys``.
* **Sign operation fails / card returns 6985** — the slot's role doesn't
  include ``SIGN``. On unmodified ``cryptnox-default`` that's 9A — see
  `Fixing it: give 9A the SIGN role`_.
* **``ssh-add -s`` succeeds, PIN is correct, but connecting still fails with
  "Permission denied (publickey)" or "agent refused operation", and you're
  using 9C** — this is the ``cryptnox-default``/9C issue described in
  `Why it fails on cryptnox-default`_ above, not a misconfiguration. It
  reproduces identically with or without ``ssh-agent`` in the loop, so
  retrying agent setup won't fix it — switch to 9A instead
  (`Fixing it: give 9A the SIGN role`_).
* **``piv perso smoke-test`` says the PIN/PUK is blocked, but ``piv pin
  status`` shows full tries remaining** — you're on 9A and forgot
  ``--slot 9A`` (the command defaults to 9C); see the note in
  `Fixing it: give 9A the SIGN role`_.
* **Login fails against a PKCS#11 tool (``CKR_USER_NOT_LOGGED_IN`` / similar)
  even with the correct PIN, and the reader is contactless** — 9A's
  contactless access mode is ``NEVER``; this is the card correctly refusing
  the interface, not a PIN or software problem. Switch to a contact reader —
  see Prerequisites.

Next steps
------------

* :doc:`/piv/quick-start-a-working-piv-card` — provision the key and certificate this guide builds on
* :doc:`/factory/pre-personalization-profiles` — profile YAML grammar (role, access mode, mechanisms)
