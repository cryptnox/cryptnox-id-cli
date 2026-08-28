Factory commands
================

Manufacturing-stage commands. Pre-personalization lays down the PIV applet's
*structure* — data containers, PIN/PUK verifiers, key objects — from a profile,
over the SCP03 admin channel. Operators normally never need these; development
and evaluation cards use them with ``--default-keys``. Production cards take
their admin keys from environment variables; production key management is a
manufacturing procedure outside this documentation.

.. code-block:: text

   factory piv preperso status            lifecycle + structure overview
   factory piv preperso inspect-defaults  show the built-in profiles
   factory piv preperso init-config       write a built-in profile to editable YAML
   factory piv preperso export-config     read-only snapshot of the card's structure
   factory piv preperso load-config       apply a profile to the card (supports --dry-run)
   factory piv preperso finalize          IRREVERSIBLY lock the applet structure

``load-config`` sends one structural operation per SCP03 session (a platform
requirement of this card), so a profile load is a sequence of short commands;
it stops at the first rejection and reports exactly what was applied.

Built-in profiles: ``cryptnox-default`` (the applet's own reference structure),
``developer`` / ``npivp-lab`` (the same structure, labelled for non-production
use), ``ssh`` (9A gets SIGN added, nothing else changes — see
:doc:`/piv/ssh-public-key-authentication`), and ``ms-logon`` (Windows smart-card logon /
Remote Desktop: 9A keys are SIGN-capable and an importable RSA-2048 object
coexists on 9A — see the
:doc:`/piv/windows-logon-and-remote-desktop`).

.. warning::

   ``finalize`` is **irreversible** — it locks the applet's structure for the
   card's lifetime (recovery means reinstalling the applet). It is gated by a
   typed confirmation token when run interactively, or the
   ``--i-understand-this-is-irreversible`` flag when run non-interactively —
   either satisfies the gate. Never run it on a card you are still developing
   against.

Profiles are documented in :doc:`/factory/pre-personalization-profiles`.
