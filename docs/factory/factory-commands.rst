Factory commands
================

Manufacturing-stage commands. Pre-personalization lays down the PIV applet's
*structure* — data containers, PIN/PUK verifiers, key objects — from a profile,
over the SCP03 admin channel. Operators normally never need these. As shipped,
every card opens the admin channel with the GlobalPlatform test keys
(``--default-keys``); replacing them before production is described in
:ref:`piv-admin-key-rotation`, after which the commands take the keys from the
``PIV_SCP03_ENC`` / ``PIV_SCP03_MAC`` / ``PIV_SCP03_DEK`` environment
variables.

.. code-block:: text

   factory piv preperso status            lifecycle + structure overview
   factory piv preperso inspect-defaults  show the built-in profiles
   factory piv preperso init-config       write a built-in profile to editable YAML
   factory piv preperso export-config     read-only snapshot of the card's structure
   factory piv preperso load-config       apply a profile to the card (supports --dry-run)
   factory piv preperso set-mgmt-key      load the PIV management key (9B) value
   factory piv preperso finalize          IRREVERSIBLY lock the applet structure

``status`` never authenticates: the finalize (SECURED) state comes from the
applet's own status object, and the admin security domain's SCP version and key
versions from its key information template. On this chip an INITIALIZE UPDATE
that is not followed by a successful EXTERNAL AUTHENTICATE counts as a failed
authentication, so a read-only status must not send one. ``piv inventory`` lists
the structure itself.

``load-config`` sends one structural operation per SCP03 session (a platform
requirement of this card), so a profile load is a sequence of short commands;
it stops at the first rejection and reports exactly what was applied.

The PIV **management key** (key reference ``9B``) is the applet's own
administration key. Profiles create its key object but never carry a value,
because profiles are shareable files; ``set-mgmt-key`` writes the value over the
admin channel from ``--default-keys`` or ``PIV_MGMT_KEY``
(``CARD_PIV_MGMT_KEY`` is accepted as an alias). With ``--default-keys`` the
published value is written and the variable is not read. It refuses to create a
missing ``9B`` object and refuses to overwrite a value that is already set
unless ``--replace`` is given; ``status`` shows whether ``9B`` holds a value.

Built-in profiles: ``cryptnox-default`` (the applet's own reference structure),
``developer`` / ``npivp-lab`` (the same structure, labelled for non-production
use), ``ssh`` (9A gets SIGN added, nothing else changes — see
:doc:`/piv/ssh-public-key-authentication`), and ``ms-logon`` (Windows smart-card logon /
Remote Desktop: 9A keys are SIGN-capable and an importable RSA-2048 object
coexists on 9A — see the
:doc:`/piv/windows-logon-and-remote-desktop`).

.. warning::

   ``finalize`` is **irreversible** — it locks the applet's structure for the
   card's lifetime. A full reset of the PIV applet is a Cryptnox operation:
   contact Cryptnox support. It is gated by a
   typed confirmation token when run interactively, or the
   ``--i-understand-this-is-irreversible`` flag when run non-interactively —
   either satisfies the gate. Never run it on a card you are still developing
   against.

Profiles are documented in :doc:`/factory/pre-personalization-profiles`.
