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
   card's lifetime. A full reset of the PIV applet runs through the Cryptnox
   remote PIV service (:doc:`/remote/remote-guide`). It is gated by a
   typed confirmation token when run interactively, or the
   ``--i-understand-this-is-irreversible`` flag when run non-interactively —
   either satisfies the gate. Never run it on a card you are still developing
   against.

Profiles are documented in :doc:`/factory/pre-personalization-profiles`.

The card as a whole
-------------------

.. code-block:: text

   factory card status   the card's lifecycle and which JCOP modules are loaded
   factory card fuse     IRREVERSIBLY fuse the card

Both authenticate to the card manager: ``--default-keys`` for a development card
on the GlobalPlatform test keys, otherwise ``CARD_MANAGER_ENC`` /
``CARD_MANAGER_MAC`` / ``CARD_MANAGER_DEK``. ``status`` changes nothing; it
reports the lifecycle, which of the four modules are loaded, and whether the
configuration is sealed (the configuration module is gone).

``fuse`` is the manufacturer's last step. In this order it deletes the JCOP
sample modules (``egovaccelerators``, ``fips``, ``piv``) and then the
configuration module, which seals the chip's configuration; moves the card's
lifecycle to INITIALIZED and then SECURED, skipping what the card has already
reached; and replaces the card-manager key. A module that is already gone is
skipped. Afterwards it authenticates with the new key and reads the lifecycle
and the modules again. A fused card still loads and deletes applets for whoever
holds the card-manager key; SECURED is the card's normal operating state.

The new key comes from ``CARD_MANAGER_NEW_ENC`` / ``CARD_MANAGER_NEW_MAC`` /
``CARD_MANAGER_NEW_DEK``, or ``--randomize`` generates it. ``--randomize``
requires ``--out FILE``: the key file is written with mode 0600, never over an
existing file, before anything on the card changes. ``--dry-run`` shows the
plan and needs no current key.

.. warning::

   ``fuse`` cannot be undone. The configuration stays sealed, the lifecycle
   cannot go back from SECURED, and the card manager answers only to the new
   key. The command prints the card's state and a warning, then asks you to
   type ``FUSE-CARD``; ``-y`` skips the question, and non-interactive use
   requires ``-y``. Keep the new key: without it nobody can administer the
   card again.
