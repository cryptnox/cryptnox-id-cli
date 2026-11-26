Factory commands
================

Commands for the card as a whole: the card manager's lifecycle and the JCOP
fuse. The PIV applet's structure is set up with the pre-personalization
commands (:ref:`piv-preperso-commands`).

.. code-block:: text

   factory card status   the card's lifecycle and which JCOP modules are loaded
   factory card fuse     IRREVERSIBLY fuse the card

Both authenticate to the card manager: ``--default-keys`` for a development card
on the GlobalPlatform test keys, otherwise ``CARD_MANAGER_ENC`` /
``CARD_MANAGER_MAC`` / ``CARD_MANAGER_DEK``. ``status`` changes nothing; it
reports the lifecycle and which of the four modules the card lists. A card can
leave these modules out of its listing while they are still loaded, so "not
listed" is no proof that a module is gone, and ``status`` reports the sealed
state as unknown unless the configuration module is listed.

``fuse`` is the manufacturer's last step. In this order it deletes the JCOP
sample modules (``egovaccelerators``, ``fips``, ``piv``) and then the
configuration module, which seals the chip's configuration; moves the card's
lifecycle to INITIALIZED and then SECURED, skipping what the card has already
reached; and replaces the card-manager key. A DELETE is sent for every module,
listed or not, and one that is already gone answers so. The configuration
counts as sealed when its DELETE answered that it was deleted or not present.
Afterwards it authenticates with the new key and reads the lifecycle again. A fused card still loads and deletes applets for whoever
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
   type ``FUSE-CARD``. ``--i-understand-this-is-irreversible`` skips the
   question and is required for non-interactive use; the global ``--yes``
   does not skip it. Keep the new key: without it nobody can administer the
   card again.
