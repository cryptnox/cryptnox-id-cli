Quick start: prove a card is genuine
====================================

On a **contact** reader (the genuineness applet does not answer contactless):

.. code-block:: console

   $ cryptnox-id genuine info
   $ cryptnox-id genuine verify

``genuine info`` reports whether the attestation applet is present and
personalized, and shows the on-card device certificate's subject, issuer and
serial — no verification yet.

``genuine verify`` runs the two checks that prove genuineness:

#. **proof of possession** — the card signs a fresh host nonce with its on-card
   device key, so a copied certificate cannot pass;
#. **certificate chain** — the on-card certificate is chained to the **pinned**
   Cryptnox root.

The verdict is **GENUINE** only when *both* pass. The Cryptnox production root
ships bundled with the tool, so a production card anchors and verifies out of
the box:

.. code-block:: console

   $ cryptnox-id genuine verify
   Genuineness: GENUINE
     proof of possession (ATTEST): valid
     certificate chain: verified

.. note::

   A **development** card chains to a throwaway dev root and can never pass as
   genuine Cryptnox hardware — its verdict stays **NOT proven**. To test the
   flow against a dev PKI, anchor it explicitly:

   .. code-block:: console

      $ cryptnox-id genuine verify --anchors <dev-ca-dir>

Next steps
------------

* :doc:`/genuine/genuineness-guide` — what is checked, what deliberately is not,
  and how trust anchors work
* :doc:`/genuine/genuineness-commands` — every ``genuine`` command
