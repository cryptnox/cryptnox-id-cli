Genuineness commands
====================

All ``genuine`` commands are **read-only** and **contact-only** — the
attestation applet does not answer over a contactless reader (SELECT returns
6A82 there). What is checked, what deliberately is not, and how trust anchors
work are covered in :doc:`/genuine/genuineness-guide`.

Inspection
----------

.. code-block:: text

   genuine info      SELECT + GET INFO + GET CERT; reports present / personalized,
                     device leaf subject, issuer, serial (no verification)

Verification
------------

.. code-block:: text

   genuine verify    live ATTEST (proof of possession) + certificate chain to a
                     pinned Cryptnox root; verdict GENUINE only when BOTH pass

   Options:
     --nonce HEX     challenge to sign (default: 32 random bytes)
     --anchors DIR   directory of extra pinned CA PEMs (e.g. a dev genuineness
                     CA) to anchor the chain

The Cryptnox production root ships bundled, together with the genuineness CA
that sits under it, so production cards anchor without extra setup. Where no
pinned root covers the chain, the verdict is **NOT proven** — extend the
anchors with ``--anchors`` or ``$CRYPTNOX_TRUST_DIR``. A **dev** card chains to
a throwaway dev root and can never pass as genuine Cryptnox hardware;
``genuine verify --anchors <dev-ca-dir>`` verifies it against the dev PKI for
testing.
