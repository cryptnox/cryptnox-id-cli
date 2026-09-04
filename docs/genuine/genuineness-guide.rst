Genuineness guide
=================

The Cryptnox **genuineness / attestation applet** (RID ``A0000010``, AID
``A000001000024701``) carries an on-card EC device key and a device certificate
that chains to the Cryptnox PKI. It lets a host prove a card is genuine
Cryptnox hardware without any shared secret. For the condensed version, see
:doc:`/genuine/quick-start-prove-a-card-is-genuine`.

The applet is **contact-only** — it does not answer over a contactless reader
(SELECT returns ``6A82`` there) — and all ``genuine`` commands are
**read-only**: the applet is inspected, never provisioned, by this tool.

What is checked — and what deliberately is not
------------------------------------------------

There is more than one way to test a Cryptnox card's genuineness; the methods
differ in what secret the verifier needs. This tool performs the two checks
that need **no secret key material**:

* **Proof of possession (live).** The host sends a fresh random nonce and the
  card signs it with its device key (``ATTEST``); the signature is verified
  against the on-card leaf certificate's public key. Because the nonce is
  random per run, a copied certificate or a replayed signature cannot pass —
  the card must physically hold the device private key *now*.
* **Certificate chain.** ``leaf -> Genuineness CA -> … -> pinned Cryptnox root``,
  validated (name chaining, signatures, validity windows, CA constraints) and
  anchored on the pinned trust store. A root is trusted only because it is
  pinned — never because it appears in a chain read off the card.

The verdict is **GENUINE only when both pass**; proof of possession alone
yields **NOT proven**.

It deliberately does **not** attempt the ISD or PIV-SSD key checks: those
verify per-card, HSM/KDF-derived secret keys that this tool has no access to.
Their absence is stated in the output, never hidden.

Trust anchors
---------------

The Cryptnox production root ships bundled, together with the genuineness CA
that sits under it, so production cards anchor without extra setup. Where no
pinned root covers the chain, the chain step reports "cannot verify" and the
verdict is **NOT proven** even though proof of possession passes — the tool
never silently treats an unanchored chain as genuine.

Add anchors with ``--anchors DIR`` (a directory of CA PEMs) or the
``CRYPTNOX_TRUST_DIR`` environment variable; both **extend** the bundled set
rather than replacing it.

Development cards
-------------------

A **dev** card chains to a throwaway dev root and can never pass as genuine
Cryptnox hardware; ``genuine verify --anchors <dev-ca-dir>`` verifies it
against the dev PKI for testing the flow only.

Inspection without the proof
------------------------------

``info``, ``doctor`` and the ``report`` commands surface the applet's state
(present / personalized / not present) without running the proof;
``report genuine`` emits it as a secret-safe JSON snapshot (see
:doc:`/json-output`). Only ``genuine verify`` produces a verdict.

Next steps
------------

* :doc:`/genuine/quick-start-prove-a-card-is-genuine` — the condensed walkthrough
* :doc:`/genuine/genuineness-commands` — every ``genuine`` command
