Pre-personalization profiles
============================

A **profile** describes the PIV applet structure to lay down during factory
pre-personalization: the data containers, the PIN/PUK verifiers and their
policy, and the asymmetric key slots with their access rules and mechanisms.
``factory piv preperso load-config`` turns a profile into a sequence of
OpenFIPS201 ``PUT DATA ADMIN`` commands over SCP03. See
:doc:`/piv/piv-personalization` for where this fits in the full lifecycle.

Built-in profiles
--------------------

``cryptnox-default``
   Byte-exact to the applet's own reference profile: an AES-256 admin key,
   ten containers (CHUID/CCC/certs/security-object/fingerprints/facial/printed),
   and five ECC-P256 key slots (9A/9C/9D/9E, plus the AES-only admin key 9B).

``developer`` / ``npivp-lab``
   The same structure as ``cryptnox-default`` — only the ``mode`` label
   differs (``developer-not-for-production`` / ``lab``), for cards that
   should never be mistaken for production units.

``ssh``
   SSH auth (raw public key or SSH user certificates) via PKCS#11
   (``ssh-agent`` / OpenSC) — see :doc:`/piv/ssh-public-key-authentication`. Only change
   from ``cryptnox-default``: the 9A (PIV Authentication) key gets
   ``SIGN`` added to its role (``SIGN+AUTHENTICATE``). 9C cannot be used for
   this regardless of role: OpenSC's PIV driver requires re-authentication
   before every signature on key reference 0x9C specifically (PKCS#11
   ``CKA_ALWAYS_AUTHENTICATE``, matching the PIV spec's non-repudiation
   convention for that slot), which neither ``ssh-agent`` nor ``ssh``'s own
   PKCS#11 client can satisfy.

``ms-logon``
   Windows smart-card logon / Remote Desktop. This applet dispatches PKI
   challenge signing on ``ROLE_SIGN`` only, so the 9A (PIV Authentication)
   key gets ``SIGN+AUTHENTICATE`` — that's what makes client authentication
   (PKINIT, SSH, TLS) *and* on-card CSR generation work on 9A. A second
   RSA-2048 (CRT) key object coexists on 9A — same slot, different mechanism,
   since the applet keys objects by ``(ref, mechanism)``. The role deliberately
   does **not** include ``KEY_ESTABLISH``: the applet routes challenge-response
   to key transport before signing, and that role would divert it. Use ``ssh``
   above instead if you only need SSH and don't need the extra RSA object.

   **That RSA object is why this profile works on Windows.** The Windows inbox
   PIV minidriver enumerates RSA keys only; given an EC key it builds no key
   container at all, so the card looks empty to Windows (see
   :doc:`/piv/windows-logon-and-remote-desktop`). The object can be filled either way:

   * **generated on-card** — ``piv quickstart --profile ms-logon --slot 9A
     --algorithm RSA2048`` (the private key never leaves the card);
   * **imported**, for an AD-issued credential (CSR → CA → import, or PKCS#12
     import via :doc:`/piv/piv-personalization`).

   The object carries the ``IMPORTABLE`` attribute so the second path is
   available; that attribute permits import, it does not prevent on-card
   generation.

Inspecting profiles
----------------------

.. code-block:: console

   $ cryptnox-id factory piv preperso inspect-defaults
   $ cryptnox-id factory piv preperso init-config --profile ms-logon --out profile.yaml

``inspect-defaults`` shows the applet's supported algorithms, key slots, and
PIN/PUK limits — no card needed. ``init-config`` writes a built-in
profile to an editable YAML file. To capture what a *card* currently exposes
(a read-only observed snapshot, not a loadable profile), use
``export-config --out snapshot.yaml``.

Profile YAML
---------------

.. code-block:: yaml

   name: cryptnox-default
   mode: production
   admin:
     key_ref: "9B"
     mechanism: AES256
   pin:
     min: 6
     max: 8
     retries: 6
     charset: numeric
   puk:
     min: 8
     max: 8
     retries: 6
     charset: numeric
   containers:
     - oid: 5FC102
       name: chuid
       contact: ALWAYS
       contactless: ALWAYS
     - oid: 5FC109
       name: printed
       contact: PIN
       contactless: VCI_PIN
   keys:
     - ref: "9C"
       name: sign
       mechanism: ECCP256
       role: SIGN
       contact: PIN
       contactless: NEVER
       attributes: [IMPORTABLE]

**Mechanisms**: ``AES128``, ``AES192``, ``AES256``, ``RSA2048``, ``RSA3072``,
``RSA4096``, ``ECCP256``, ``ECCP384``, ``CS2``, ``CS7``.

**Access modes** (used for ``contact``/``contactless`` on both containers and
keys): ``ALWAYS``, ``NEVER``, ``PIN``, ``VCI`` (contact-interface-only, no
PIN), ``VCI_PIN`` (contact interface **and** PIN), ``OCC``, ``SM``.

**Key roles** (a bitmask — combine with ``+``, e.g. ``AUTHENTICATE+SIGN``, or
give a YAML list): ``AUTHENTICATE``, ``KEY_ESTABLISH``, ``SIGN``.

**Key attributes** (a YAML list): ``IMPORTABLE``, ``PERMIT_EXTERNAL``,
``PERMIT_MUTUAL``, ``RSA_CRT``.

**PIN/PUK charset** (optional, defaults to ``numeric``): ``numeric``,
``alpha``, ``alpha_invariant``, ``raw``.

.. note::

   No built-in profile creates the Discovery Object container (``oid: 7E``).
   The object is optional in PIV, and a card without it works everywhere. To
   add it, put the container in a custom profile (as above) and write the
   object with ``piv perso write-object --object discovery``; it is written
   and returned in the bare ``7E`` form SP 800-73-4 requires — the one PIV
   object that must not be wrapped in a ``53`` template. Verified on hardware
   against OpenFIPS201 v2. A malformed (``53``-wrapped) Discovery Object is
   worse than an absent one: the Windows inbox PIV minidriver rejects the
   whole card. This tool never writes that form.

   The container also cannot be removed afterwards, because ``load-config``
   stops at the first element that already exists. Recovering a card requires
   reinstalling the PIV applet, which erases its keys and certificates.
   Discovery is optional in PIV, and a card without it works normally.

``from_yaml`` rejects unknown mode/role/mechanism names and validates the
whole profile before anything is sent to a card:

- the admin key mechanism must be AES-128/192/256 (this applet's 9B is
  AES-only);
- PIN and PUK ``min`` must be at least 6 and ``max`` must be ≥ ``min``;
- PIN and PUK ``retries`` must be 0–10;
- every key's mechanism must be one this applet actually supports (see
  ``inspect-defaults``);
- the profile must define at least one container or key.

Generate a starting file with ``init-config``, edit it, then apply it with
``load-config --file``.

Applying a profile
----------------------

.. code-block:: console

   # preview the exact APDUs without touching the card
   $ cryptnox-id factory piv preperso load-config --profile cryptnox-default --dry-run

   # apply (development/evaluation cards)
   $ cryptnox-id factory piv preperso load-config --profile cryptnox-default --default-keys

   # or apply a custom profile file
   $ cryptnox-id factory piv preperso load-config --file profile.yaml --default-keys

Each builder command is sent as a **single short APDU in its own SCP03
session** (JCOP 4.5 accepts one application APDU per applet-directed SCP03
session) — the CLI handles session setup/teardown per command for you.

Next steps
------------

* :doc:`/piv/piv-personalization` — the full lifecycle this structure feeds into
* :doc:`/piv/quick-start-a-working-piv-card` — the condensed, one-command path
* :doc:`/factory/factory-commands` — the full ``factory piv preperso`` command reference
