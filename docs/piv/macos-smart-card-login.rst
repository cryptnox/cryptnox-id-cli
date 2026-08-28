macOS smart-card login
======================

macOS recognizes a PIV card for login through Apple's own **CryptoTokenKit**
``pivtoken`` driver, not OpenSC/PKCS#11, there is no bypass. Pairing a card
to a local account is additive by default: the card becomes an alternative
to your password at the lock screen, ``sudo``, and full login, not a
replacement. Requiring the card and removing password login entirely is a
separate, optional, higher-risk step covered at the end.

.. warning::

   macOS's bundled CCID driver (still v1.5.1 as of macOS Tahoe) fails to
   negotiate this card's ATR outright: connect attempts return
   "unresponsive," even though the ATR itself reads fine. This isn't a
   reader problem (two different reader models fail identically) or a dead
   card (a T=0 connect attempt gets ``E_PROTO_MISMATCH`` rather than
   "unresponsive," proving the reader is talking to the card, just failing
   to open the T=1 session the card requires). The fix is Step 0 below;
   without it, nothing else in this guide will work.

How it has to look
---------------------

Same role rule as the rest of this card: the login/authentication signature
needs a **SIGN-capable** slot. This guide is written and tested against
**9A**, provisioned with the **ssh** profile (see :doc:`/factory/pre-personalization-profiles`)
— the same key used in :doc:`/piv/ssh-public-key-authentication`/:doc:`/piv/tls-client-authentication`.

.. note::

   ``cryptnox-default``'s 9C is **not recommended here**, and hasn't been
   tested for macOS login at all. 9C carries the PIV spec's
   ``nonRepudiation``/always-reauth convention (confirmed elsewhere on this
   card: a fresh re-login is required before every single signature, which
   breaks SSH/TLS via OpenSC — see :doc:`/piv/ssh-public-key-authentication`'s
   :ref:`ssh-why-it-fails-cryptnox-default`). That's a PIV-spec-level
   behavior, not an OpenSC quirk, so Apple's ``pivtoken`` driver may hit the
   same problem — genuinely unknown, not assumed safe. Use 9A.

``cryptnox-default`` is one named profile among several, not necessarily
what any given card has — check with ``factory piv preperso export-config``
or whoever personalized the card. Unlike Windows AD, macOS local pairing
doesn't require a specific EKU or UPN in the certificate — a plain client
certificate from :doc:`/piv/quick-start-a-working-piv-card` is enough.

Prerequisites
---------------

* A card already through :doc:`/piv/quick-start-a-working-piv-card` (key + certificate in a SIGN-capable
  slot), with the standard PIV objects written (``write-standard-objects``
  — CryptoTokenKit identifies the card as PIV through the CCC/CHUID).
* Admin access on the Mac.
* OpenSC, for the diagnostic check in Step 0 (``brew install opensc``). The
  actual login path doesn't use it, or need |cli| installed on the Mac at
  all — GUI login goes through Apple's own ``pivtoken`` driver exclusively.
* A **contact** reader. Only contact readers have been tried for this guide
  — by analogy with SSH/TLS (same signing key, same access-mode
  restriction) contactless is expected not to work, but that hasn't been
  separately confirmed on macOS.

Step 0 — fix macOS's CCID driver
------------------------------------

.. code-block:: console

   $ sudo defaults write /Library/Preferences/com.apple.security.smartcard useIFDCCID -bool yes

Then physically **unplug and replug the reader**, with the card inserted,
so the smartcard service reloads the driver. This switches macOS to the
alternative CCID driver (the actively maintained upstream one) instead of
Apple's outdated bundled one — not Cryptnox-specific; the CCID driver's own
author recommends this as the first troubleshooting step for any macOS
smartcard problem. The setting persists across reboots; if a later macOS
update breaks smart-card login, check this first.

Confirm the card now responds:

.. code-block:: console

   $ opensc-tool -n

Should report the card as a "Personal Identity Verification Card." If it
still says "unresponsive," the driver switch didn't take, confirm the
``defaults write`` succeeded and that you actually unplugged and replugged
the reader afterward (a service restart alone isn't enough).

Step 1 — pair the certificate to the account
-------------------------------------------------

Find the card's identity hash:

.. code-block:: console

   $ sc_auth identities

Shows an "Unpaired identities" line with a hash and the certificate's CN.
Pair it:

.. code-block:: console

   $ sc_auth pair -u $(whoami) -h <hash-from-above>

Prompts for your Mac account password once (to authorize the pairing), then
the card's PIV PIN. ``sc_auth list -u $(whoami)`` confirms the pairing
afterward. This is additive — your password still works everywhere; the
card is now an alternative, not a replacement.

.. note::

   ``security find-identity -p smartcard`` does not work on current macOS
   — the ``smartcard`` policy value isn't supported by ``find-identity``.
   Use ``sc_auth identities`` instead.

Step 2 — use it
---------------------

* **Lock screen**: lock the screen with the card inserted, enter the PIV
  PIN instead of your password to unlock.
* ``sudo``: ``sudo -v`` in Terminal accepts the card PIN too — macOS wires
  the card into ``sudo``'s PAM stack automatically, no separate setup.
* **Full login**: log out, sign in with the card inserted using the PIN.

Requiring the card (optional, higher risk)
-----------------------------------------------

.. warning::

   Unlike pairing, this removes the password fallback entirely. Test
   pairing thoroughly first (Step 2 above) with a card and reader you
   trust, before disabling password login. Keep an active admin session or
   physical access available until you've confirmed the card works at the
   login window with enforcement on.

.. code-block:: console

   $ sudo sysadminctl -smartcardstatus enable

Requires a smart card for **all** local accounts, not just the paired one.
For managed fleets, Apple's current guidance is a Smart Card configuration
profile pushed via MDM instead of this local command.

For pre-boot (FileVault) card requirement specifically, ``sc_auth
filevault -o enable`` exists but carries the same class of risk at the
very first screen of a cold boot, before any recovery options are
available — leave it off unless you specifically need it.

Troubleshooting
------------------

* **PIN entry stops working, card seems locked** — too many wrong PIN
  attempts blocks the card's PIN (6 tries on the default profile, see
  :doc:`/piv/quick-start-a-working-piv-card`); unblock with the PUK (``sc_auth changepin``, or from the
  Linux/CLI side). This is a card PIN lockout, not a login lockout — your
  password still works unless you've also enabled "require card" above.
* **``sc_auth: command not found`` / no ``-smartcardstatus`` flag** — Apple
  has changed and relocated these commands across macOS releases; check
  ``man sc_auth`` and ``man sysadminctl`` on the target OS, or use an MDM
  Smart Card profile instead.
* **Card not offered at login, or "unresponsive card" from any tool** —
  confirm Step 0's driver fix is applied and the reader was replugged
  afterward; this is the most common cause. Then confirm ``opensc-tool -n``
  sees the card outside the login window.
* **Locked out after enabling "require card"** — boot into Recovery / Safe
  Mode, or use another admin account, to run ``sudo sysadminctl
  -smartcardstatus disable``.
* **Cert expired** — login (and pairing) stops working once the PIV
  certificate expires; issue a new one and re-pair.
* **Card only responds over a contactless/NFC-capable reader, or a combo
  reader's contactless pad** — this card's signing slot has its contactless
  access mode set to ``NEVER``; the card itself refuses the private-key
  operation login needs over that interface, by design, not a driver or
  macOS bug. Use the reader's contact slot instead. The exact macOS-side
  error text for this case hasn't been captured yet (not independently
  tested over NFC on a Mac); on Linux/OpenSC the same underlying refusal
  surfaces as ``CKR_USER_NOT_LOGGED_IN`` at login, over a contact reader it
  works normally.

Next steps
------------

* :doc:`/piv/quick-start-a-working-piv-card` — provision the key and certificate this guide builds on
* :doc:`/factory/pre-personalization-profiles` — profile options for the signing slot
