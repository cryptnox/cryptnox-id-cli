Windows logon & Remote Desktop
==============================

Remote Desktop with a smart card is **Windows smart-card logon**: ``mstsc``
redirects the card into the session and the remote host performs Kerberos
PKINIT against a certificate on the card. This guide personalizes the card for
that — and for interactive Windows logon generally.

How it has to look
------------------

Windows reads the logon certificate from slot **9A** (PIV Authentication) via
the inbox PIV minidriver. The applet only performs client-authentication
signing for keys created with a SIGN-capable role, so the card must be
pre-personalized with the **ms-logon profile** (its 9A keys are
``AUTHENTICATE+SIGN``, and it adds an importable RSA-2048 object on 9A).

The certificate itself is dictated by Active Directory, not by the card:

* issued by the **enterprise CA** (present in the domain's NTAuth store) — a
  self-signed certificate can never log on;
* from a smart-card-logon template: *Client Authentication* and *Smart Card
  Logon* EKUs and the user's **UPN in the Subject Alternative Name**;
* since the KB5014754 strong-mapping enforcement, carrying the **SID security
  extension** — Active Directory Certificate Services adds it automatically
  when issuing against a user from a current template;
* the key in 9A must be **RSA** — see below.

.. important::

   **Use an RSA key on Windows. The inbox PIV minidriver does not enumerate EC
   keys.**

   With an EC key in 9A, Windows does not merely reject the certificate, it
   never builds a key container at all: ``certutil -scinfo`` reports
   ``NTE_BAD_KEYSET``, nothing appears in the Windows certificate store, and no
   application can offer the credential. The card looks empty rather than
   broken, which makes this easy to misdiagnose.

   This is a property of the Windows driver, not of this card. The same test
   reproduces on a YubiKey 5, and P-384 fails the same way as P-256.

   Because of this, pass ``--algorithm RSA2048`` to ``piv quickstart`` for any
   card intended for Windows (quickstart's default is ECC, and it warns when
   that default lands on ``ms-logon``'s 9A). The RSA key is still generated
   **on-card** and never leaves it, so choosing RSA costs nothing in key
   protection.

   If a deployment genuinely requires ECC on Windows, that needs a third-party
   minidriver (Yubico's supports P-256/P-384), which is outside the
   no-extra-software path this guide describes.

Step 0 — pre-personalize with the ms-logon profile (once per card)
------------------------------------------------------------------

.. code-block:: console

   $ cryptnox-id factory piv preperso load-config --profile ms-logon --default-keys
   $ cryptnox-id piv quickstart --profile ms-logon --include-preperso \
        --slot 9A --cert-mode csr --csr-out 9a.csr.pem --default-keys

The second form does everything in one shot — PIN, PUK, an on-card **RSA-2048**
key in 9A (the private key never leaves the card), a CSR for your CA, and the
CHUID/CCC objects Windows expects. It reports the key type it chose as it runs.

Step 1 — get the certificate issued
-----------------------------------

Two equivalent paths; pick the one your PKI supports.

**Path A — CSR to the CA (key stays on-card).** Submit ``9a.csr.pem`` against
a smart-card-logon template and import the issued certificate:

.. code-block:: console

   $ certreq -submit -attrib "CertificateTemplate:SmartcardLogon" 9a.csr.pem 9a-issued.cer
   $ cryptnox-id piv perso import-cert --slot 9A --cert 9a-issued.cer

**Path B — PKI-issued PKCS#12 (centralized key generation).** If your PKI
delivers a ``.pfx``/``.p12``, one command imports both the key and the
certificate:

.. code-block:: console

   $ cryptnox-id piv perso import-p12 --slot 9A --p12 user.pfx

(The container password comes from a masked prompt or
``CRYPTNOX_PIV_P12_PASSWORD``; chain certificates inside the container are
ignored — PIV stores the entity certificate.)

Step 2 — verify Windows sees the card
-------------------------------------

.. code-block:: console

   $ certutil -scinfo

You should see the card bind to the PIV minidriver ("Identity Device (NIST SP
800-73 [PIV])") and the 9A certificate listed.

Windows logon, like OpenSC, uses **standard PIV discovery and standard PIV
commands only** — an ``ms-logon`` card lists its certificate and produces a
PIN-verified signature with the 9A key under OpenSC (tested with the ECC key
on 9A; on-card signing with the RSA-2048 key is separately verified via the
CLI's smoke test). The Yubico-specific connect requirement of
``yubico-piv-tool`` (see the :doc:`/piv/quick-start-a-working-piv-card` interop note) plays no role in logon.

.. note::

   **If another vendor's smart-card middleware is installed** (SafeNet/Thales,
   etc.), its ATR mask may claim this card before Windows runs PIV discovery,
   handing it to the wrong driver. The fix is an administrator-level smart
   card registry association (Calais database) mapping this card's exact ATR
   to the PIV class minidriver — reversible, per machine. On machines without
   competing middleware, no configuration is needed.

Step 3 — log on
---------------

* **Local/interactive**: select the smart-card credential tile and enter the
  PIV PIN.
* **Remote Desktop**: in ``mstsc`` the card is redirected by default (Local
  Resources → Smart cards). Connect to the domain host and authenticate with
  the PIN at the remote credential prompt.

Scope and limits
----------------

* Smart-card logon requires a **domain** (Active Directory or hybrid-joined
  Entra ID). Standalone Windows machines do not support smart-card logon
  natively.
* Enrollment runs through |cli| (CSR or PKCS#12) — Windows-side enrollment
  tools that write directly to the card (certreq onto the card, MMC
  enrollment) use the Yubico-style management model and do not apply; this
  card administers over SCP03.
* The end-to-end logon path (PKINIT against a domain controller) can only be
  proven in a domain lab; the card-side personalization and minidriver
  recognition are verifiable standalone with ``certutil -scinfo``.

Next steps
----------

* :doc:`/piv/quick-start-a-working-piv-card` — the general PIV quick start and tooling interop
* :doc:`/factory/pre-personalization-profiles` — what the ms-logon profile defines
* :doc:`/piv/piv-commands` — ``import-key``, ``import-p12``, ``quickstart``
