TLS client authentication
=========================

TLS client (mutual) authentication proves identity to a server with a
certificate instead of a password: the server requests a client certificate
during the TLS handshake, and the private key signs the handshake on-card
after a PIN prompt — the key never leaves the card, same as
:doc:`/piv/ssh-public-key-authentication`.

How it has to look
---------------------

Same role rule as the rest of this card: only a **SIGN-capable** slot can
perform the handshake signature. On the ``cryptnox-default`` built-in
profile that's slot **9C**; 9A is ``AUTHENTICATE``-only there and cannot be
used. If the card was provisioned with the **ssh** or **ms-logon** profile
instead, 9A is ``SIGN``-capable and works too — see :doc:`/factory/pre-personalization-profiles`.
``cryptnox-default`` is one named profile among several, not necessarily
what any given card has — check with
``factory piv preperso export-config`` or whoever personalized the card.

.. warning::

   Whichever slot you use, **it must be reached over the contact
   interface**. 9A's contactless access mode is ``NEVER`` on both
   ``cryptnox-default`` and ``ssh`` — a login attempt over a contactless
   reader fails at ``C_Login`` with ``CKR_USER_NOT_LOGGED_IN``, the card
   correctly refusing the interface, not a bug. Use a contact reader (or a
   combo reader's contact slot, not its contactless pad).

The certificate's **Extended Key Usage** matters more here than for SSH: it
must include *Client Authentication* (OID ``1.3.6.1.5.5.7.3.2``). The
self-signed certificate from :doc:`/piv/quick-start-a-working-piv-card` already carries it (no EKU
restriction). A certificate issued from :doc:`/piv/windows-logon-and-remote-desktop`'s
smart-card-logon template also carries it (that template includes *Client
Authentication* alongside *Smart Card Logon*), so it's reusable here — but for
a server that isn't Active Directory, prefer a plain client-auth certificate
without the UPN/logon-specific fields, since some relying parties reject a
certificate with a Smart Card Logon EKU it doesn't expect.

Prerequisites
---------------

* A card already through :doc:`/piv/quick-start-a-working-piv-card` (or :doc:`/piv/windows-logon-and-remote-desktop`)
  — a key and certificate in a SIGN-capable slot.
* A target that performs mutual TLS and is configured to trust the
  certificate's issuer (its own CA, or the self-signed cert imported directly
  into the server's trust store for testing).
* OpenSC, for the browser and command-line paths below — see
  :doc:`/piv/ssh-public-key-authentication` Step 0 for locating ``opensc-pkcs11.so``.
* **A contact reader** — see the warning above; the key's contactless access
  mode is ``NEVER``.

Firefox (NSS, cross-platform)
--------------------------------

Firefox uses its own certificate store (NSS), independent of the OS, on every
platform. Try the target site directly first:

1. Visit the target site. Some Firefox versions detect a PC/SC smart card
   natively and offer the card's certificate without any setup.
2. If no certificate is offered, register the module manually:
   ``about:preferences#privacy`` → **Security Devices** → **Load**. Module
   name: anything recognizable (e.g. ``Cryptnox PIV``). Module filename: the
   ``opensc-pkcs11.so`` path from :doc:`/piv/ssh-public-key-authentication`.
3. Reload the site. On a certificate request, Firefox shows a picker listing
   the card's certificate; selecting it prompts for the PIV PIN once per
   browser session.

Windows / IIS (native store)
-------------------------------

On Windows the inbox PIV minidriver exposes the card to CryptoAPI/CNG, so any
application using the Windows certificate store (IIS, Edge, curl built against
Schannel) sees the card certificate without a PKCS#11 module, the same
mechanism :doc:`/piv/windows-logon-and-remote-desktop` relies on for logon. Configure IIS to *request* or
*require* client certificates on the site binding, which is a server-side
setting rather than a card-side one, and the handshake triggers the PIN prompt.

Three card-side requirements apply here specifically:

* **9A must be SIGN-capable**, so the card needs the ``ms-logon`` (or ``ssh``)
  profile. Windows performs client authentication with the 9A key, and
  ``cryptnox-default``'s 9A is ``AUTHENTICATE``-only, which cannot produce the
  handshake signature.
* **The 9A key must be RSA.** The inbox minidriver does not enumerate EC keys:
  with an EC key the card produces no key container at all, so no certificate
  reaches the Windows store and nothing can be offered in the picker. This is a
  Windows driver property rather than a card one — it reproduces on a YubiKey,
  and P-384 behaves like P-256. Pass ``--algorithm RSA2048`` to
  ``piv quickstart --profile ms-logon --slot 9A`` for this reason (the ECC
  default warns on that combination). See :doc:`/piv/windows-logon-and-remote-desktop` for the detail.
* **The card must not carry a Discovery Object container.** No built-in profile
  creates one, so this only affects cards where ``oid: 7E`` was added by hand.
  Such a card is rejected outright by the minidriver: nothing enumerates and
  ``certutil -scinfo`` reports ``NTE_BAD_KEYSET``. See
  :doc:`/factory/pre-personalization-profiles`.

.. warning::

   Three server-side settings are easy to get wrong, and each produces a
   failure that looks like a card fault:

   * **``appcmd`` needs ``/commit:apphost``.**
     ``system.webServer/security/access`` is locked at the global level, so
     without it the write lands in the site's ``web.config`` and is refused.
     ``appcmd`` is a native executable, so this does not raise in PowerShell.
     ``sslFlags`` silently stays ``None``, IIS never asks for a client
     certificate, and the browser test yields a false negative. Always read the
     value back with ``Get-WebConfigurationProperty``.
   * **TLS 1.3 breaks browser client-certificate auth on Windows 11 before
     24H2.** TLS 1.3 replaced renegotiation with post-handshake authentication,
     which Chrome and Edge do not implement and Firefox does not enable by
     default, so http.sys resets the connection (``ERR_CONNECTION_RESET`` /
     ``PR_CONNECT_RESET_ERROR``). Enable negotiation on the binding instead of
     disabling TLS 1.3 machine-wide::

        netsh http add sslcert ipport=0.0.0.0:443 certhash=<thumbprint> \
            appid=<appid> certstorename=MY clientcertnegotiation=enable

     Confirm with ``netsh http show sslcert``; the line that matters is
     ``Negotiate Client Certificate : Enabled``.
   * **A successful ``curl`` does not prove the browser path works.** Windows
     ``curl`` uses Schannel, which does support post-handshake authentication,
     and ships without HTTP/2, so it returns ``200 OK`` in exactly the
     configuration where every browser fails.

.. note::

   In *request* mode (``SslNegotiateCert``) the page still loads if you cancel
   the certificate picker, so a page load alone does not prove the card signed
   anything. To prove it, use *require* mode (``SslRequireCert``): a client
   with no certificate is then refused with ``403.7`` on the same binding.
   Close every browser window between runs, since both the certificate choice
   and the TLS session are cached.

   Also type ``https://`` in full. Edge resolves a bare ``localhost`` to
   ``http://``, which returns ``403.4 ... secured with SSL`` from port 80
   without ever touching the HTTPS binding.

curl / OpenSSL (scripted clients)
-------------------------------------

The exact mechanism depends on your curl/OpenSSL build. Check ``curl -V`` for
the SSL backend, then ``curl --engine list`` — most current builds (OpenSSL
3.x with ``ENGINE`` support removed) have no PKCS#11 engine compiled in, in
which case use the provider-based path below instead of the older
``pkcs11:`` URI + legacy engine approach some older guides show.

**OpenSSL 3 provider path** (needs the ``pkcs11-provider`` package —
``dnf install pkcs11-provider`` on Fedora, or your distro's equivalent):

.. code-block:: text

   # openssl.cnf (a dedicated file via OPENSSL_CONF, not necessarily the
   # system config — activates both the default and pkcs11 providers)
   openssl_conf = openssl_init
   [openssl_init]
   providers = provider_sect
   [provider_sect]
   default = default_sect
   pkcs11 = pkcs11_sect
   [default_sect]
   activate = 1
   [pkcs11_sect]
   activate = 1
   pkcs11-module-path = /usr/lib64/pkcs11/opensc-pkcs11.so

.. code-block:: console

   $ export OPENSSL_CONF=/path/to/that/openssl.cnf
   $ curl --cacert server-ca.pem \
          --cert 9c.crt.pem \
          --key 'pkcs11:serial=<card serial>;type=private' --key-type PROV \
          https://target.example.com

Two details that aren't obvious from the ``pkcs11:`` URI syntax alone:

- **The certificate must come from a plain file, not a ``pkcs11:`` URI.**
  ``pkcs11-provider`` implements PKCS#11 key objects only, no
  ``CKO_CERTIFICATE`` support (its docs and man page never mention
  certificates). A ``type=cert`` URI silently matches nothing; it isn't an
  error, it just won't work. Export the certificate once
  (:doc:`/piv/quick-start-a-working-piv-card` already does, as ``9c.crt.pem``/``9a.crt.pem``) and
  point ``--cert`` at that file.
- **Plain ``pkcs11:`` URIs need ``--cert-type PROV``/``--key-type PROV``.**
  Without it, curl tries the legacy OpenSSL ``ENGINE`` API and fails with
  ``crypto engine not set, cannot load certificate`` on any build without a
  pkcs11 engine compiled in (``curl --engine list`` shows what's available —
  most current builds have none).
- **``serial=`` is the reliable URI identifier** if more than one PKCS#11
  token could be present (e.g. a second reader, or a token-less empty slot).
  A bare ``token=<label>`` or unqualified ``pkcs11:`` URI may resolve to the
  wrong slot, or hang waiting for a PIN on a reader you didn't mean to use.

Troubleshooting
------------------

* **Handshake fails / card returns 6985** — the slot's role doesn't include
  ``SIGN``; see `How it has to look`_ above.
* **Server rejects the certificate** — check the EKU includes *Client
  Authentication*, and that the server trusts the issuing CA (or the
  self-signed cert is imported into its trust store directly).
* **No certificate offered in the picker** — the store (NSS/CryptoAPI) isn't
  seeing the card; confirm the PKCS#11 module loaded (Firefox) or that the
  minidriver recognizes the card (Windows: ``certutil -scinfo``).
* **Windows: ``NTE_BAD_KEYSET`` from ``certutil -scinfo``, nothing enumerates**
  — the minidriver found no containers on the card. Check the two card-side
  requirements in `Windows / IIS (native store)`_ above: a SIGN-capable 9A, and
  no Discovery Object container. Note this error is not specific; an entirely
  blank PIV applet produces it too.
* **Windows: certificates appear in the picker that don't belong to this card**
  — certificates propagate into ``Cert:\CurrentUser\My`` and *stay there after
  the card is removed*. A stale entry makes the picker look correct while the
  inserted card contributes nothing. Match on the certificate subject before
  concluding the card was read.
* **curl: "No cert found in the openssl store" with no other error** — you
  used a ``pkcs11:`` URI for ``--cert``; switch to a plain certificate file
  (see the notes above — the provider doesn't support certificate objects).
* **curl hangs, or prompts for a PIN on a reader/token you didn't expect** —
  more than one PKCS#11 token is visible (e.g. a second reader plugged in);
  add ``serial=<card serial>`` to the URI to disambiguate instead of a bare
  ``token=`` label.
* **Login fails (``CKR_USER_NOT_LOGGED_IN`` or similar) with the correct PIN
  over a contactless reader** — 9A/9C's contactless access mode is ``NEVER``;
  this is the card refusing the interface by design, not a bug. Switch to a
  contact reader.

Next steps
------------

* :doc:`/piv/quick-start-a-working-piv-card` — provision the key and certificate this guide builds on
* :doc:`/piv/ssh-public-key-authentication` — the same PKCS#11 path, for SSH instead of TLS
* :doc:`/factory/pre-personalization-profiles` — the ``ssh``/``ms-logon`` profiles' 9A ``SIGN`` role
