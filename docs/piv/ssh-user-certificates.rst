SSH user certificates
=====================

:doc:`/piv/ssh-public-key-authentication` authorizes the card's raw public key on each
server's ``authorized_keys``. **SSH user certificates** replace that with a
trust relationship: an SSH CA signs the card's public key once, every server
trusts the CA (one line in ``sshd_config``), and revocation/renewal happens
at the CA instead of editing ``authorized_keys`` everywhere the key was
copied. The card's role in this is identical to the raw-key guide — it only
ever signs the connection challenge; certificate issuance is a host-side
step this guide covers, not a card capability.

.. warning::

   **9C cannot be used for SSH on the unmodified ``cryptnox-default``
   profile**, for the same reason as :doc:`/piv/ssh-public-key-authentication` — see
   :ref:`ssh-why-it-fails-cryptnox-default`. The certificate layer doesn't
   change which key actually signs the connection; if the raw-key path
   fails on your card, this one will too. Use 9A instead — see
   :ref:`ssh-fix-9a-sign-role`.

   Also, do not use ``ssh-add`` to load the certificate — it cannot load a
   bare certificate file (``invalid format``) when the matching private key
   lives on a PKCS#11 token rather than on disk. Step 4 below uses
   ``CertificateFile`` + ``PKCS11Provider`` instead, which is the mechanism
   ``ssh_config(5)`` documents for this case.

Prerequisites
---------------

* Complete :doc:`/piv/ssh-public-key-authentication` first — this guide only adds a
  certificate on top of that public key, it doesn't replace any of it. That
  includes its contact-reader requirement — 9A's contactless access mode is
  ``NEVER``, and the certificate layer doesn't change what interface the
  underlying signature needs.
* An SSH CA keypair. For a self-managed CA:
  ``ssh-keygen -t ed25519 -f ssh_ca -C "internal SSH CA"`` (keep ``ssh_ca``
  offline; ``ssh_ca.pub`` is what servers trust). Larger deployments
  typically run a CA service (e.g. Vault SSH secrets engine, ``step-ca``)
  instead of a bare keypair — the signing command in Step 2 is the same
  either way, only how you invoke the signer differs.

Step 1 — export the card's public key
-----------------------------------------

Same as :doc:`/piv/ssh-public-key-authentication` Step 1:

.. code-block:: console

   $ ssh-keygen -D "$PKCS11_MODULE" -e > card-key.pub

Step 2 — the CA signs it
----------------------------

.. code-block:: console

   $ ssh-keygen -s ssh_ca -I "user-id" -n username -V +52w card-key.pub

This produces ``card-key-cert.pub``. ``-I`` is a certificate identifier (shows
up in server auth logs), ``-n`` restricts which login principal(s) the
certificate is valid for, ``-V`` sets an expiry — the CA can also constrain
by IP, force-command, or source address; see ``man ssh-keygen``.
Host certificates (signing the *server's* key so clients stop trusting
first-connection TOFU) use the same command with ``-h``, but that's a
server-key operation, unrelated to the card.

Step 3 — trust the CA on the server
---------------------------------------

One line in ``/etc/ssh/sshd_config``, instead of touching
``authorized_keys`` per user:

.. code-block:: text

   TrustedUserCAKeys /etc/ssh/ssh_ca.pub

Copy ``ssh_ca.pub`` (never the CA private key) to the server, then
``systemctl reload sshd``.

Step 4 — connect with the certificate
------------------------------------------

.. code-block:: console

   $ ssh -o PKCS11Provider="$PKCS11_MODULE" \
         -o CertificateFile=card-key-cert.pub \
         username@host

Do **not** use ``ssh-add card-key-cert.pub`` for this — ``ssh-add`` only
loads private keys (checking file permissions as if it might be one first),
and a bare certificate file has no matching on-disk private key to pair with
when the key itself lives on a PKCS#11 token. ``CertificateFile`` is the
option ``ssh_config(5)`` documents specifically for pairing a certificate
with a key provided via ``PKCS11Provider`` (or ``IdentityFile``/``ssh-agent``
for a disk-resident key). Make this permanent in ``~/.ssh/config``:

.. code-block:: text

   Host host
       PKCS11Provider /usr/lib64/pkcs11/opensc-pkcs11.so
       CertificateFile ~/card-key-cert.pub

Troubleshooting
------------------

* **Server still asks for a password / falls back** — confirm
  ``TrustedUserCAKeys`` points at the CA's *public* key and ``sshd`` was
  reloaded; check ``sshd -T | grep trustedusercakeys``.
* **"certificate invalid: not yet valid" / "expired"** — re-sign with ``-V``
  covering the current date; certificates don't auto-renew.
* **Principal mismatch** ("Certificate invalid: name is not a listed
  principal") — the ``-n`` value at signing time must match the login
  username (or use ``-n`` with multiple comma-separated principals).
* **"Error loading key ...: invalid format" from ssh-add** — you tried
  ``ssh-add card-key-cert.pub``, which doesn't work for a PKCS#11-resident
  key (see the warning at the top): use ``CertificateFile`` +
  ``PKCS11Provider`` in Step 4 instead.
* **"Permission denied (publickey)" / "agent refused operation" even with
  correct syntax and correct PIN, and you're using 9C** — this is the
  ``cryptnox-default``/9C always-reauth issue, identical to
  :ref:`ssh-why-it-fails-cryptnox-default`. The certificate doesn't change
  which key signs the connection — switch to 9A, see
  :ref:`ssh-fix-9a-sign-role`.
* Anything else from the raw-key path (module not found, other PIN/agent
  issues) — see :doc:`/piv/ssh-public-key-authentication` Troubleshooting first; this guide
  only adds the certificate layer on top.

Next steps
------------

* :doc:`/piv/ssh-public-key-authentication` — the raw-public-key path this builds on, including
  the 9A fix
