Remote service commands
=======================

The ``remote`` commands run operations through the Cryptnox remote PIV
service. The card stays in the local reader; |cli| relays the commands the
service sends to the card and reports the outcome. What the service asserts
and what |cli| verified locally are shown apart. The service, the relay policy
and what each operation does to the card are described in
:doc:`/remote/remote-guide`.

Every command opens the local reader first, then connects to the service over
TLS and answers a small proof-of-work before any command is relayed. Only the
PIV function and its security domains are reachable through the relay; the
other card functions are refused by the relay policy.

Group options
-------------

.. code-block:: text

   remote [--full-transcript] COMMAND

   Options:
     --full-transcript   write relayed commands to --apdu-log and --verbose
                         without the extra masking the relay applies by
                         default; the standard secret masking still applies

Identification and inspection
-----------------------------

.. code-block:: text

   remote authenticate   identify the card to the service: ATR and CPLC UID,
                         nothing else; key-free on both sides

   remote inspect        probe the PIV function through the service: whether
                         the PIV applet and its security domain are present
                         and which key versions they carry; key-free, the
                         relay refuses any authentication attempt

Both commands report the card as read locally (reader, ATR, CPLC UID), the
service's result as the service asserted it, and a cross-check of the fields
the two have in common.

Key attestation
---------------

.. code-block:: text

   remote attest [--slot 9C] [--algorithm ECCP256] [--ca-obj HEX] [--out FILE]

                         generate a key in the slot through the service and
                         receive its key-attestation certificate; the service
                         also stores the certificate in the card's attestation
                         container. The slot's previous key and the container's
                         previous certificate are replaced: when either holds
                         something, the command asks, or needs --yes.

   Options:
     --slot HEX          9A, 9C, 9D, 9E or a retired slot 82 to 95 (default 9C)
     --algorithm NAME    ECCP256 (default), ECCP384, RSA2048, RSA3072, RSA4096
     --ca-obj HEX        signing sub-CA in the service; omit for the
                         key-attestation CA
     --out FILE          write the returned certificate (PEM)

The returned certificate is verified locally before success is reported: the
chain must end at a pinned trust anchor, the subject serial number must be the
card's CPLC UID, the ``cryptnoxPivSlot`` extension must name the requested
slot, the trust model must be the server-driven value, and the certified
public key must equal the certificate read back from the card's attestation
container. That the key was generated on the card is the service's claim; the
tool cannot witness it and says so.

Reset
-----

.. code-block:: text

   remote reset [--fused] [--i-understand-this-is-irreversible]

                         IRREVERSIBLY wipe and reinstall the PIV function: the
                         service deletes the PIV applet, its package and its
                         security domain, reinstalls the applet, recreates the
                         security domain and loads the card's keys. Every PIV
                         key and certificate is destroyed. Interactively the
                         phrase RESET-PIV must be typed; non-interactively the
                         flag is required. --yes is not accepted.

   remote dev-reset [--fused] [--i-understand-this-is-irreversible]

                         Development cards only. As reset, but the card manager
                         and the PIV security domain are left on the public
                         default key, so the PIV function can be worked on
                         locally. Needs the development access credential in
                         $CRYPTNOX_REMOTE_DEV_TOKEN (never an option). The
                         phrase is DEV-RESET-PIV.

   Options:
     --fused             the card is a fused production card: the service
                         derives its per-card card-manager key. On a card that
                         is not fused the derived key is wrong and the failed
                         authentication costs a card-management retry.

Before asking for consent, both commands read and show what the card holds:
the PIV personalization state and data objects, the PIV security domain and
its key versions, and the state of the FIDO2 and genuineness functions, which
stay outside the operation. The same inventory is read again afterwards and
shown next to the service's result.

Endpoint
--------

The service endpoint is fixed to ``wss://piv.cryptnox.com``. For development
against a local stand-in, ``CRYPTNOX_REMOTE_URL`` redirects the identification
and inspection commands only; it must be a ``wss://`` URL, or ``ws://`` to
loopback. ``reset`` and ``dev-reset`` refuse to run while it is set.
