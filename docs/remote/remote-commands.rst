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

Endpoint
--------

The service endpoint is fixed to ``wss://piv.cryptnox.com``. For development
against a local stand-in, ``CRYPTNOX_REMOTE_URL`` redirects the identification
and inspection commands only; it must be a ``wss://`` URL, or ``ws://`` to
loopback.
