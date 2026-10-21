Remote service guide
====================

Some PIV lifecycle operations need keys that never leave Cryptnox: the key
that makes a card genuine, and the certificate authority that attests keys
generated on it. The remote PIV service holds those keys in a hardware
security module and performs the operation over a relayed command channel,
with the card in the holder's own reader.

How a relayed operation works
-----------------------------

1. |cli| opens the local reader and reads the card's ATR and CPLC serial.
2. It connects to the service over TLS and names the operation.
3. The service issues a small proof-of-work; |cli| answers it. This is an
   anti-abuse throttle, not a credential.
4. The service sends card commands one at a time. |cli| checks each one
   against the relay policy, transmits it, and returns the card's answer
   verbatim, status word included. |cli| never sends a command of its own and
   never reassembles a chained response; the service sees the card exactly as
   a local reader would.
5. The service returns a result. |cli| shows it as the service's assertion and
   adds what it verified locally.

The relay policy
----------------

The card carries more than the PIV function. A relay that executed whatever
it was sent would expose the wallet, the FIDO2 passkeys and the genuineness
key to the service. The relay policy is an allow-list, per operation, over
what a command header reveals: the selected applet, the class byte, the
instruction, and for a SELECT the target application. Anything not listed is
refused, the operation stops, and the refusal names the command header.

The policy also caps the number of commands and the time an operation may
take, limits secure-channel authentication attempts per security domain, and
never relays a card-holder PIN or PUK command. Inside a secure channel only
the class and instruction bytes stay in the clear, so the policy fences which
security domain the channel was opened to and which instructions pass through
it; it cannot see what an encrypted command carries.

Operations
----------

``authenticate``
   Reads the ATR and CPLC serial. Key-free. Allows only card-manager reads.

``inspect``
   Probes whether the PIV applet and its security domain are present and which
   key versions they carry. Key-free: the service reads each security domain's
   key information without authenticating, and the relay refuses every
   EXTERNAL AUTHENTICATE. A run leaves no failed authentication on the card.

``attest``
   Generates a key in one slot and returns a key-attestation certificate for
   it, signed by the Cryptnox key-attestation CA and stored in the card's
   attestation container as well. The relay policy admits the applet's admin
   channel for the key-object setup, the management-key handshake (never a
   slot key), key generation for the requested slot only, and the certificate
   write. The tool then verifies the certificate against the pinned anchors and
   binds it to the card, the slot and the certificate stored on the card. The
   certificate write itself is not bound to the slot: PUT DATA names its object
   inside the data, so the service could write any PIV data object during the
   operation, and only the certificate read back is checked. The generation
   itself happening on the card is the service's claim; nothing the relay sees
   authenticates it.

``reset``
   Wipes and reinstalls the PIV function. The service authenticates to the
   card manager, deletes the PIV applet, its package and its security domain,
   loads the applet again, recreates the security domain and loads the card's
   keys, then verifies the result. Every PIV key and certificate is destroyed;
   the keys were never exportable, so nothing can bring them back. Interactive
   use requires typing ``RESET-PIV``; non-interactive use requires
   ``--i-understand-this-is-irreversible``. ``--yes`` is not accepted.

   The relay policy for this operation admits card content management through
   the card manager only, lets a DELETE name nothing but the PIV instance, its
   package and its security domain, refuses a DELETE it cannot read unless the
   channel encrypts commands, caps authentication attempts per security
   domain, and stops at the first failed authentication so no further attempt
   adds to the card's count. Inside an encrypted channel the policy
   sees instructions, not targets; that limit is real and is why the FIDO2 and
   genuineness state is read before and after.

``dev-reset``
   As ``reset``, for development cards, leaving the card manager and the PIV
   security domain on the publicly documented GlobalPlatform key so the PIV
   function can be pre-personalized and personalized locally. Before anything
   is deleted, the card must prove it is genuine with one of its own keys (see
   below); a card that cannot is refused untouched. Afterwards anyone with a
   reader can install or delete applets on the card, and only Cryptnox can make
   it genuine again.

What a failed authentication costs
----------------------------------

A security domain counts every INITIALIZE UPDATE that is not followed by a
successful EXTERNAL AUTHENTICATE, including one for a key version it does not
hold. After five, it answers each further INITIALIZE UPDATE about 24 seconds
late, until a successful authentication to it clears the count. There is no
lockout, only the delay. Which security domains keep this count depends on the
chip: on some only the card manager does, on others the PIV security domain
does as well. This is why the relay caps authentication attempts per
operation. For the PIV security domain, ``piv admin authenticate`` with the
card's own keys clears the count; the card manager's clears only with an
authentication to the card manager.

The ``--default-keys`` flag
---------------------------

By default the service authenticates to the card manager with the card's own
key, derived per card from its identity. That is the state a card leaves the
factory in, and a ``reset`` keeps it.

On ``reset``, ``--default-keys`` asks the service to authenticate with the
published GlobalPlatform default key instead and make the card genuine. That
is a Cryptnox operation: the service refuses it without a Cryptnox factory
token, and the refusal leaves the card untouched. A card that ended up on the
default key, for example after a ``dev-reset``, is re-provisioned by Cryptnox
support.

On ``dev-reset``, the flag selects how the card proves it is genuine before
anything is deleted: without it, with its card-manager key; with it, with key
version 2 of its PIV security domain. A card that can prove neither is refused
untouched; Cryptnox support re-provisions it. The service's refusal may suggest
``reset --default-keys``, which it refuses without a factory token.

What is sent to the service
---------------------------

The card's ATR and CPLC serial identify the card to the service. They are the
same values any reader can obtain from the card without a key. Nothing else
about the card holder is sent.

Transcripts
-----------

With ``--apdu-log`` or ``--verbose``, relayed commands are written with their
data masked unless the instruction is a known-harmless read, because the
service chose the command and |cli| cannot vouch for what it carries.
``remote --full-transcript`` lifts that extra masking for troubleshooting; the
standard masking of secret-bearing commands still applies.

Relayed lines start with ``relay``, so they read apart from the commands |cli|
sends on its own before and after the operation::

   > 00A4040008A00000015100000000
   < 6F108408A000000151000000A5049F6501FF9000
   relay > 80CA9F7F00
   relay < 9F7F2A...9000
