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
   key versions they carry. Key-free: an authentication attempt from the
   service is refused before it reaches the card.

``attest``
   Generates a key in one slot and returns a key-attestation certificate for
   it, signed by the Cryptnox key-attestation CA and stored in the card's
   attestation container as well. The relay policy admits the applet's admin
   channel for the key-object setup, the management-key handshake (never a
   slot key), key generation for the requested slot only, and the certificate
   write. The tool then verifies the certificate against the pinned anchors and
   binds it to the card, the slot and the certificate stored on the card. The
   generation itself happening on the card is the service's claim; nothing the
   relay sees authenticates it.

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
   package and its security domain where the command travels in the clear,
   caps authentication attempts per security domain, and stops at the first
   failed authentication so no further attempt can spend a card-management
   retry. Inside an encrypted channel the policy sees instructions, not
   targets; that limit is real and is why the FIDO2 and genuineness state is
   read before and after.

``dev-reset``
   As ``reset``, for development cards, leaving the card manager and the PIV
   security domain on the publicly documented GlobalPlatform key so the PIV
   function can be pre-personalized and personalized locally. Anyone with a
   reader can then install or delete applets on the card, and the card is not
   genuine until it is reset through the service again. The development access
   credential comes from ``CRYPTNOX_REMOTE_DEV_TOKEN`` only.

The ``--fused`` flag
--------------------

A fused production card has its card manager locked to a per-card key. The
service derives that key when ``--fused`` is passed and uses the shared
default otherwise. The tool cannot tell the two apart without a key, so the
flag is the holder's statement. A wrong statement makes the service present
the wrong key; the failed authentication costs one of the card's bounded
card-management retries, and the relay stops there.

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
