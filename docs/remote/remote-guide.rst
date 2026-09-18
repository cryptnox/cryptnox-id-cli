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
