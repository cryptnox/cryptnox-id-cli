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

``ping``
   Asks the service about itself: its build, the operations it serves, the PIV
   applet builds it can install and its secure-channel policy. No card is
   involved; the service answers before any proof-of-work or card exchange.

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

The admin channel the service opens
-----------------------------------

For ``attest``, ``reset`` and ``dev-reset`` the service opens the PIV
applet's admin channel with the card's own key. On an SCP03 card it asks for
security level ``0x33``: commands and answers are both authenticated and
encrypted, so nothing between the service and the card, |cli| included, can
alter what the card says. That is the hardened channel. SCP02 cards have no
answer protection, so on them the service drives the card at the legacy level
``0x03``, where only the commands are protected. Every result names the
channel used (``channel``: protocol, level, ``hardened`` or ``legacy``) and
|cli| shows it. A legacy channel on an SCP03 card is warned about, and the
service's log says why. A result without the field comes from a service
without the hardened channel; |cli| shows the channel as not reported and
treats it as legacy. The relay policy stops at the first failed
authentication, so an SCP03 security domain that refused the hardened level
ends the operation rather than being driven at the legacy level.

Three rules follow from the channel:

* The relay stays a plain relay. On the hardened channel the card signs each
  answer together with its status word, so a client that reassembled chained
  answers or rewrote status words would break the channel. The service then
  reports ``R-MAC mismatch``, and |cli| says to check the relay path rather
  than retry.
* Administration is contact-only. Through the channel the applet reports
  which interface it is being driven over, and the service refuses ``attest``
  over contactless. ``reset`` and ``dev-reset`` work through the card manager,
  which the applet does not govern; there the card's own configuration keeps
  administration on the contact interface. After a ``reset`` the service also
  sets the applet's own lock, so the applet refuses its admin channel over
  contactless by itself (``nfc_admin_lock`` in the result); ordinary PIV use
  over contactless is unaffected. |cli| warns before connecting when the
  selected reader looks contactless; the service's decision rests on the
  card's report, not on the reader's name.
* A card whose channel cannot authenticate its answers (SCP02, or an SCP03
  card driven at the legacy level) gets no key attestation, and the other
  operations only with a Cryptnox access token, which |cli| has no option
  for. The service refuses with ``legacy_channel`` set and |cli| says so.
  ``authenticate`` and ``inspect`` open no channel and need no token.

For ``attest``, ``public_key_authenticated`` says whether the public key the
service certified reached it through the hardened channel. When it did not,
or the service does not say, |cli| warns that something between the service
and the card could have substituted the key: the certificate is still bound
to the card, the slot and the certificate stored on the card, but the key's
origin rests on the service's claim alone.

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

When an operation leaves INITIALIZE UPDATEs without a completed
authentication, |cli| says so afterwards with a count per security domain,
also when the operation failed. With ``--json`` the counts are in
``relay.open_initialize_updates``.

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

The PIV applet build
--------------------

``reset`` and ``dev-reset`` reinstall the PIV applet, and the service holds two
builds of it, made from the same source with one switch apart:

* the **FIPS-mode build**, the default and the build cards ship with;
* the **build with FIPS mode off**, asked for with ``--fips-off`` or
  ``--piv-variant fipsoff``.

With FIPS mode off the applet lifts three limits it enforces when a
pre-personalization profile is loaded: the PIN may be as short as 4 digits
instead of 6, the retry counter may exceed 15 (|cli| still caps a profile at
15, the most the card reports back), and the PIN may be made usable
over the contactless interface without secure messaging. It also skips the
FIPS power-up self-tests and does not zeroise an object before discarding it.
Slots, algorithms, key generation, key import, certificates and the admin
channel behave the same in both builds; a card personalized with a profile
that asks for none of the three behaves the same whichever build it carries.

A profile asks for them with ``fips_mode: false``
(:doc:`/factory/pre-personalization-profiles`). The built-in ``ms-logon-nfc``
profile, for Windows logon with the card on an NFC reader, is the one that
does (:doc:`/piv/windows-logon-and-remote-desktop`).

The two builds share the applet and package identifiers, so nothing outside
the applet tells them apart. The applet reports its build in its status, read
without authentication: ``piv inventory`` shows it as "FIPS-mode build", and
``remote inspect``, ``remote reset`` and ``remote dev-reset`` read it and
report it. After a reset the build read from the card is compared with the
one asked for, so a service that installed something else is noticed.

A ``reset`` without the option installs the FIPS-mode build again. Whether the
service offers the build with FIPS mode off is its own setting; ``remote ping``
lists the builds it offers, and |cli| asks before a reset that needs it.

The limit of operations per card
--------------------------------

The service accepts a fixed number of operations per card in a period, five an
hour at the time of writing, and every operation that reaches a card counts,
``inspect`` and ``authenticate`` included. ``ping`` does not: it involves no
card. When the limit is reached the service refuses before anything is sent to
the card and says when it accepts the next operation; |cli| reports that
waiting time, and ``retry_in_seconds`` with ``--json``. The counter is kept by
the service, per card, and survives a restart of the service.

What is sent to the service
---------------------------

The card's ATR and CPLC serial identify the card to the service. They are the
same values any reader can obtain from the card without a key. Nothing else
about the card holder is sent. An operation sends its own parameters with
them: the slot and algorithm for ``attest``, the applet build and the key tier
for ``reset`` and ``dev-reset``. ``ping`` sends nothing about a card.

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
