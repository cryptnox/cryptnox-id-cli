# 2. Management-key fallback for on-card key generation

## Context

On-card key generation returns the new public key as a `7F49` template in the
GENERATE response. An RSA template is larger than one 256-byte response: 270 bytes
for RSA-2048, and more for RSA-3072 and RSA-4096. A card that chains splits it
across a first response and GET RESPONSE frames, and the CLI's transport reassembles
it — that is the path every command already takes.

Some cards do not chain on the secured response path. They deliver the first 256
bytes, end with a plain success status, and drop the remainder. The response looks
complete to the host, so the CLI parsed a partial template and failed with a raw TLV
error. ECC is unaffected: its templates are 70 and 102 bytes.

The applet is a certified build. Changing it is not on the table for this problem.

## Options

1. **Change the applet's response layer** so the secured path chains like the plain
   one. Correct at the source, and unavailable: it forks a certified build.
2. **Always generate over plain APDUs**, behind a management-key authentication.
   One code path, but it makes a working card depend on a key value that cards in the
   field do not carry, and it moves an operation off the admin channel for every card
   to fix a problem only some cards have.
3. **Ask for a response-MAC session**, whose framing does chain. Secure-channel-version
   specific, and unavailable on one of the two channel versions this CLI speaks.
4. **Detect the truncation and fall back** to the plain path only then.

## Decision

Option 4.

The detector reads the card's own response: an RSA mechanism, a success status,
exactly the requested length, and a `7F49` header declaring a larger object than
arrived. It consults no card identity, version or build, and it cannot fire for ECC
or for a card that returns the full template — those take the admin channel with the
same APDUs as before.

When it fires, the CLI authenticates the PIV management key (key reference 9B)
mutually over plain APDUs and repeats the GENERATE as a plain APDU; the applet's
plaintext response path chains, and the existing transport loop reassembles the
template. Authentication is mutual rather than external, so the card proves it holds
the key too. The management key's value is never injected automatically: a card whose
9B holds no value is reported with the one command that loads one
(`factory piv preperso set-mgmt-key`). Writing a card's administration key is an
explicit act, not a side effect of generating a key.

Only the GENERATE read-back moves off the admin channel. Object creation, key import,
certificate writes, PIN and PUK operations and data objects are untouched, as is the
transport.

## Consequences

* On a card that needs the fallback, a key pair is generated twice: the applet
  generates before it builds the response, so the truncated first attempt already
  replaced the slot's key. The key that survives is the one from the plain path,
  and its public half is the one reported. The CLI says so before it retries. An
  interruption between the two attempts leaves a private key whose public half
  nobody knows; re-running the command resolves it.
* The fallback needs 9B to hold a value, and 9B is contact-only.
* "Management key" now names something real on this card, which the glossary
  previously told readers to avoid. `CONTEXT.md` carries the new term and the
  amended "Admin channel" entry.
* Management-key authentication grants a role that the applet keeps until the card
  is deselected or loses power. The CLI does not spend an extra command trying to
  drop it early.
