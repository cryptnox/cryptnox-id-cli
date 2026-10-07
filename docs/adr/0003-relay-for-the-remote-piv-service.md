# 3. A policed relay for the remote PIV service

## Context

Some PIV lifecycle operations need keys that never leave Cryptnox: the key that
makes a card genuine, and the certificate authority that attests keys generated
on it. Cryptnox operates a service that performs those operations with the card
in the holder's own reader. The service chooses every card command; the tool's
part is to carry commands to the card and answers back over a TLS WebSocket.

The card carries more than the PIV function. A wallet, FIDO2 passkeys, a
genuineness key and DESFire share the plastic, and each has retry counters or
content that a stray command can destroy. A card-management authentication that
fails spends one of a bounded number of retries, after which the card manager
locks for good. The service is one party; anything that can speak its protocol
to the tool is another.

The tool had no network code, and every command it sent to a card was one it had
composed itself.

## Options

1. **Present the service as a card connection**, so the existing PIV code runs
   over the wire. Backwards: the card is local and the service drives, so the
   tool would be relaying the service's commands whatever the seam is called,
   and the CLI's transport reassembles chained responses the service expects to
   drive itself.
2. **A transparent relay**: carry every command the service sends. Simplest, and
   it hands the other card functions to whoever holds the connection.
3. **A relay behind a fail-closed policy**, per operation, over what a command
   header reveals.

## Decision

Option 3.

The relay transmits each command the service sends through the raw card
connection and returns the answer verbatim, status word included. It never sends
a command of its own and never reassembles a chained response; the service sees
the card as a local reader would.

Before a command reaches the card, a policy decides. The policy is an allow-list
per operation: which applet may be selected (the PIV applet and its security
domain; the card manager only where card content management is the point),
which instructions may pass in each of those contexts, how many INITIALIZE
UPDATE and EXTERNAL AUTHENTICATE commands each security domain may see, how many
commands and seconds an operation may take. A DELETE whose data travels in the
clear may name the PIV instance, its package or its security domain and nothing
else. Key generation is bound to the slot the holder asked for, and the
management-key handshake to key 9B, so no slot key can be exercised. Card-holder
verifier commands are never relayed. A refusal ends the operation and names the
command header, so the rules can be reviewed against what the service actually
needs rather than loosened in advance.

Inside an encrypted channel only the class and instruction bytes stay in the
clear. The policy fences which security domain the channel was opened to and
which instructions pass through it; it cannot see what an encrypted command
carries, and the documentation says so.

The service's result is shown as the service's assertion. What the tool can
verify itself, it reads from the card before and after: identity, personalization
state, security-domain key versions, the neighbouring functions, and for key
attestation the returned certificate bound to the card, the slot and the
certificate stored on it. An unchecked binding never counts as a passed one.

Irreversible operations sit behind the gate the codebase already uses for
`finalize` and `fido reset`: a typed phrase interactively, an explicit flag
otherwise, and no `--yes` bypass. The development access credential comes from
the environment, never from an option. The production endpoint is a constant;
an override reaches the read-only operations only.

## Consequences

* `websockets` is the tool's first network dependency. The synchronous client
  keeps every command synchronous, as the rest of the tool is.
* A service change that needs a command the policy does not admit fails loudly
  with the header, and needs a tool release to admit it. That is the intended
  trade: the policy is written from what the service was observed to send, not
  from what it might.
* Relayed commands are written to the transcript with their data masked unless
  the instruction is a known read, the reverse of the tool's own transcript rule,
  because the tool did not compose the command. `remote --full-transcript`
  lifts that masking for troubleshooting.
* The tool cannot witness that a key was generated on the card. The output says
  so next to every key attestation.
* The glossary gains the remote service, the relay and the relay policy.
