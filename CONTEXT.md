# Cryptnox ID CLI

Management tooling for a smartcard family carrying three independent functions - PIV
identity credentials, FIDO2 passkeys, and MIFARE DESFire contactless applications.
The language below keeps the functions, their interfaces, and their administration
models from blurring into each other.

## Language

### The card

**Card function**:
One of the three independent capabilities on the card: PIV, FIDO2, or MIFARE DESFire.
Functions share the plastic but not state, keys, or admin channels.
_Avoid_: applet (DESFire is not a JavaCard applet), app, mode

**Contact interface**:
The wired ISO 7816 interface; the only interface where PIV administration works.
_Avoid_: chip mode

**Contactless interface**:
The ISO 14443 (PICC) interface; the only interface where DESFire answers.
_Avoid_: NFC mode (phone NFC follows different rules than PC/SC contactless)

### PIV structure and lifecycle

**Pre-personalization**:
The manufacturing-style step that creates the PIV applet's structure - containers,
key objects, verifiers - from a profile. It decides what _can_ exist on the card.
_Avoid_: provisioning (ambiguous), setup

**Personalization**:
Filling the pre-personalized structure with PIN/PUK values, keys, certificates, and
data objects. It decides what _does_ exist.
_Avoid_: provisioning, enrollment

**Personalization state**:
A ladder, never a boolean: pre-personalized, partially personalized, personalized,
secured (locked). Output state labels follow the ladder.
_Avoid_: initialized, blank, done

**Profile**:
A named pre-personalization configuration, such as `cryptnox-default` or `ms-logon`.
_Avoid_: template, preset

**Slot**:
A PIV key reference (9A authentication, 9C signature, 9D key management, 9E card
authentication) holding at most one private key.
_Avoid_: container (that holds bytes, not keys)

**Data object**:
A PIV container addressed by its object identifier: CHUID, CCC, certificates,
Discovery. A certificate and its slot's key are separate things.
_Avoid_: file, record (DESFire vocabulary)

**Discovery Object**:
The optional PIV data object carrying the PIN usage policy - the one PIV object
returned bare rather than wrapped. Absence is a normal, spec-legal state.
_Avoid_: discovery file

**Quickstart**:
The one-shot personalization chain from blank card to usable credential, which skips
completed steps and resumes after a failure.
_Avoid_: init, enroll

**Smoke test**:
A sign/verify round trip with an on-card key, proving the credential works.
_Avoid_: self-test (the FIDO2 credential self-test is a different operation)

### Keys and administration

**Admin channel**:
The SCP03 secure channel to the PIV applet, through which all PIV writes go. This
card has no Yubico-style management key.
_Avoid_: management key (another vendor's concept; nothing on this card answers to it)

**Default keys**:
The publicly documented GlobalPlatform test key value. It authenticates convenience,
not identity: a card still on default keys is administrable by anyone.
_Avoid_: factory secret, our keys

### Trust

**Genuineness**:
The card-level attestation function: a device key proves possession by signing a
challenge, and its certificate chain anchors to a pinned trust anchor. The verdict
is GENUINE only when both hold.
_Avoid_: attestation (alone - see Key attestation)

**Key attestation**:
The per-key PIV attestation: a factory-issued leaf certificate for one slot's key,
validated against a pinned trust anchor.
_Avoid_: genuineness, device cert

**Pinned trust anchor**:
A root CA shipped with the package. A chain is trusted only because it terminates at
a pinned root, never because a root arrived with the card; an uncovered chain is
unverifiable, never passing.
_Avoid_: CA bundle, system trust

### MIFARE DESFire

**Secure Dynamic Messaging (SDM)**:
The DESFire EV3 mechanism that embeds per-read authentication data (UID, counter,
MAC) into a file's NDEF content. EV3-only.
_Avoid_: SUN (the message SDM produces, not the mechanism)

### Tool behavior

**Dry run**:
The mode that writes nothing to the card: commands that can plan show their intended
actions, and commands that cannot plan refuse to run.
_Avoid_: simulation, preview (card responses are not simulated)
