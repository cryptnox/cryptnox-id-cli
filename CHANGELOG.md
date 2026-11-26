# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `remote consumer-lock`: the service replaces the card-manager key and key
  version 2 of the PIV security domain with random keys nobody keeps, and key
  version 1 and the management key 9B as `--ssd-key1` and `--mgmt-key` say.
  Delivered keys arrive encrypted to a key of the run and go to an encrypted
  key sheet (`--sheet-out`) or the terminal (`--show-once`); `remote key-sheet`
  reads a sheet back. Asks for `SEAL-CARD`; under `--dry-run` the service
  returns its plan and the relay admits no write.

### Changed

- The pre-personalization commands (`status`, `inspect-defaults`, `init-config`,
  `export-config`, `load-config`, `set-mgmt-key`, `finalize`) are under
  `piv perso`. `factory piv preperso` stops with the command's new name;
  `factory` keeps `card status` and `card fuse`.
- The `pin` and `puk` objects in JSON output gain `state` and `interface`;
  `configured`, `blocked` and `retries_remaining` are `null` where the card's
  answer leaves them unknown (see the JSON output reference).
- Profile validation requires a PIN and PUK `max` of 8, the length this tool
  sends.
- The result objects of `piv pin verify`, `pin change`, `pin unblock` and
  `puk change` add no `retries_remaining`, `blocked` or `recovery` for `63C0`;
  for `6983` they add `blocked` and `recovery` over contact, `hint` otherwise.
  Over contact, `pin change`, `pin unblock` and `puk change` no longer add the
  `hint` they gave for `6983`.

### Fixed

- `63C0` is shown as a PIN or PUK without a retry limit, not as blocked.
- `6983` over a contactless reader is shown as no tries left on that
  interface, not as blocked, by every command that reads the PIN or PUK; over
  contact it is shown as blocked, and the commands that present a PIN or PUK
  name the way to recover.
- `piv pin change`, `pin unblock` and `puk change` explain a PIN or PUK refused
  on this interface (`6982`, and `6A81` from `pin unblock`).
- The `quickstart` pre-flight PIN check names the cause when the card refuses
  the PIN.
- A PIN or PUK that is not 4 to 8 bytes long is refused with exit code 2
  before it is sent, instead of a traceback.
- `quickstart` no longer sets a PIN or PUK whose state the card's answer left
  unknown, and `piv validate` reports that check as unknown.
- `quickstart` no longer reports the smoke test as ok when no signature was
  made: it skips the step for a key known to lack the SIGN role, and a
  signature the card refuses with `6985` fails the run with exit code 6. When
  nothing is left to run, it says so and does not ask to proceed.

## [1.2.0] - 2026-11-23

### Added

- `mifare keys picc-to-aes`: replace a 2K3DES PICC master key with an AES-128
  key.
- `scripts/windows/eobo-wrap.ps1` and a Windows logon guide section on
  enrolling a card for another user through an enrollment agent.
- `factory card fuse`: the manufacturer's last step, which seals the card and
  replaces the card-manager key.
- `factory card status`: the card's lifecycle and the JCOP modules it lists.
- Remote operations report the INITIALIZE UPDATEs the service left without a
  completed authentication (`relay.open_initialize_updates`).
- `piv perso create-key-object`: add a key object for one slot and algorithm
  with a given role and access modes.
- `remote reset` and `remote dev-reset`: `--piv-variant fips|fipsoff` and
  `--fips-off` choose the PIV applet build the service installs; the build on
  the card afterwards is reported as `piv_build` and `piv_build_matches`.
- `remote inspect` reports the PIV applet build read from the card
  (`piv_build`, `piv_build_matches`).
- `remote ping`: the service's build, operations, applet builds and
  secure-channel policy, without a card.
- A refused or failed remote operation names the reason and what to do next;
  the JSON error object gains `reason`, `retry_in_seconds` and `ref`.
- `remote attest` checks the identifiers the service reports against the
  returned certificate (`certificate_serial_matches`,
  `certificate_sha256_matches`, `public_key_sha256_matches`).
- `remote attest` on a finalized applet asks before the key in the slot is
  overwritten, and prints the certificate when the card cannot store it.
- Remote operations show the admin channel the service used (`channel`) and,
  after `reset`, the applet's contactless-administration lock
  (`nfc_admin_lock`); `attest` shows whether the certified public key reached
  the service authenticated by the card.
- Profile YAML: `fips_mode: false` for the PIV applet build with FIPS mode off,
  with a PIN or PUK of at least 4 and up to 15 retries; `load-config` refuses
  such a profile on the FIPS-mode build. `inspect-defaults` lists both sets of
  bounds.
- Profile YAML: `contactless: ALWAYS` with `contactless_retries` under `pin`
  or `puk`.
- Built-in profile `ms-logon-nfc`: Windows logon with the card on an NFC
  reader, on the PIV applet build with FIPS mode off.

### Changed

- `piv pin verify`, `pin change`, `pin unblock`, `puk change`, `perso set-pin`,
  `set-puk`, `import-cert`, `write-object` and `write-standard-objects` exit
  with code 6 when the card refuses, with the same result object as before.
- `remote` commands exit with code 17 when a check under `verified_locally` is
  `false`; `null` is not a failure. `remote attest --out` is checked for a
  writable directory before anything is sent.
- The licence is stated as `LGPL-3.0-only OR LicenseRef-Commercial` in the
  package metadata and in an SPDX header in every source file.
- The package ships the text of the GNU GPL version 3 next to the LGPL and the
  commercial licence.
- Profile YAML: `VCI` and `VCI_PIN` mean the applet's VCI modes (`0x60`,
  `0x61`); `SM_PIN` (`0x41`) is new. `load-config` warns when a file uses `VCI`
  or `VCI_PIN`.
- `mifare sdm setup` and `sdm read` refuse a card whose DESFire is EV1 or EV2;
  `mifare version` names the generation.
- `mifare app delete` warns that only `mifare format` frees the deleted
  application's memory.
- `mifare format` and `--zero-key` work with a 2K3DES PICC master key as well
  as an AES one.
- `genuine`, `info` and `doctor` say why the genuineness applet was not found;
  `genuine` JSON gains `reason`.
- `piv pin unblock` help says it also works on a PIN that is not blocked.
- The APDU transcript withholds the DESFire authentication tokens and the
  card's AuthenticateISO challenge.
- `factory piv preperso inspect-defaults` reports the profile retry cap and the
  applet's retry limit separately; the JSON key `pin_fips` is now `pin_limits`.
- `piv inventory` labels the applet's FIPS flag "FIPS-mode build".
- `remote --default-keys` help and warnings match the current service.
- A `6985` to `generate-csr`, `self-sign-cert` or `smoke-test` names the key's
  role and a key on the slot that can sign.
- `generate-key`, `import-key` and `import-p12 --create-key-object` name the
  role they copy and ask before giving 9A or 9C a key that cannot sign.
- `load-config` and `quickstart --include-preperso` warn when the profile's 9A
  key cannot sign.
- `quickstart` refuses a certificate step the key cannot sign before writing
  anything, creates a missing key object with the profile's role, accepts
  `--algorithm RSA*` where the card has that key object, and does not
  overwrite a certificate it cannot account for.

### Removed

- `remote dev-reset` no longer asks for a development token.
- `remote attest --ca-obj`.

### Fixed

- `info`, `genuine info` and `genuine verify` print certificate names that
  contain square brackets as written, instead of failing or dropping part of
  them. So do `report` in human mode, which prints the report's JSON, and
  the `--out` path it names, `fido ping`, `fido info` and
  `fido credential list` for the strings the authenticator returns,
  `mifare sdm read` for the tag's NDEF text, `info`, `piv info` and
  `piv inventory` for the PIV applet's label, URL and version label, and
  `piv verify-attestation` and `piv export-attestation` for certificate
  names and the `--out` path, `piv perso import-key` for the `--public-out`
  path, and `piv perso import-p12` for the certificate's subject.
- Text the service supplies is stripped of control sequences and escaped
  before display, in results and in the error line.
- A command the card answers with a corrected length (`6Cxx`) is resent with
  its data intact.
- A value that is not valid hex, or a `--slot` that is not a key reference,
  ends with exit code 2 instead of a traceback.
- A DESFire answer shorter than expected ends in an error instead of a
  traceback.
- `piv perso generate-csr` and `self-sign-cert` accept a DER public key as
  well as PEM.
- `piv quickstart --csr-out` on a slot whose certificate it keeps stops before
  writing anything; `--public-out` then writes the kept certificate's public
  key.
- `info` reads the card serial correctly when the CPLC answer uses a long-form
  length.
- `piv objects read --out` writes a file only the owner can read.
- `piv certs list` and `piv certs inspect` print a subject or issuer that
  contains square brackets as written.
- `mifare app delete` fails with an error when the card still finds the
  application afterwards.
- On Windows, a `fido` command re-run through the UAC prompt reports the
  elevated run's error message.
- `piv pin change`, `piv pin unblock` and `piv puk change` name both causes of
  `6983`, a blocked verifier or its contactless limit; `63C0` still reports
  the block.
- A PIN refused with `6983` while signing or reading a PIN-protected object is
  reported as blocked or at its contactless limit.
- An all-zero key is no longer masked as a secret in output and transcripts.
- `piv certs list` marks a certificate it cannot parse as unreadable and
  prints the parse error.
- `mifare keys change` without `--auth-key-no` authenticates with the new key
  after the change and fails with `ev2_error` when it does not.
- `mifare read --full` on a file that is not in FULL mode, and `mifare value
  get` on one that is, fail with an error instead of printing wrong data.
- In `shell`, Ctrl-C during a command and a declined confirmation return to
  the prompt.
- `mifare read --full`, `mifare write --full`, `mifare sdm setup` and
  `mifare keys change --auth-key-no` fail with `ev2_error` when the card
  answers OK without a response MAC.
- `piv perso generate-key` warns that it destroys the slot's key only when the
  slot's certificate is for a key of the same algorithm.
- A signature refused because the key object holds no key yet (`6983`) says
  so.
- Creating a key object on a finalized applet says the applet is finalized.
- On a contactless reader, `piv status`, `piv pin status`, `piv validate` and
  the commands that present the PIN say the PIN is not usable over this
  interface; JSON gains `refused_on_interface`.
- `piv perso generate-key` refuses a slot that cannot hold an asymmetric key,
  such as 9B or 04, with exit code 2 before it opens the card. With
  `--create-key-object` it used to add a permanent key object there.
- `--dry-run piv objects read` refuses a PIN-protected object instead of
  verifying the PIN; public objects still read.
- `piv quickstart` stops before any write when it cannot read the card's
  CHUID or CCC, instead of planning to write over it. `piv status`, `report`
  and `factory piv preperso export-config` show such an object as unknown
  (`null` in JSON) rather than absent.

## [1.1.0] - 2026-10-16

### Added

- `piv perso import-cert --csr FILE` refuses a certificate whose public key
  is not the CSR's; `--verify-pin` has the slot sign a challenge and refuses
  unless the certificate's key verifies it.
- `piv inventory`: the applet's key objects, verifiers, containers and config
  flags with their access rules, read without authentication.
- The finalized (SECURED) state, read from the applet's status object, in
  `piv status`, `info`, `report` and `factory piv preperso status`.
- `piv admin keys`: the admin security domain's key table; `--check-default`
  authenticates once to key version 1 with the GlobalPlatform default key.
- `piv admin rotate-keys`: replace key version 1 of the PIV security domain in
  place; new keys from `PIV_SCP03_NEW_ENC` / `_MAC` / `_DEK`, key version 2
  never addressed, key check values and a fresh authentication verified after.
- `piv admin delete-factory-keyset`: delete key version 2 after a typed
  confirmation; refuses while key version 1 is still the test key.
- `RSA4096` in `perso generate-key`, `perso import-key`, CSR and
  self-signed-cert signing, and profile key mechanisms.
- `perso generate-key --create-key-object`, the dev/eval fallback
  `import-key` already had.
- `remote authenticate` and `remote inspect`: identify and probe the card
  through the Cryptnox remote PIV service, with the card in the local reader.
  The tool relays the commands the service sends under a fail-closed policy
  that keeps every other card function out of reach, and reports what the
  service asserted apart from what it verified locally. Relayed commands
  carry a `relay` prefix in `--apdu-log` and `--verbose` output. Adds the
  `websockets` dependency and exit codes 12 to 16.
- `remote reset` and `remote dev-reset`: wipe and reinstall the PIV function
  through the service, behind the same irreversibility gate as `factory piv
  preperso finalize` (typed phrase or explicit flag, `--yes` not accepted),
  with the card's PIV state, data objects, security-domain key versions and
  neighbouring functions read locally before consent and again afterwards.
  The relay policy for these operations admits card content management
  through the card manager only, restricts a DELETE to the PIV instance,
  package and security domain (refusing one it cannot read unless the
  channel encrypts commands), and stops at the first failed authentication.
- `remote attest`: generate a key in a slot through the service and receive
  its key-attestation certificate. The certificate is verified locally against
  the pinned anchors and bound to the card's CPLC UID, the requested slot, the
  trust model and the certificate read back from the card before success is
  reported.
- Coverage measurement in CI (`pytest-cov` in the `dev` extra) with a
  project-wide floor and a tighter one over the command modules, both on
  combined statement-and-branch coverage.
- `factory piv preperso set-mgmt-key`: load the PIV management key (9B)
  over the admin channel; `--replace` overwrites a set value.
  `factory piv preperso status` reports whether 9B holds a value.
- `PIV_MGMT_KEY` (hex) for the PIV management key, next to `PIV_SCP03_*`.

### Changed

- `piv quickstart` defaults to RSA-2048 on `--profile ms-logon --slot 9A`,
  the Windows shape, instead of warning that its ECC default will not work
  there.
- `piv quickstart` plans from the applet's key-object listing. A structure
  that lacks the requested (slot, mechanism) object gets that object created
  under `--include-preperso` instead of a second `load-config`, which the
  applet refuses with `6E27`.
- `piv admin status` and `factory piv preperso status` read the admin security
  domain's SCP version and key versions from its key information template
  instead of sending INITIALIZE UPDATE, which this chip counts as a failed
  authentication. `piv admin status --key-version` is gone.
- A finalized applet's key-object error and a failed `load-config` name
  `remote reset` for a full PIV reset.
- `--create-key-object` says that the key object it creates is permanent,
  also when the chip then refuses the key size.

### Removed

- `transport.pcsc.list_reader_names()`; `reader_states()` returns the same
  names with card presence and ATR.

### Fixed

- The PyInstaller spec collected the trust anchors from a package name that no
  longer exists, so a frozen build shipped without them and could verify no
  attestation or genuineness chain. The spec is `packaging/cryptnox-id.spec`
  now, named after the tool, and a test checks that every name in it resolves.
- `factory piv preperso status` reported the SCP version of whatever applet was
  selected last, not the PIV security domain's.
- The Windows logon guide's quickstart example lacked `--algorithm RSA2048`
  and generated an ECC key Windows cannot use.
- `cryptography>=43` is now required: the SCP02 code imports its `decrepit`
  3DES module, which older releases do not have, so an install on a system
  with cryptography 41 failed at start-up.
- `factory piv preperso load-config` warns that structural operations are
  permanent (existing elements cannot be changed or removed; only new ones can
  be added) instead of calling them reversible before finalize.
- Error messages and docs no longer suggest reinstalling the applet as a
  recovery step. The `load-config` failure message points at adding missing
  key objects with `--create-key-object`.
- `PivPersonalized` no longer requires the optional Discovery Object; CHUID,
  CCC and a set PIN suffice. Discovery is still probed and listed.
- `factory piv preperso status` reports `finalize_allowed` under the rule
  `finalize` applies (applet selectable, not SECURED) and adds
  `load_config_allowed` for a blank applet.
- The APDU transcript withholds the whole body of a secret-bearing command
  whose `Lc` disagrees with the bytes present, instead of rendering an
  unmasked data field. Other commands still render in full.
- `doctor` uses the reader name as well as the ATR for the DESFire
  diagnosis, so it no longer recommends a contactless reader to someone
  already on one.
- `perso generate-key` and `quickstart` handle an RSA public-key template
  truncated at 256 bytes over the admin channel by repeating the generation
  over plain APDUs after 9B authentication.
- An unparseable public-key template ends in a CLI error naming the response
  length, not an unhandled exception.
- A `PIV_SCP03_*` value that is not valid hex ends in a CLI error naming the
  variable, not an unhandled exception that printed the value.

## [1.0.3] - 2026-08-31

### Changed

- Package metadata: marked Production/Stable and declared the dual license
  (LGPL-3.0-or-later or commercial) as an SPDX expression.

## [1.0.2] - 2026-08-31

### Added

- CI workflow that publishes tagged releases to PyPI.

## [1.0.1] - 2026-08-28

### Fixed

- Install instructions lead with pipx: global `cryptnox-id` command, and works
  where PEP 668 blocks system-Python installs. venv stays for development.

## [1.0.0] - 2026-08-28

### Added

- **PIV (SP 800-73)** — read-only inspection (`info`, `status`, `slots`,
  `discover`, `validate`), PIN/PUK lifecycle (`pin verify`/`change`/`unblock`,
  `puk change`), certificate and data-object access, and the `piv perso`
  personalization set: on-card key generation, external key and PKCS#12 import,
  CSR and self-signed certificates signed on-card, CHUID/CCC objects, and a
  post-personalization smoke test.
- `piv quickstart` — one-shot personalization chaining pre-personalization
  through PIN/PUK, key, certificate, CHUID/CCC and a smoke test over a single
  card connection, skipping whatever is already done.
- **Factory pre-personalization** (`factory piv preperso`) — profile-driven
  applet structure over SCP03, with built-in profiles (`cryptnox-default`,
  `ms-logon`, `ssh`, `developer`, `npivp-lab`), YAML import/export, a dry-run
  mode, and the irreversible `finalize` behind a typed confirmation.
- **FIDO2 / CTAP 2.1** — `ping`, `info`, PIN status/set/change, credential
  create/assert/self-test/list/delete, `authenticatorConfig` policy (`alwaysUv`,
  minimum PIN length), and a gated `reset`. On Windows, a non-elevated `fido`
  command offers to relaunch itself through a UAC prompt and shows the elevated
  result in the original window.
- **MIFARE DESFire EV2/EV3** — application and file management, AES key
  operations, MACed reads and writes, value and record files, and EV3 Secure
  Dynamic Messaging (`sdm setup` / `sdm read`) per NXP AN12196.
- **Genuineness / attestation** — read-only device-key proof of possession and
  certificate-chain verification, plus PIV key-attestation export and
  validation. The Cryptnox production root ships pinned in the package, with the
  intermediates bundled so chains build offline; `$CRYPTNOX_TRUST_DIR` and
  `--anchors` add anchors without a rebuild. A chain no pinned root covers is
  reported as unverifiable, never as passing.
- `cryptnox-id shell` — an interactive prompt that runs subcommands without the
  `cryptnox-id` prefix, suitable for launching from a desktop shortcut.
- Cross-cutting: `readers`/`info`/`doctor` diagnostics, secret-safe JSON reports
  (`report …`), machine-readable `--json` output on every command, a redacted
  APDU log (`--apdu-log`), and raw APDU access for developers. With no
  `--reader`, the tool auto-selects the single Cryptnox/ACS reader holding a
  card and refuses to guess otherwise.
- Three interchangeable console commands: `cryptnox-id`, the short `cnx-id`,
  and `cryptnox-id-card`.

[Unreleased]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/cryptnox/cryptnox-id-cli/releases/tag/v1.0.0
