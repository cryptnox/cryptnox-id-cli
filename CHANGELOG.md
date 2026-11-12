# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `mifare keys picc-to-aes`: replace a 2K3DES PICC master key (the factory
  default) with an AES-128 key, confirmed by authenticating with the new key.
- `scripts/windows/eobo-wrap.ps1` and a Windows logon guide section on
  enrolling a card for another user through an enrollment agent.
- `factory card fuse`: the manufacturer's last step. Deletes the JCOP sample
  modules and then the configuration module, sets the card's lifecycle to
  SECURED and replaces the card-manager key, from `CARD_MANAGER_NEW_*` or
  `--randomize --out FILE`. It prints the card's state and a warning, then
  asks for `FUSE-CARD`; `-y` skips the question.
- `factory card status`: the card's lifecycle and which JCOP modules the card
  lists, read over the card-manager channel. A card can leave them out of the
  listing, so the sealed state is unknown unless the configuration module is
  listed.
- Remote operations warn when the service leaves INITIALIZE UPDATEs without a
  completed authentication, with a count per security domain, also after a
  failed operation. The JSON `relay` object lists them as
  `open_initialize_updates`.
- `piv perso create-key-object`: add a key object for one slot and algorithm
  with the role and access modes given, for example a signing 9A on a card
  whose 9A key cannot sign. Asks for confirmation; `--dry-run` sends nothing.
  Refuses a finalized applet, and SIGN together with KEY_ESTABLISH, which the
  applet refuses.

### Changed

- The package ships the text of the GNU GPL version 3, which the LGPL
  incorporates, next to the LGPL and the commercial licence.
- Profile YAML: `VCI` and `VCI_PIN` now mean the applet's VCI modes (`0x60`,
  `0x61`), and `SM_PIN` (`0x41`) is new. The built-in profiles write the same
  bytes as before, now named `SM` and `SM_PIN`. Files written by 1.1
  (`init-config`, the docs example) use `VCI_PIN` for `0x41` and must say
  `SM_PIN` instead; `load-config` warns when a file uses `VCI` or `VCI_PIN`.
- `mifare sdm setup` and `sdm read` refuse a card whose DESFire is EV1 or EV2,
  and `mifare version` names the generation.
- `mifare app delete` warns that the card does not return the deleted
  application's memory; only `mifare format` frees it.
- `mifare format` works with a 2K3DES PICC master key as well as an AES one
  (factory cards ship with 2K3DES); `--zero-key` covers both factory defaults.
- `genuine` says why the applet was not found: a contactless interface, or a
  card without it (production cards with FIDO2), pointing at FIDO2
  attestation; JSON gains `reason`. `info` and `doctor` say the same.
- `piv pin unblock` help says it also works on a PIN that is not blocked.
- The APDU transcript withholds the DESFire authentication tokens and the card's
  AuthenticateISO challenge.
- `factory piv preperso inspect-defaults` reports the profile retry cap (10)
  and the applet's retry limit (15) separately; the JSON key `pin_fips` is
  now `pin_limits`.
- `piv inventory` labels the applet's FIPS flag "FIPS-mode build".
- `remote --default-keys` help and warnings updated for the current service.
- A `6985` to `generate-csr`, `self-sign-cert` or `smoke-test` names the key's
  role and points at a key on the slot that can sign, or at how to add one,
  instead of suggesting a wrong lifecycle state.
- `generate-key`, `import-key` and `import-p12 --create-key-object` name the
  role they copy, and ask first when it gives 9A or 9C a key that cannot sign.
- `load-config` and `quickstart --include-preperso` warn when the profile's 9A
  key cannot sign.
- `quickstart` refuses, before writing anything, a certificate step that would
  fail because the key cannot sign (on cards that list their key objects);
  creates a missing key object with the profile's role; accepts
  `--algorithm RSA*` where the card already has that key object; and counts a
  slot's certificate only for the key it was issued to, refusing to overwrite
  one it cannot account for.

### Removed

- `remote dev-reset` no longer asks for a development token.

### Fixed

- `mifare read --full`, `mifare write --full`, `mifare sdm setup` and
  `mifare keys change` with `--auth-key-no` fail with `ev2_error` (exit 11)
  when the card answers OK without a response MAC, instead of reporting
  success with nothing verified.
- `piv perso generate-key` warns that it destroys the slot's key only when the
  slot's certificate is for a key of the same algorithm.
- A signature refused because the key object holds no key yet (`6983`) says
  so, instead of suggesting a blocked PIN.
- Creating a key object on a finalized applet (`--create-key-object`,
  `create-key-object`) says the applet is finalized; the applet answers `6986`
  there, which was reported as a bare status word.
- On a contactless reader, `piv status`, `piv pin status`, `piv validate`
  and the commands that present the PIN say the PIN is not usable over this
  interface (the card answers 6982) instead of "not set" or the generic
  security-status text; `quickstart` stops there instead of planning
  `set-pin`; JSON gains `refused_on_interface`. Docs: the PIN, the PUK, the
  PIN-protected keys and the management key (9B) are contact-only; the admin
  channel works over both interfaces.

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

[Unreleased]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/cryptnox/cryptnox-id-cli/releases/tag/v1.0.0
