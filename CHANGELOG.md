# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `RSA4096` in `perso generate-key`, `perso import-key`, CSR and
  self-signed-cert signing, and profile key mechanisms.
- `perso generate-key --create-key-object`, the dev/eval fallback
  `import-key` already had.
- Coverage measurement in CI (`pytest-cov` in the `dev` extra) with a
  project-wide floor and a tighter one over the command modules, both on
  combined statement-and-branch coverage.
- `factory piv preperso set-mgmt-key`: load the PIV management key (9B)
  over the admin channel; `--replace` overwrites a set value.
  `factory piv preperso status` reports whether 9B holds a value.
- `PIV_MGMT_KEY` (hex) for the PIV management key, next to `PIV_SCP03_*`.

### Removed

- `transport.pcsc.list_reader_names()`; `reader_states()` returns the same
  names with card presence and ATR.

### Fixed

- `factory piv preperso load-config` warns that structural operations are
  permanent (existing elements cannot be changed or removed; only new ones can
  be added) instead of calling them reversible before finalize.
- Error messages and docs no longer suggest reinstalling the applet as a
  recovery step; a full reset of the PIV applet is a Cryptnox operation. The
  `load-config` failure message points at adding missing key objects with
  `--create-key-object`.
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

[Unreleased]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/cryptnox/cryptnox-id-cli/releases/tag/v1.0.0
