<p align="center">
  <img src="https://github.com/user-attachments/assets/6ce54a27-8fb6-48e6-9d1f-da144f43425a"/>
</p>

<h3 align="center">cryptnox-id-cli</h3>
<p align="center">CLI for managing Cryptnox multi-applet ID smart cards</p>

<br/>
<br/>

[![PyPI](https://img.shields.io/pypi/v/cryptnox-id-cli.svg)](https://pypi.org/project/cryptnox-id-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/cryptnox-id-cli.svg)](https://pypi.org/project/cryptnox-id-cli/)
[![docs](https://github.com/cryptnox/cryptnox-id-cli/actions/workflows/docs.yml/badge.svg)](https://github.com/cryptnox/cryptnox-id-cli/actions/workflows/docs.yml)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

`cryptnox-id-cli` is a command-line interface for managing the **Cryptnox ID**
multi-applet smart card: **PIV** identity credentials, **FIDO2** passkeys, and
**MIFARE DESFire** contactless applications — three independent functions on
one physical card, driven by one tool.

---

## Supported hardware

### Cryptnox ID smart cards

One card, four applets, reachable over two interfaces:

| Function | Interface | Notes |
|----------|-----------|-------|
| **PIV** (SP 800-73 keys + X.509 certificates) | Contact (admin), contact/contactless (use) | All personalization is contact-only |
| **FIDO2 / CTAP 2.1** (passkeys / WebAuthn) | Contactless (NFC) | Windows requires an Administrator terminal |
| **MIFARE DESFire** (incl. EV3 Secure Dynamic Messaging) | Contactless (NFC) | Needs a DESFire-capable reader |
| **Genuineness** (factory attestation) | Contact | Read-only; proves the card is genuine Cryptnox hardware |

### Smart card readers

Works with Cryptnox readers and any other standard PC/SC smart card reader:

| Reader | Type | Interface |
|--------|------|-----------|
| [Cryptnox® Smartcard Reader](https://shop.cryptnox.com/product/cryptnox-smartcard-reader/) | Contact (ID-1 + SIM) | USB-A |
| [Compact USB Mini Smartcard Reader](https://shop.cryptnox.com/product/mini-smartcard-reader/) | Contact (ID-1) | USB-A |
| [Cryptnox NFC Contactless Reader](https://shop.cryptnox.com/product/cryptnox-contactless-reader/) | Contactless (NFC/ISO 14443) | USB-C |

Verified third-party readers: ACS ACR39U (contact), ACS ACR1252 (contactless,
native DESFire OK). The HID OMNIKEY 5422CL does **not** support DESFire.

> [!IMPORTANT]
> MIFARE DESFire requires a contactless reader that passes *native* DESFire
> commands — not all contactless readers do.

---

## Installation

> [!IMPORTANT]
> This is only a minimal setup. Additional packages may be required depending
> on your operating system. See
> [Installation](https://docs.cryptnox.com/cryptnox-id-cli/installation.html)
> in the documentation.

Requirements: Python 3.10+ and a PC/SC stack (built into Windows and macOS; on
Linux install `pcscd` + `libccid`).

### From PyPI

Recommended: [pipx](https://pipx.pypa.io/) — makes `cryptnox-id` available
globally while keeping its dependencies isolated, and works on current Linux
distributions where installing into the system Python is blocked (PEP 668):

```bash
pipx install cryptnox-id-cli
```

Plain pip also works where the environment allows it (e.g. Windows):

```bash
pip install cryptnox-id-cli
```

A virtual environment works too, but the command is then only available while
the venv is activated — fine for development, not for day-to-day use.

Three interchangeable console commands are installed: `cryptnox-id`, the short
`cnx-id`, and `cryptnox-id-card`.

### From source

```bash
git clone https://github.com/cryptnox/cryptnox-id-cli.git
cd cryptnox-id-cli
pip install .
```

---

## Quick usage examples

> [!TIP]
> The examples below are only a subset of available commands. The complete list
> of commands and detailed usage instructions is described in the
> [official documentation](https://docs.cryptnox.com/cryptnox-id-cli/).

### 1. Inspect the card

```bash
cryptnox-id readers     # list readers, card presence, ATR
cryptnox-id info        # detect the card + all functions on one screen
cryptnox-id doctor      # PC/SC service, reader, per-function reachability
```

`info` and `doctor` are read-only and safe to run any time.

### 2. Provision a PIV credential

1. Run `cryptnox-id piv quickstart` on a contact reader.
2. The card gets a key, a certificate, a CHUID and a CCC — usable by standard
   PIV tooling (`yubico-piv-tool`, OpenSC, OS smart-card stacks).

### 3. Create a passkey and prove the whole loop

1. Run `cryptnox-id fido credential self-test` — registers a credential,
   requests an assertion, and verifies the returned signature: the full
   WebAuthn round trip against the real authenticator.
2. For a resident, PIN-verified credential: `cryptnox-id fido pin set`, then
   re-run the self-test with `--rk`. On Windows, run from an Administrator
   terminal.

### 4. Prove the card is genuine

1. Run `cryptnox-id genuine verify` on a contact reader.
2. The card signs a fresh nonce and the on-card certificate is chained to the
   pinned Cryptnox root — the verdict is **GENUINE** only when both checks pass.

### 5. Work interactively

```bash
cryptnox-id shell       # run subcommands without re-typing the prefix
```

---

## Documentation

The full **User & Developer documentation** is available at the
[Cryptnox ID CLI Documentation](https://docs.cryptnox.com/cryptnox-id-cli/). It
covers installation and setup, quick starts and usage guides for every card
function (PIV, FIDO2, MIFARE DESFire, genuineness), the complete CLI command
reference, JSON output and exit codes, and factory/provisioning notes.

---

## Development

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests
mypy
pytest -q -m "not real_card"
```

Unit tests use a mock transport — no reader or card required. Real-card tests
are opt-in (`-m real_card`) and never run in CI.

---

## License

`cryptnox-id-cli` is dual-licensed:

- **LGPL-3.0** for open-source projects and proprietary projects that comply
  with LGPL requirements (see [`LICENSE`](LICENSE))
- **Commercial license** for projects that require a proprietary license
  without LGPL obligations (see [`COMMERCIAL.md`](COMMERCIAL.md) for details)

The documentation is licensed CC BY-NC-ND 4.0.

For commercial inquiries, contact: contact@cryptnox.com
