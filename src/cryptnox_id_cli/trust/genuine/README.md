# Pinned attestation trust anchors

The **Cryptnox production PKI** ships here as PEM and is bundled into the wheel and the
PyInstaller binary:

| File | Role |
|---|---|
| `cryptnox-root-ca.pem` | `CN=CRYPTNOX ROOT CA` — self-issued, **the pinned anchor** |
| `cryptnox-intermediate-ca.pem` | `CN=CRYPTNOX INTERMEDIATE CA` — issues the FIDO2 attestation leaves |
| `cryptnox-intermediate-ca-2.pem` | `CN=CRYPTNOX INTERMEDIATE CA #2` — issues the sub-CAs below |
| `cryptnox-attestation-ca.pem` | `CN=CRYPTNOX ATTESTATION CA` — PIV key attestation |
| `cryptnox-genuineness-ca.pem` | `CN=CRYPTNOX GENUINENESS CA` — genuineness applet |
| `cryptnox-dlt-cards-ca.pem` | `CN=CRYPTNOX DLT CARDS CA` — wallet-card issuance |

Every certificate here was verified to chain to `cryptnox-root-ca.pem` before being added.
Each file carries `# subject / issuer / not after / sha256 (DER)` comment lines above the PEM
block so the pinned set is reviewable without running `openssl`.

Only the root grants trust. The intermediates add nothing a card could not present itself —
they are bundled so chain building works offline, when a card omits part of its chain.

Loading is by **inspection, not filename** (see `../__init__.py`):

- self-issued CA -> root (pinned anchor)
- non-self-issued CA -> intermediate
- non-CA material -> ignored (so leaf/attestation certs dropped here are inert)

Each file may contain more than one PEM block. `$CRYPTNOX_TRUST_DIR` adds anchors at runtime
without a rebuild; it extends this set, it never replaces it. There is no online refresh in
this version — updating the bundled set means shipping a release.

Do **not** commit private keys here — public CA certificates only. Dev/throwaway PKI
certificates (CN suffixed `(DEV)`) must never be added; pass those via `--anchors` instead.
