"""PIV constants for the OpenFIPS201 applet under test.

Values reflect what THIS applet implements (verified from source + the live card),
not generic PIV assumptions: e.g. no 3DES, no RSA-1024/4096; admin key is AES-only.
"""

from __future__ import annotations

# AID observed on the card; the trailing 00 01 00 is the version/coexistent suffix.
PIV_AID = bytes.fromhex("A000000308000010000100")
PIV_RID = bytes.fromhex("A000000308")

# Instruction bytes (ISO 7816-4 / PIV).
INS_SELECT = 0xA4
INS_GET_DATA = 0xCB
INS_VERIFY = 0x20
INS_CHANGE_REFERENCE_DATA = 0x24
INS_RESET_RETRY = 0x2C
INS_GENERAL_AUTHENTICATE = 0x87
INS_PUT_DATA = 0xDB
INS_GENERATE_ASYMMETRIC = 0x47
INS_GET_RESPONSE = 0xC0

# Key-reference (slot) bytes.
KEYREF_PIV_AUTH = 0x9A
KEYREF_ADMIN = 0x9B  # management/admin key (AES only on this applet)
KEYREF_DIGITAL_SIGNATURE = 0x9C
KEYREF_KEY_MANAGEMENT = 0x9D
KEYREF_CARD_AUTH = 0x9E
KEYREF_SECURE_MESSAGING = 0x04
KEYREF_RETIRED_FIRST = 0x82
KEYREF_RETIRED_LAST = 0x95

# Verifier references. The PIV Application PIN (0x80) is the only cardholder PIN this
# CLI provisions; the Global PIN (key ref 0x00) is intentionally not supported -- see
# docs/adr/0001-piv-application-pin-not-global-pin.md.
REF_PIV_PIN = 0x80
REF_PUK = 0x81

# Algorithm identifiers (SP 800-78). Only the ones THIS applet supports are "supported".
ALGORITHMS: dict[int, str] = {
    0x06: "RSA-1024",
    0x07: "RSA-2048",
    0x05: "RSA-3072",
    0x16: "RSA-4096",
    0x08: "AES-128",
    0x0A: "AES-192",
    0x0C: "AES-256",
    0x11: "ECC-P256",
    0x14: "ECC-P384",
    0x27: "PIV-SM-CS2 (AES-128/SHA-256)",
    0x2E: "PIV-SM-CS7 (AES-256/SHA-384)",
}

# Algorithms this OpenFIPS201 FIPS build actually implements. RSA-4096 (0x16) is
# included: on-card createKey + GENERATE for RSA-4096 is confirmed on the D600/SCP03
# hardware (returns a real 512-byte modulus), gated only by the chip's DF2B max-RSA
# = 0x1000 on a non-fused card. NOTE: this covers on-card key GENERATION and key
# objects; the host-side key-IMPORT/sign helpers (keyimport.py) still cover only
# RSA-2048/3072, so external RSA-4096 import is a separate, not-yet-implemented path.
SUPPORTED_ALGORITHMS: frozenset[int] = frozenset(
    {0x07, 0x05, 0x16, 0x08, 0x0A, 0x0C, 0x11, 0x14, 0x27, 0x2E}
)

# Explicitly removed in this FIPS build (used to warn / never offer).
REMOVED_ALGORITHMS: frozenset[int] = frozenset({0x06})  # RSA-1024 (+ 3DES) — FIPS-gated
