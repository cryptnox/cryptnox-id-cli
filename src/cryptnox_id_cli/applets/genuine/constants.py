"""Constants for the Cryptnox Genuineness / attestation applet.

Values mirror the factory tool (``genuineness_tools/factory_perso.py``): Cryptnox
RID ``A0000010``, applet instance AID ``A000001000024701``. The applet is
**contact-only** (enforced on-card), so it does not answer over a contactless
interface — SELECT there returns 6A82.
"""

from __future__ import annotations

# Applet instance AID and package AID (RID A0000010 = Cryptnox).
GENUINE_AID = bytes.fromhex("A000001000024701")
GENUINE_PKG = bytes.fromhex("A0000010000247")

# Instruction bytes (CLA 0x80). GET INFO / GET CERT / ATTEST are open (no-auth)
# reads; GENERATE / PUT CERT / LOCK are factory-only over an SCP02 C-MAC channel
# and are intentionally NOT exposed by this read-only CLI.
INS_GET_INFO = 0x01
INS_GET_CERT = 0x02
INS_ATTEST = 0x04
INS_GENERATE = 0x10  # factory only (not used here)
INS_PUT_CERT = 0x12  # factory only (not used here)
INS_LOCK = 0x1E  # factory only (not used here)

# GET CERT P1 selectors.
CERT_LEAF = 0x00  # the on-card device leaf (signed by the Cryptnox Genuineness CA)
CERT_INTERMEDIATE = 0x01  # the issuer cert stored alongside the leaf

# ATTEST domain-separation label. The card returns ECDSA(SHA-256) over LABEL||nonce
# with the device private key; the host verifies it against the leaf's public key.
ATTEST_LABEL = b"CRYPTNOX-GENUINE-v1"
ATTEST_NONCE_LEN = 32
