"""Cryptnox Genuineness / attestation applet (RID A0000010, AID A000001000024701).

Read-only client for the on-card attestation applet: SELECT, GET INFO, GET CERT
(leaf / issuer, free-read even when fused) and ATTEST (sign a host nonce with the
on-card device key). These are the KDF-free genuineness checks — they need no ISD /
PIV-SSD secret, so this tool can run them without the factory HSM. See
``docs/genuineness.md``.
"""

from cryptnox_id_cli.applets.genuine.genuine import GenuinenessApplet, GenuinenessInfo

__all__ = ["GenuinenessApplet", "GenuinenessInfo"]
