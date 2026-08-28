"""FIDO2 / CTAP 2.1 applet support (Cryptnox NXP applet).

Phase 7A scope is read-only: SELECT, authenticatorGetInfo, ping, clientPIN status,
and CTAP error decoding. On Windows the OS blocks PC/SC access to the FIDO CTAP
AID for non-elevated processes, so these commands require an Administrator
terminal (the CLI detects the block and says so).
"""
