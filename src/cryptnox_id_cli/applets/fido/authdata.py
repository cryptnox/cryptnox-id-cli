"""Parse CTAP2 authenticatorData (the signed structure inside make/getAssertion).

Layout: ``rpIdHash(32) || flags(1) || signCount(4 BE) || [attestedCredentialData] ||
[extensions]``. Attested credential data (present when the AT flag 0x40 is set) is
``aaguid(16) || credentialIdLength(2 BE) || credentialId || credentialPublicKey(COSE)``.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import cbor2

FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified
FLAG_AT = 0x40  # attested credential data included
FLAG_ED = 0x80  # extension data included


@dataclass
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None
    credential_public_key: dict | None = None

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)


def parse_authenticator_data(data: bytes) -> AuthenticatorData:
    if len(data) < 37:
        raise ValueError(f"authenticatorData too short ({len(data)} bytes)")
    ad = AuthenticatorData(
        rp_id_hash=data[:32],
        flags=data[32],
        sign_count=int.from_bytes(data[33:37], "big"),
    )
    rest = data[37:]
    if ad.flags & FLAG_AT:
        if len(rest) < 18:
            raise ValueError("attested credential data truncated")
        ad.aaguid = rest[:16]
        cid_len = int.from_bytes(rest[16:18], "big")
        if len(rest) < 18 + cid_len:
            raise ValueError("credentialId truncated")
        ad.credential_id = rest[18 : 18 + cid_len]
        # The COSE public key is one CBOR item; extensions (if any) follow it.
        decoder = cbor2.CBORDecoder(io.BytesIO(rest[18 + cid_len :]))
        key = decoder.decode()
        if not isinstance(key, dict):
            raise ValueError("credentialPublicKey is not a COSE map")
        ad.credential_public_key = key
    return ad


def verify_es256_assertion(
    cose_public_key: dict, auth_data: bytes, client_data_hash: bytes, signature: bytes
) -> bool:
    """Verify a getAssertion ES256 signature over ``authData || clientDataHash``."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from cryptnox_id_cli.applets.fido.pinproto import cose_to_public_key

    try:
        cose_to_public_key(cose_public_key).verify(
            signature, auth_data + client_data_hash, ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False
