"""Proof-of-work for the remote PIV service.

The service gates each operation behind a small hash puzzle: find a nonce whose
SHA-256 digest of ``challenge || decimal(nonce)`` starts with at least the
requested number of zero bits. It is an anti-abuse throttle, not a credential,
and it is solved before the service knows which card is present.

The work is bounded twice over: the client refuses a difficulty it would not
finish in reasonable time, and the search itself stops rather than spinning
forever on a challenge that has no cheap answer.
"""

from __future__ import annotations

import hashlib

from ..transport.errors import RemoteProtocolError

#: Highest difficulty this client will attempt. At 24 bits the expected work is
#: ~17 million hashes, already tens of seconds of pure Python. Anything beyond
#: that is refused rather than silently hanging the command.
MAX_BITS = 24

#: Safety factor on the expected number of attempts, so a pathological challenge
#: aborts instead of running unbounded. The expected count is 2**bits.
_ATTEMPT_MARGIN = 16


def leading_zero_bits(digest: bytes) -> int:
    """Count the zero bits at the start of ``digest``."""
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        # 8 bits wide, so the first set bit sits at 7 - floor(log2(byte)).
        count += 8 - byte.bit_length()
        break
    return count


def digest_for(challenge: bytes, nonce: int) -> bytes:
    """The digest the service checks: SHA-256 over the challenge and the nonce.

    The nonce contributes its decimal representation, not its bytes.
    """
    return hashlib.sha256(bytes(challenge) + str(nonce).encode("ascii")).digest()


def solve(challenge: bytes, bits: int, *, max_attempts: int | None = None) -> int:
    """Find a nonce whose digest has at least ``bits`` leading zero bits.

    Raises :class:`RemoteProtocolError` if the difficulty is beyond what this
    client attempts, or if the bounded search finds no answer.
    """
    if bits < 0:
        raise RemoteProtocolError("the service asked for a negative proof-of-work difficulty")
    if bits > MAX_BITS:
        raise RemoteProtocolError(
            f"the service asked for {bits} bits of proof-of-work; this client attempts "
            f"at most {MAX_BITS}"
        )
    if bits == 0:
        return 0

    limit = max_attempts if max_attempts is not None else (1 << bits) * _ATTEMPT_MARGIN
    challenge = bytes(challenge)
    for nonce in range(limit):
        if leading_zero_bits(digest_for(challenge, nonce)) >= bits:
            return nonce
    raise RemoteProtocolError(f"no proof-of-work answer for {bits} bits within {limit} attempts")
