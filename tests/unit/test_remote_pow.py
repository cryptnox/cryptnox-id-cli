"""The proof-of-work solver: correct answers, and bounded work."""

import hashlib

import pytest

from cryptnox_id_cli.remote import pow as rpow
from cryptnox_id_cli.transport.errors import RemoteProtocolError


def test_leading_zero_bits_counts_bits_not_nibbles():
    assert rpow.leading_zero_bits(b"\xff") == 0
    assert rpow.leading_zero_bits(b"\x80") == 0
    assert rpow.leading_zero_bits(b"\x7f") == 1
    assert rpow.leading_zero_bits(b"\x01") == 7
    assert rpow.leading_zero_bits(b"\x00\xff") == 8
    assert rpow.leading_zero_bits(b"\x00\x7f") == 9
    assert rpow.leading_zero_bits(b"\x00\x00\x01") == 23
    assert rpow.leading_zero_bits(b"\x00\x00\x00\x00") == 32


def test_digest_uses_decimal_nonce_not_bytes():
    challenge = bytes.fromhex("00112233")
    # The service checks sha256(challenge || str(nonce)), so nonce 10 must hash
    # the two ASCII characters "10", never the single byte 0x0A.
    assert rpow.digest_for(challenge, 10) == hashlib.sha256(challenge + b"10").digest()
    assert rpow.digest_for(challenge, 10) != hashlib.sha256(challenge + b"\x0a").digest()


def test_solve_returns_a_nonce_the_service_would_accept():
    challenge = bytes.fromhex("a1b2c3d4")
    bits = 12
    nonce = rpow.solve(challenge, bits)
    assert rpow.leading_zero_bits(rpow.digest_for(challenge, nonce)) >= bits


def test_solve_returns_the_first_valid_nonce():
    challenge = bytes.fromhex("deadbeef")
    bits = 10
    nonce = rpow.solve(challenge, bits)
    for earlier in range(nonce):
        assert rpow.leading_zero_bits(rpow.digest_for(challenge, earlier)) < bits


def test_zero_bits_needs_no_work():
    assert rpow.solve(b"\x01\x02", 0) == 0


def test_difficulty_beyond_the_ceiling_is_refused_without_hashing():
    with pytest.raises(RemoteProtocolError, match="at most"):
        rpow.solve(b"\x00", rpow.MAX_BITS + 1)


def test_negative_difficulty_is_refused():
    with pytest.raises(RemoteProtocolError):
        rpow.solve(b"\x00", -1)


def test_search_is_bounded_rather_than_endless():
    # A tight attempt budget cannot satisfy a difficulty this high, and the
    # solver must give up instead of spinning.
    with pytest.raises(RemoteProtocolError, match="attempts"):
        rpow.solve(b"\x00", 24, max_attempts=50)
