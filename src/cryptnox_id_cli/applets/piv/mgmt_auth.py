"""PIV management key (key reference 9B): authentication and value management.

The applet administers each key object either through the GlobalPlatform secure
channel (the admin role on a wrapped APDU) or through the PIV management key named in
the object's admin-key element, which defaults to 9B. Authenticating 9B over plain
APDUs grants the key-holder role for 9B, which authorizes GENERATE on every key
object 9B administers, and the applet answers on its plaintext response path, which
chains long responses with 61xx. The CLI uses this for one thing: finishing an on-card
key generation when the admin channel cannot return the full public-key template. 9B
is contact-only on the structure this CLI lays down (the key object's contactless
access mode is NEVER).

Authentication is MUTUAL (GENERAL AUTHENTICATE cases 4 and 5): the card returns an
enciphered witness, the host returns it deciphered together with its own challenge,
and the card's answer to that challenge proves the card holds the key too.

Wire grammar only; the caller owns the card session and the SELECT that precedes the
exchange. See docs/adr/0002-management-key-fallback-for-on-card-generation.md.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError
from cryptnox_id_cli.util import tlv

INS_GENERAL_AUTHENTICATE = 0x87
INS_CHANGE_REFERENCE_DATA = 0x24

TAG_DYNAMIC_AUTH = 0x7C
TAG_WITNESS = 0x80
TAG_CHALLENGE = 0x81
TAG_RESPONSE = 0x82

ELEMENT_KEY = 0x80  # symmetric key value element
ELEMENT_CLEAR = 0x9F  # "drop the current value" element

#: AES block length. Witness, challenge and response are one block each.
BLOCK_LEN = 16

#: AES mechanism id -> key length in bytes.
AES_MECHANISMS: dict[int, int] = {0x08: 16, 0x0A: 24, 0x0C: 32}

#: Probe order when nothing narrows it: the built-in profiles create 9B as AES-256.
MECHANISM_PROBE_ORDER: tuple[int, ...] = (0x0C, 0x08, 0x0A)

#: Shaped like ``CardSession.transmit`` - the caller passes the bound method.
Transmit = Callable[..., Response]

_PREFIX = "PIV management key authentication failed: "


def mechanism_name(mechanism: int) -> str:
    """Human-readable mechanism label, e.g. ``AES-256``."""
    return c.ALGORITHMS.get(mechanism, f"{mechanism:#04x}")


def mechanism_for_key_length(length: int) -> int | None:
    """The AES mechanism a key value of ``length`` bytes belongs to, or ``None``."""
    for mechanism, key_len in AES_MECHANISMS.items():
        if key_len == length:
            return mechanism
    return None


class MgmtKeyError(CryptnoxError):
    """Management-key (9B) authentication or provisioning failure."""

    code = "mgmt_key"
    exit_code = 7

    def __init__(self, message: str, *, stage: str, sw: int | None = None) -> None:
        super().__init__(message)
        #: Which part of the exchange failed: ``missing``, ``empty``, ``access``,
        #: ``unusable``, ``key_length``, ``key_mismatch``, ``card_verify``,
        #: ``protocol`` or ``set_value``.
        self.stage = stage
        self.sw = sw

    def to_dict(self) -> dict[str, object]:
        return {
            "error": self.code,
            "message": str(self),
            "stage": self.stage,
            "sw": f"{self.sw:04X}" if self.sw is not None else None,
        }


@dataclass(frozen=True)
class MgmtKeyMaterial:
    """Where the 9B value came from, and the value it can serve per mechanism."""

    #: ``--default-keys``, ``$PIV_MGMT_KEY`` or ``$CARD_PIV_MGMT_KEY``. Named in
    #: messages; the value itself never is.
    source: str
    #: mechanism id -> key bytes, already length-checked against AES_MECHANISMS.
    keys: Mapping[int, bytes]

    def mechanisms(self) -> tuple[int, ...]:
        """Probe order: the mechanisms this material can serve first, then the rest.

        Probing the others too costs one short APDU each and turns "authentication
        failed" into "this card's 9B is AES-128 and you supplied 32 bytes".
        """
        served = [m for m in MECHANISM_PROBE_ORDER if m in self.keys]
        rest = [m for m in MECHANISM_PROBE_ORDER if m not in self.keys]
        return tuple(served + rest)

    def key_for(self, mechanism: int) -> bytes:
        """The value for a mechanism the card reported, or a ``key_length`` failure."""
        value = self.keys.get(mechanism)
        if value is not None:
            return bytes(value)
        name = mechanism_name(mechanism)
        need = AES_MECHANISMS.get(mechanism, 0)
        if self.source == "--default-keys":
            raise MgmtKeyError(
                f"--default-keys has no published value for an {name} management key; "
                f"set $PIV_MGMT_KEY ({need * 2} hex characters).",
                stage="key_length",
            )
        supplied = next(iter(self.keys.values()), b"")
        raise MgmtKeyError(
            f"{_PREFIX}the card's management key is {name} and needs a {need}-byte "
            f"value; {self.source} supplied {len(supplied)} bytes.",
            stage="key_length",
        )


@dataclass(frozen=True)
class MgmtKeyProbe:
    """Outcome of the read-only witness-request probe."""

    #: The mechanism whose key object answered, or ``None`` when every candidate
    #: reported "no such (key reference, mechanism) pair".
    mechanism: int | None
    #: Status word of the deciding response (6A86 when no candidate answered).
    sw: int
    #: The enciphered witness, when the card returned one.
    witness: bytes | None


@dataclass(frozen=True)
class MgmtAuth:
    """A completed mutual authentication against 9B."""

    mechanism: int
    source: str


# --------------------------------------------------------------------------- #
# APDU builders                                                               #
# --------------------------------------------------------------------------- #
def witness_request_apdu(mechanism: int) -> APDU:
    """GENERAL AUTHENTICATE case 4: an empty witness tag asks the card for one."""
    body = tlv.build_constructed(TAG_DYNAMIC_AUTH, tlv.build(TAG_WITNESS, b""))
    return APDU(0x00, INS_GENERAL_AUTHENTICATE, mechanism, c.KEYREF_ADMIN, data=body, le=256)


def mutual_response_apdu(mechanism: int, witness: bytes, challenge: bytes) -> APDU:
    """GENERAL AUTHENTICATE case 5: the deciphered witness, then the host challenge.

    Tag order inside the template is witness (80) before challenge (81); the applet
    dispatches on exactly that combination.
    """
    body = tlv.build_constructed(
        TAG_DYNAMIC_AUTH,
        tlv.build(TAG_WITNESS, witness) + tlv.build(TAG_CHALLENGE, challenge),
    )
    return APDU(0x00, INS_GENERAL_AUTHENTICATE, mechanism, c.KEYREF_ADMIN, data=body, le=256)


def clear_value_apdu(mechanism: int) -> APDU:
    """CHANGE REFERENCE DATA ADMIN dropping 9B's current value (admin channel only)."""
    return APDU(
        0x00,
        INS_CHANGE_REFERENCE_DATA,
        mechanism,
        c.KEYREF_ADMIN,
        data=tlv.build(ELEMENT_CLEAR, b""),
    )


def set_value_apdu(mechanism: int, value: bytes) -> APDU:
    """CHANGE REFERENCE DATA ADMIN loading a 9B value (admin channel only)."""
    expected = AES_MECHANISMS.get(mechanism)
    if expected is None:
        raise MgmtKeyError(
            f"{mechanism:#04x} is not an AES mechanism, so it cannot hold a management key.",
            stage="key_length",
        )
    if len(value) != expected:
        raise MgmtKeyError(
            f"an {mechanism_name(mechanism)} management key needs a {expected}-byte value; "
            f"{len(value)} bytes were supplied.",
            stage="key_length",
        )
    return APDU(
        0x00,
        INS_CHANGE_REFERENCE_DATA,
        mechanism,
        c.KEYREF_ADMIN,
        data=tlv.build(ELEMENT_KEY, bytes(value)),
    )


# --------------------------------------------------------------------------- #
# Crypto and parsing                                                          #
# --------------------------------------------------------------------------- #
def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """Encrypt exactly one AES block, no padding (the 9B authentication primitive)."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - single block
    return enc.update(_one_block(block)) + enc.finalize()


def aes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    """Decrypt exactly one AES block, no padding."""
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305 - single block
    return dec.update(_one_block(block)) + dec.finalize()


def _one_block(block: bytes) -> bytes:
    if len(block) != BLOCK_LEN:
        raise MgmtKeyError(
            f"{_PREFIX}expected a {BLOCK_LEN}-byte block, got {len(block)}.", stage="protocol"
        )
    return bytes(block)


def auth_field(data: bytes, tag: int) -> bytes:
    """The one-block value of ``tag`` inside the 7C dynamic-authentication template."""
    try:
        nodes = tlv.parse(data)
    except ValueError as exc:
        raise MgmtKeyError(
            f"{_PREFIX}the card's response did not match the expected 7C template ({exc}).",
            stage="protocol",
        ) from exc
    template = tlv.find(nodes, TAG_DYNAMIC_AUTH)
    if template is None:
        raise MgmtKeyError(
            f"{_PREFIX}the card's response carries no 7C template.", stage="protocol"
        )
    node = tlv.find(template.children, tag)
    if node is None:
        raise MgmtKeyError(
            f"{_PREFIX}the card's 7C template carries no tag {tag:02X}.", stage="protocol"
        )
    if len(node.value) != BLOCK_LEN:
        raise MgmtKeyError(
            f"{_PREFIX}tag {tag:02X} is {len(node.value)} bytes; expected {BLOCK_LEN}.",
            stage="protocol",
        )
    return node.value


# --------------------------------------------------------------------------- #
# Drivers                                                                     #
# --------------------------------------------------------------------------- #
def probe(transmit: Transmit, mechanisms: Sequence[int]) -> MgmtKeyProbe:
    """Ask 9B for a witness, one candidate mechanism at a time.

    This is the only way to learn anything about a key object's value: the applet has
    no read-only "is it set" query, and its precondition ordering makes the status word
    of this one command say which of "absent", "no value", "not accessible here",
    "not usable for this flow" and "ready" holds. Nothing is written and no retry
    counter exists on 9B.

    A successful probe leaves a two-step exchange open on the card; the applet resets
    it on the next witness request, so abandoning one is harmless. It does clear any
    key-holder role already held, so never probe between an authentication and the
    operation that depends on it.
    """
    for mechanism in mechanisms:
        resp = transmit(witness_request_apdu(mechanism), context="9B witness request")
        if resp.sw == 0x6A86:  # no key object for this (reference, mechanism) pair
            continue
        witness = auth_field(resp.data, TAG_WITNESS) if resp.ok else None
        return MgmtKeyProbe(mechanism=mechanism, sw=resp.sw, witness=witness)
    return MgmtKeyProbe(mechanism=None, sw=0x6A86, witness=None)


def authenticate(
    transmit: Transmit,
    material: MgmtKeyMaterial,
    *,
    challenge: bytes | None = None,
    contactless: bool = False,
) -> MgmtAuth:
    """Authenticate 9B mutually over plain APDUs, granting the key-holder role.

    ``challenge`` is injectable so tests are deterministic; production passes nothing
    and gets a fresh random block. ``contactless`` only shapes the refusal message.

    The two commands are sent back to back: the applet holds a single pending
    authentication state, so anything in between invalidates the exchange.
    """
    candidates = material.mechanisms()
    found = probe(transmit, candidates)

    if found.mechanism is None:
        names = ", ".join(mechanism_name(m) for m in candidates)
        raise MgmtKeyError(
            f"{_PREFIX}this card has no AES key object in slot 9B (SW=6A86 for {names}). "
            "Slot 9B is laid down by pre-personalization; check the card with "
            "'cryptnox-id factory piv preperso status'.",
            stage="missing",
            sw=found.sw,
        )
    name = mechanism_name(found.mechanism)
    if found.sw == 0x6983:
        raise MgmtKeyError(
            f"{_PREFIX}slot 9B exists ({name}) but holds no key value (SW=6983), so this "
            "card cannot complete the generation over the plain path. Load a value once "
            "with 'cryptnox-id factory piv preperso set-mgmt-key' (needs the admin "
            "channel), then re-run this command.",
            stage="empty",
            sw=found.sw,
        )
    if found.sw == 0x6982:
        where = (
            ", and this session looks like a contactless (PICC) interface - re-run on the "
            "contact reader."
            if contactless
            else "; use the contact reader."
        )
        raise MgmtKeyError(
            f"{_PREFIX}slot 9B refused authentication on this interface (SW=6982). The "
            f"management key is contact-only on this card{where}",
            stage="access",
            sw=found.sw,
        )
    if found.sw == 0x6985:
        raise MgmtKeyError(
            f"{_PREFIX}slot 9B does not permit mutual authentication (SW=6985). Its key "
            "object needs the AUTHENTICATE role and the PERMIT_MUTUAL attribute, which "
            "are fixed at pre-personalization.",
            stage="unusable",
            sw=found.sw,
        )
    if found.witness is None:
        raise StatusWordError(found.sw >> 8, found.sw & 0xFF, context="9B witness request")

    key = material.key_for(found.mechanism)
    witness = aes_ecb_decrypt(key, found.witness)
    nonce = challenge if challenge is not None else os.urandom(BLOCK_LEN)

    resp = transmit(
        mutual_response_apdu(found.mechanism, witness, nonce), context="9B mutual response"
    )
    if resp.sw == 0x6982:
        raise MgmtKeyError(
            f"{_PREFIX}the card rejected the response to its witness (SW=6982), so the "
            f"value from {material.source} is not this card's 9B key.",
            stage="key_mismatch",
            sw=resp.sw,
        )
    if resp.sw in (0x6A80, 0x6700):
        raise MgmtKeyError(
            f"{_PREFIX}the card's response did not match the expected 7C template "
            f"(SW={resp.sw_hex()}).",
            stage="protocol",
            sw=resp.sw,
        )
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context="9B mutual response")

    answer = auth_field(resp.data, TAG_RESPONSE)
    if not hmac.compare_digest(aes_ecb_decrypt(key, answer), nonce):
        raise MgmtKeyError(
            f"{_PREFIX}the card's response does not match the challenge, so the card does "
            f"not hold the key from {material.source}.",
            stage="card_verify",
            sw=resp.sw,
        )
    return MgmtAuth(mechanism=found.mechanism, source=material.source)
