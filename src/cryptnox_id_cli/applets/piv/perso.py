"""PIV personalization wire grammar: set verifier (PIN/PUK) values, on-card key
generation, and writing data objects.

CHANGE REFERENCE DATA ADMIN (INS 24), GENERATE ASYMMETRIC KEYPAIR (INS 47) and
PUT DATA (INS DB) per SP 800-73 / the applet's perso-grammar doc. The exact
CHANGE-REF-DATA value layout is marked "to verify" in that doc, so it is
validated against the live card.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.util import tlv

INS_CHANGE_REFERENCE_DATA = 0x24
INS_GENERATE_ASYMMETRIC = 0x47
INS_PUT_DATA = 0xDB

P1_PIN_VALUE = 0xFF  # CHANGE REF DATA ADMIN P1 for a PIN/PUK reference (vs a key mechanism)

TAG_GENERATE_REQUEST = 0xAC
TAG_MECHANISM = 0x80
TAG_PUBKEY_TEMPLATE = 0x7F49
TAG_RSA_MODULUS = 0x81
TAG_RSA_EXPONENT = 0x82
TAG_ECC_POINT = 0x86

TAG_DATA = 0x53
TAG_TAG_LIST = 0x5C
TAG_DISCOVERY = 0x7E  # the one PIV object written (and read) bare, never 53-wrapped

# Curves by mechanism id.
_EC_CURVES = {0x11: ec.SECP256R1, 0x14: ec.SECP384R1}

# Asymmetric algorithm name -> mechanism id (those this applet supports).
ALGORITHMS = {"ECCP256": 0x11, "ECCP384": 0x14, "RSA2048": 0x07, "RSA3072": 0x05, "RSA4096": 0x16}


def pad_pin(value: bytes, length: int = 8) -> bytes:
    """PIV PIN/PUK values are padded to 8 bytes with 0xFF."""
    if len(value) > length:
        raise ValueError(f"PIN/PUK value exceeds {length} bytes")
    return bytes(value) + b"\xff" * (length - len(value))


def set_verifier_value_apdu(ref: int, padded_value: bytes) -> APDU:
    """CHANGE REFERENCE DATA ADMIN to set a PIN/PUK value (P1=0xFF, P2=ref).

    Wrapped by the SCP03 layer (admin). ``padded_value`` should already be padded.
    """
    return APDU(0x00, INS_CHANGE_REFERENCE_DATA, P1_PIN_VALUE, ref, data=padded_value)


def generate_keypair_apdu(slot: int, mechanism: int) -> APDU:
    """GENERATE ASYMMETRIC KEYPAIR: request AC{80 mechanism} for the given slot."""
    request = tlv.build_constructed(
        TAG_GENERATE_REQUEST, tlv.build(TAG_MECHANISM, bytes([mechanism]))
    )
    return APDU(0x00, INS_GENERATE_ASYMMETRIC, 0x00, slot, data=request, le=256)


def parse_public_key(mechanism: int, response: bytes):
    """Parse the 7F49 public-key template from a GENERATE response into a
    cryptography public-key object (EC or RSA)."""
    nodes = tlv.parse(response)
    template = tlv.find(nodes, TAG_PUBKEY_TEMPLATE)
    scope = template.children if (template and template.children) else nodes
    if mechanism in _EC_CURVES:
        point = tlv.find(scope, TAG_ECC_POINT)
        if point is None:
            raise ValueError("no EC point (tag 86) in GENERATE response")
        curve = _EC_CURVES[mechanism]()
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, point.value)
    modulus = tlv.find(scope, TAG_RSA_MODULUS)
    exponent = tlv.find(scope, TAG_RSA_EXPONENT)
    if modulus is None or exponent is None:
        raise ValueError("no RSA modulus/exponent (tags 81/82) in GENERATE response")
    n = int.from_bytes(modulus.value, "big")
    e = int.from_bytes(exponent.value, "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def public_key_pem(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def put_data_body(oid: bytes, object_data: bytes) -> bytes:
    """The PUT DATA command body: 5C{oid} 53{object_data} for standard objects.

    The Discovery Object is the documented exception (SP 800-73-4): it travels as the
    bare 7E TLV itself, no tag list and no 53 wrapper, and the applet's PUT DATA has a
    dedicated branch keyed on the first CDATA byte being 7E. Wrapping it like a
    standard object makes the applet store and echo the wrapper, producing a malformed
    object on the wire - the read side (objects.unwrap) has always special-cased 7E;
    this is the matching write-side case.
    """
    if oid == bytes([TAG_DISCOVERY]):
        return object_data
    return tlv.build(TAG_TAG_LIST, oid) + tlv.build(TAG_DATA, object_data)


def put_data_apdu(oid: bytes, object_data: bytes) -> APDU:
    """PUT DATA (standard): write a data object's content into a container (single APDU)."""
    return APDU(0x00, INS_PUT_DATA, 0x3F, 0xFF, data=put_data_body(oid, object_data))


INS_GENERAL_AUTHENTICATE = 0x87
TAG_DYNAMIC_AUTH = 0x7C
TAG_AUTH_CHALLENGE = 0x81
TAG_AUTH_RESPONSE = 0x82


def general_authenticate_sign_apdu(slot: int, mechanism: int, digest: bytes) -> APDU:
    """GENERAL AUTHENTICATE to sign a pre-computed digest with the slot's key.

    Request: 7C { 82 (empty response placeholder), 81 <digest> }.
    Response: 7C { 82 <signature> }. Requires the slot's access (PIN) to be met.
    """
    body = tlv.build_constructed(
        TAG_DYNAMIC_AUTH, tlv.build(TAG_AUTH_RESPONSE, b"") + tlv.build(TAG_AUTH_CHALLENGE, digest)
    )
    return APDU(0x00, INS_GENERAL_AUTHENTICATE, mechanism, slot, data=body, le=256)


def parse_sign_response(response: bytes) -> bytes:
    """Extract the signature (7C → 82) from a GENERAL AUTHENTICATE response."""
    nodes = tlv.parse(response)
    template = tlv.find(nodes, TAG_DYNAMIC_AUTH)
    scope = template.children if (template and template.children) else nodes
    sig = tlv.find(scope, TAG_AUTH_RESPONSE)
    if sig is None:
        raise ValueError("no signature (tag 82) in GENERAL AUTHENTICATE response")
    return sig.value
