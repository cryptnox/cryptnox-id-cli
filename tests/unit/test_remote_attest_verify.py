"""Local verification of a returned attestation certificate, against a test PKI."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.remote import attest_verify as av

UID = "4301012345670042"
NOW = datetime.datetime(2026, 9, 22, tzinfo=datetime.timezone.utc)


def _name(cn: str, serial: str | None = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TEST PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if serial is not None:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial))
    return x509.Name(attrs)


def _der_int(value: int) -> bytes:
    # Minimal two's-complement encoding, so 0x9C becomes 00 9C, not a negative byte.
    body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return bytes([0x02, len(body)]) + body


def _ca(subject: str, issuer_key=None, issuer_name=None):
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(subject)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name or name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return key, cert


def _leaf(
    issuer_key,
    issuer_cert,
    *,
    uid: str | None = UID,
    slot: int | None = 0x9C,
    trust_model: int | None = 2,
    key=None,
):
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("CRYPTNOX PIV ATTESTATION", uid))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=365))
    )
    if slot is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(av.OID_PIV_SLOT, _der_int(slot)), critical=False
        )
    if trust_model is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(av.OID_TRUST_MODEL, _der_int(trust_model)),
            critical=False,
        )
    return key, builder.sign(issuer_key, hashes.SHA256())


def _der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="module")
def pki():
    root_key, root = _ca("TEST ROOT CA")
    att_key, att = _ca("TEST ATTESTATION CA", issuer_key=root_key, issuer_name=root.subject)
    return {"root": root, "att_key": att_key, "att": att, "anchors": ([_der(root)], [_der(att)])}


def verify(pki, leaf, *, slot=0x9C, uid=UID, on_card=None):
    return av.verify_returned_attestation(
        _der(leaf),
        slot=slot,
        cplc_uid=uid,
        on_card_der=on_card,
        anchors=pki["anchors"],
        at_time=NOW,
    )


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def test_leaf_from_pem_returns_the_first_certificate(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"])
    assert av.leaf_from_pem(_pem(leaf) + _pem(pki["att"])) == _der(leaf)


def test_leaf_from_pem_rejects_empty():
    with pytest.raises(ValueError):
        av.leaf_from_pem("not a certificate")


def test_der_integer():
    assert av.der_integer(bytes.fromhex("020102")) == 2
    assert av.der_integer(bytes.fromhex("02019C")) == -100  # signed: 0x9C alone is negative
    assert av.der_integer(bytes.fromhex("0202009C")) == 0x9C
    assert av.der_integer(bytes.fromhex("0401AA")) is None  # not an INTEGER
    assert av.der_integer(b"") is None
    assert av.der_integer(bytes.fromhex("020200")) is None  # truncated


# --------------------------------------------------------------------------- #
# The whole check                                                             #
# --------------------------------------------------------------------------- #
def test_genuine_leaf_verifies_and_binds(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"])
    result = verify(pki, leaf, on_card=_der(leaf))
    assert result.verified is True
    assert result.chain_verified is True
    assert "CN=CRYPTNOX PIV ATTESTATION" in result.chain[0]
    assert result.serial_number == UID
    assert result.serial_number_matches_card is True
    assert result.slot == 0x9C
    assert result.slot_matches is True
    assert result.trust_model == 2
    assert result.trust_model_matches is True
    assert result.public_key_matches_card is True
    assert result.reasons == []
    assert result.to_dict()["slot"] == "9C"


def test_without_the_card_copy_the_key_binding_is_unchecked_and_not_verified(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"])
    result = verify(pki, leaf, on_card=None)
    assert result.public_key_matches_card is None
    assert result.verified is False  # an unchecked binding is not a passed one
    assert result.chain_verified is True


def test_wrong_slot_is_a_failure(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"], slot=0x9A)
    result = verify(pki, leaf, slot=0x9C, on_card=_der(leaf))
    assert result.slot == 0x9A
    assert result.slot_matches is False
    assert result.verified is False
    assert any("attests slot 9A" in r for r in result.reasons)


def test_wrong_card_is_a_failure(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"], uid="4301999999990042")
    result = verify(pki, leaf, on_card=_der(leaf))
    assert result.serial_number_matches_card is False
    assert result.verified is False


def test_serial_comparison_ignores_case(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"], uid=UID.lower())
    assert verify(pki, leaf, on_card=_der(leaf)).serial_number_matches_card is True


def test_wrong_trust_model_is_a_failure(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"], trust_model=1)
    result = verify(pki, leaf, on_card=_der(leaf))
    assert result.trust_model == 1
    assert result.trust_model_matches is False
    assert result.verified is False


def test_missing_extensions_are_failures_not_passes(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"], slot=None, trust_model=None)
    result = verify(pki, leaf, on_card=_der(leaf))
    assert result.slot_matches is False
    assert result.trust_model_matches is False
    assert result.verified is False
    assert any("no cryptnoxPivSlot" in r for r in result.reasons)


def test_missing_serial_number_is_a_failure(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"], uid=None)
    result = verify(pki, leaf, on_card=_der(leaf))
    assert result.serial_number is None
    assert result.serial_number_matches_card is False
    assert result.verified is False


def test_untrusted_chain_is_a_failure(pki):
    other_key, other_root = _ca("SOME OTHER ROOT")
    _, leaf = _leaf(other_key, other_root)
    result = verify(pki, leaf, on_card=_der(leaf))
    assert result.chain_verified is False
    assert result.verified is False
    assert any("not anchored" in r for r in result.reasons)


def test_public_key_mismatch_with_the_card_is_a_failure(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"])
    _, other = _leaf(pki["att_key"], pki["att"])  # a different key pair
    result = verify(pki, leaf, on_card=_der(other))
    assert result.public_key_matches_card is False
    assert result.verified is False
    assert any("differs from the certificate stored on the card" in r for r in result.reasons)


def test_uid_unknown_leaves_the_serial_binding_unchecked(pki):
    _, leaf = _leaf(pki["att_key"], pki["att"])
    result = verify(pki, leaf, uid=None, on_card=_der(leaf))
    assert result.serial_number_matches_card is None
    assert result.verified is False
