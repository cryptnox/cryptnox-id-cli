"""Manual attestation-chain path validation (leaf -> intermediate -> pinned root)."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.crypto.attestation import verify_attestation_chain

_NB = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_NA = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
_NOW = datetime.datetime(2026, 6, 21, tzinfo=datetime.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, sub_key, issuer, iss_key, *, ca, nb=_NB, na=_NA) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sub_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(iss_key, hashes.SHA256())
    )


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _cn_of(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _chain(*, leaf_ca=False, inter_ca=True, leaf_na=_NA, leaf_signer=None):
    """Return (leaf, inter, root) certs. ``leaf_signer`` overrides who signs the leaf."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(_name("Test Root"), root_key, _name("Test Root"), root_key, ca=True)
    inter = _cert(_name("Test Intermediate"), inter_key, _name("Test Root"), root_key, ca=inter_ca)
    leaf = _cert(
        _name("PIV Attestation 9C"),
        leaf_key,
        _name("Test Intermediate"),
        leaf_signer or inter_key,
        ca=leaf_ca,
        na=leaf_na,
    )
    return leaf, inter, root


def test_good_chain_verifies():
    leaf, inter, root = _chain()
    res = verify_attestation_chain(_der(leaf), [_der(inter)], [_der(root)], at_time=_NOW)
    assert res.verified, res.reasons
    assert res.chain == ["CN=PIV Attestation 9C", "CN=Test Intermediate", "CN=Test Root"]
    assert res.csr_match is None


def test_no_pinned_root_fails():
    leaf, inter, _ = _chain()
    res = verify_attestation_chain(_der(leaf), [_der(inter)], [], at_time=_NOW)
    assert not res.verified
    assert any("pinned trust anchor" in r for r in res.reasons)


def test_missing_intermediate_is_not_anchored():
    leaf, _inter, root = _chain()
    res = verify_attestation_chain(_der(leaf), [], [_der(root)], at_time=_NOW)
    assert not res.verified
    assert any("not anchored" in r for r in res.reasons)


def test_tampered_leaf_signature_fails():
    rogue = ec.generate_private_key(ec.SECP256R1())
    leaf, inter, root = _chain(leaf_signer=rogue)  # leaf says inter issued it, but rogue signed
    res = verify_attestation_chain(_der(leaf), [_der(inter)], [_der(root)], at_time=_NOW)
    assert not res.verified
    assert any("does not verify" in r for r in res.reasons)


def test_expired_leaf_fails():
    leaf, inter, root = _chain(leaf_na=datetime.datetime(2026, 3, 1, tzinfo=datetime.timezone.utc))
    res = verify_attestation_chain(_der(leaf), [_der(inter)], [_der(root)], at_time=_NOW)
    assert not res.verified
    assert any("validity window" in r for r in res.reasons)


def test_non_ca_intermediate_fails():
    leaf, inter, root = _chain(inter_ca=False)
    res = verify_attestation_chain(_der(leaf), [_der(inter)], [_der(root)], at_time=_NOW)
    assert not res.verified
    assert any("is not a CA" in r for r in res.reasons)


def test_sibling_cas_in_the_pool_do_not_break_the_path():
    """The bundled trust store is an unordered pool of sibling CAs, not an ordered chain.

    Regression: the walker used to pair each certificate with the *next list element*, so a
    pool holding more than one intermediate compared the leaf against an unrelated sibling
    and failed a genuine chain.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(_name("Test Root"), root_key, _name("Test Root"), root_key, ca=True)

    siblings = []
    for cn in ("Attestation CA", "Genuineness CA", "DLT Cards CA"):
        key = ec.generate_private_key(ec.SECP256R1())
        siblings.append((key, _cert(_name(cn), key, _name("Test Root"), root_key, ca=True)))

    issuer_key, issuer = siblings[1]  # leaf hangs off the middle sibling
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(
        _name("PIV Attestation 9C"), leaf_key, _name("Genuineness CA"), issuer_key, ca=False
    )

    pool = [_der(c) for _k, c in siblings]
    for ordering in (pool, list(reversed(pool))):  # list order must not matter
        res = verify_attestation_chain(_der(leaf), ordering, [_der(root)], at_time=_NOW)
        assert res.verified, res.reasons
        assert res.chain == ["CN=PIV Attestation 9C", "CN=Genuineness CA", "CN=Test Root"]
    assert _cn_of(issuer) == "CN=Genuineness CA"


def test_multi_hop_path_through_the_pool():
    """leaf -> sub-CA -> intermediate -> pinned root, with distractors in the pool."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    sub_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    decoy_key = ec.generate_private_key(ec.SECP256R1())

    root = _cert(_name("Test Root"), root_key, _name("Test Root"), root_key, ca=True)
    inter = _cert(_name("Intermediate #2"), inter_key, _name("Test Root"), root_key, ca=True)
    sub = _cert(_name("Attestation CA"), sub_key, _name("Intermediate #2"), inter_key, ca=True)
    decoy = _cert(_name("Unrelated CA"), decoy_key, _name("Test Root"), root_key, ca=True)
    leaf = _cert(_name("PIV Attestation 9C"), leaf_key, _name("Attestation CA"), sub_key, ca=False)

    res = verify_attestation_chain(
        _der(leaf), [_der(decoy), _der(sub), _der(inter)], [_der(root)], at_time=_NOW
    )
    assert res.verified, res.reasons
    assert res.chain == [
        "CN=PIV Attestation 9C",
        "CN=Attestation CA",
        "CN=Intermediate #2",
        "CN=Test Root",
    ]


def test_same_named_issuer_with_the_wrong_key_is_rejected():
    """A pool entry may carry the right subject name but a different key — name is not proof."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    real_key = ec.generate_private_key(ec.SECP256R1())
    impostor_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _cert(_name("Test Root"), root_key, _name("Test Root"), root_key, ca=True)
    # Same subject as the real issuer, different key, still signed by the pinned root.
    impostor = _cert(_name("Attestation CA"), impostor_key, _name("Test Root"), root_key, ca=True)
    leaf = _cert(_name("PIV Attestation 9C"), leaf_key, _name("Attestation CA"), real_key, ca=False)

    res = verify_attestation_chain(_der(leaf), [_der(impostor)], [_der(root)], at_time=_NOW)
    assert not res.verified
    assert any("does not verify" in r for r in res.reasons)


def test_csr_match_true_and_false():
    leaf, inter, root = _chain()
    ok = verify_attestation_chain(
        _der(leaf), [_der(inter)], [_der(root)], csr_spki=_spki(leaf), at_time=_NOW
    )
    assert ok.verified and ok.csr_match is True

    other = ec.generate_private_key(ec.SECP256R1())
    other_spki = other.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    bad = verify_attestation_chain(
        _der(leaf), [_der(inter)], [_der(root)], csr_spki=other_spki, at_time=_NOW
    )
    assert not bad.verified and bad.csr_match is False
    assert any("does not match the CSR" in r for r in bad.reasons)
