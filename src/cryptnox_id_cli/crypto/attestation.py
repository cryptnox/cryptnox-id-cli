"""Offline verification of a PIV key-attestation chain.

The pinned ``cryptography`` exposes no high-level path validator, so we walk the chain
manually (the same approach as the genuineness check in ``docs/verify-genuine.md``):

* name chaining   — each cert's issuer equals the next cert's subject
* signature       — each cert is signed by the next cert's public key
* validity        — each cert is within its not-before/not-after window
* CA constraint   — every issuer (intermediate/root) asserts BasicConstraints CA=TRUE
* anchoring       — the chain terminates at a **pinned** root (passed in by the caller);
                    a root is trusted because it is pinned, never because it appears here

The leaf comes off the card; ``intermediates`` is an **unordered candidate pool** (the bundled
trust store holds several sibling CAs, and a card may present its chain in any order), and
``roots`` are the pinned anchors. The path is built by matching each certificate's issuer name
and then checking the signature, so sibling CAs in the pool cannot be mistaken for the issuer.
An optional ``csr_spki`` enforces that the attested public key is the one in a CSR (the "same
key as your CSR" property).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


@dataclass
class AttestationResult:
    """Outcome of :func:`verify_attestation_chain` — JSON-friendly."""

    verified: bool
    reasons: list[str] = field(default_factory=list)  # empty iff verified
    chain: list[str] = field(default_factory=list)  # subjects, leaf -> anchor
    csr_match: bool | None = None  # None if no CSR was supplied
    #: DER of each certificate on the path, leaf first — the certificates actually selected,
    #: not the whole candidate pool. Kept out of ``to_dict`` (bytes are not JSON-friendly).
    path_ders: list[bytes] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "verified": self.verified,
            "reasons": self.reasons,
            "chain": self.chain,
            "csr_match": self.csr_match,
        }


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _cn(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True if ``issuer``'s public key verifies ``child``'s signature."""
    hash_alg = child.signature_hash_algorithm
    if hash_alg is None:  # e.g. Ed25519 — not used for these attestation certs
        return False
    pub = issuer.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(hash_alg))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), hash_alg)
        else:  # unsupported issuer key type
            return False
    except InvalidSignature:
        return False
    return True


def verify_attestation_chain(
    leaf_der: bytes,
    intermediate_ders: list[bytes],
    root_ders: list[bytes],
    *,
    csr_spki: bytes | None = None,
    at_time: datetime.datetime | None = None,
) -> AttestationResult:
    """Validate ``leaf -> intermediates -> pinned root`` and collect every failure reason."""
    now = at_time or datetime.datetime.now(datetime.timezone.utc)
    leaf = x509.load_der_x509_certificate(leaf_der)
    pool = [x509.load_der_x509_certificate(d) for d in intermediate_ders]
    roots = [x509.load_der_x509_certificate(d) for d in root_ders]

    reasons: list[str] = []
    chain = [_cn(leaf)]
    path_ders = [leaf_der]

    # "Same key as your CSR".
    csr_match: bool | None = None
    if csr_spki is not None:
        csr_match = _spki(leaf) == csr_spki
        if not csr_match:
            reasons.append("attested public key does not match the CSR")

    if not roots:
        reasons.append("no pinned trust anchor available — cannot verify the chain")

    def _check_validity(cert: x509.Certificate) -> None:
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            reasons.append(f"certificate {_cn(cert)!r} is outside its validity window")

    child = leaf
    used: set[bytes] = {leaf_der}
    # One hop per available certificate is the most any acyclic path can need; `used` already
    # rules out revisiting, so this only bounds a pathological pool.
    for _ in range(len(pool) + len(roots) + 1):
        _check_validity(child)

        # Anchor first: a pinned root that issued this certificate ends the path.
        anchor = next(
            (r for r in roots if r.subject == child.issuer and _signed_by(child, r)), None
        )
        if anchor is not None:
            _check_validity(anchor)
            chain.append(_cn(anchor))
            path_ders.append(_der(anchor))
            break

        # Otherwise look for the issuer among the intermediates, by name *then* signature —
        # the pool holds sibling CAs, so position in the list means nothing.
        named = [c for c in pool if c.subject == child.issuer and _der(c) not in used]
        issuer = next((c for c in named if _is_ca(c) and _signed_by(child, c)), None) or next(
            (c for c in named if _signed_by(child, c)), None
        )
        if issuer is None:
            if named:  # right name, wrong key — a substituted or tampered certificate
                reasons.append(f"signature on {_cn(child)!r} does not verify")
            elif roots:  # nothing on hand issues this cert, and no pinned root does either
                reasons.append(f"not anchored: no pinned root issues {_cn(child)!r}")
            break  # (an empty `roots` already recorded its own reason above)

        if not _is_ca(issuer):
            reasons.append(f"issuer {_cn(issuer)!r} is not a CA (BasicConstraints)")
        chain.append(_cn(issuer))
        path_ders.append(_der(issuer))
        used.add(_der(issuer))
        child = issuer
    else:  # pragma: no cover - only reachable if the bound above is ever wrong
        reasons.append("chain too long — giving up before reaching a pinned root")

    return AttestationResult(
        verified=not reasons,
        reasons=reasons,
        chain=chain,
        csr_match=csr_match,
        path_ders=path_ders,
    )
