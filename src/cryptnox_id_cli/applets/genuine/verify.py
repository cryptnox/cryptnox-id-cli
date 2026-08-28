"""Offline verification of the genuineness applet's attestation.

Two independent, KDF-free checks (neither needs the ISD / PIV-SSD secret, so this
tool can run both without the factory HSM):

* **proof of possession** — the card ATTESTs a fresh host nonce; the returned ECDSA
  signature is verified against the on-card leaf's public key. This proves the card
  physically holds the device private key *right now* (a copied certificate cannot
  fake it).
* **certificate chain** — the leaf chains ``leaf -> Genuineness CA -> ... -> pinned
  Cryptnox root`` using the pinned trust anchors (:mod:`cryptnox_id_cli.trust`).
  Without a pinned root this reports "cannot verify" — it never silently passes.

What this does NOT do: the ISD-KDF and PIV-SSD-KVN2 genuineness methods, which
require the per-card HSM-derived secret keys. Those are out of scope for a tool with
no KDF access; absence of that check is stated in the result, not hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from cryptnox_id_cli.applets.genuine import constants as c
from cryptnox_id_cli.crypto.attestation import AttestationResult, verify_attestation_chain


@dataclass
class GenuinenessResult:
    """Outcome of the read-only genuineness verification — JSON-friendly."""

    attested: bool  # card produced a signature that verifies against its leaf key
    attest_detail: str
    chain: AttestationResult | None  # None if no leaf cert was available to chain
    leaf_subject: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def genuine(self) -> bool:
        """Genuine iff the card proved possession AND the chain anchored at a pinned
        Cryptnox root. Proof-of-possession alone is necessary but not sufficient."""
        return self.attested and bool(self.chain and self.chain.verified)

    def to_dict(self) -> dict[str, object]:
        return {
            "genuine": self.genuine,
            "proof_of_possession": self.attested,
            "proof_detail": self.attest_detail,
            "leaf_subject": self.leaf_subject,
            "chain": self.chain.to_dict() if self.chain else None,
            "notes": self.notes,
        }


def verify_attestation_signature(leaf_der: bytes, nonce: bytes, signature: bytes) -> bool:
    """True iff ``signature`` is a valid ECDSA(SHA-256) over ``ATTEST_LABEL || nonce``
    under the leaf certificate's public key."""
    leaf = x509.load_der_x509_certificate(leaf_der)
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False
    try:
        pub.verify(signature, c.ATTEST_LABEL + nonce, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _order_intermediates(leaf_der: bytes, pool_ders: list[bytes]) -> list[bytes]:
    """Order a pool of candidate intermediate CAs into a leaf->root chain, following
    issuer links and dropping duplicates / self-issued roots. ``verify_attestation_chain``
    needs the intermediates pre-ordered; the pool (card issuer + pinned + --anchors) is
    not, so we walk it here."""
    pool = {der: x509.load_der_x509_certificate(der) for der in pool_ders}
    ordered: list[bytes] = []
    current = x509.load_der_x509_certificate(leaf_der)
    used: set[bytes] = set()
    while True:
        nxt = next(
            (
                der
                for der, cert in pool.items()
                if der not in used
                and cert.subject == current.issuer
                and cert.subject != cert.issuer  # a self-issued CA is a root, not an intermediate
            ),
            None,
        )
        if nxt is None:
            break
        ordered.append(nxt)
        used.add(nxt)
        current = pool[nxt]
    return ordered


def verify_genuineness(
    *,
    leaf_der: bytes | None,
    nonce: bytes,
    signature: bytes | None,
    card_issuer_der: bytes | None,
    roots: list[bytes],
    intermediates: list[bytes],
) -> GenuinenessResult:
    """Combine proof-of-possession + chain verification into one result.

    ``card_issuer_der`` is the issuer cert read off the card (GET CERT intermediate);
    it joins the pinned ``intermediates`` in a pool that is then ordered leaf->root so
    the chain can climb even when only the root is pinned. ``roots``/``intermediates``
    are the pinned anchors from the trust store (plus any the caller loaded)."""
    notes: list[str] = []
    if leaf_der is None:
        return GenuinenessResult(
            attested=False,
            attest_detail="no device leaf certificate on card (applet not personalized)",
            chain=None,
            notes=["Genuineness applet present but carries no device leaf certificate."],
        )

    leaf_subject = x509.load_der_x509_certificate(leaf_der).subject.rfc4514_string()

    if signature is None:
        attested, detail = False, "ATTEST failed (card returned no signature)"
    elif verify_attestation_signature(leaf_der, nonce, signature):
        attested = True
        detail = f"card signed the {len(nonce)}-byte nonce; verifies against leaf key"
    else:
        attested, detail = False, "ATTEST signature did NOT verify against the leaf key"

    pool = ([card_issuer_der] if card_issuer_der else []) + list(intermediates)
    inter = _order_intermediates(leaf_der, pool)
    chain = verify_attestation_chain(leaf_der, inter, roots)
    if not roots:
        notes.append(
            "No pinned Cryptnox genuineness root bundled - chain cannot be anchored. "
            "Drop the root PEM into src/cryptnox_id_cli/trust/genuine/ (or pass "
            "--anchors DIR) to complete the chain."
        )
    return GenuinenessResult(
        attested=attested,
        attest_detail=detail,
        chain=chain,
        leaf_subject=leaf_subject,
        notes=notes,
    )
