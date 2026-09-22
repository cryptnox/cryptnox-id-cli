"""Local verification of a key-attestation certificate returned by the service.

The service says it generated a key on the card and returns a certificate for
it. This module decides how much of that to believe, from evidence this tool
can check itself:

* the chain terminates at a pinned trust anchor (never at anything that came
  with the result);
* the subject's serial number is the card's CPLC UID, read locally;
* the ``cryptnoxPivSlot`` extension names the slot that was asked for;
* the ``cryptnoxAttestTrustModel`` extension carries the server-driven value;
* the certified public key equals the one stored in the card's attestation
  container, read locally after the operation.

What it cannot check is stated as plainly: the key's generation on the card is
the service's claim, witnessed by nothing the relay can authenticate.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .. import trust
from ..crypto.attestation import verify_attestation_chain

#: Cryptnox private enterprise arc and the two key-attestation extensions.
OID_PIV_SLOT = x509.ObjectIdentifier("1.3.6.1.4.1.55934.1.1.1")
OID_TRUST_MODEL = x509.ObjectIdentifier("1.3.6.1.4.1.55934.1.1.2")

#: Trust model value for a key generated on the card under the service's direction.
TRUST_MODEL_SERVER_DRIVEN = 2


@dataclass
class AttestVerification:
    """Everything checked locally about a returned attestation certificate."""

    chain_verified: bool
    chain: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    subject: str = ""
    issuer: str = ""
    leaf_sha256: str = ""
    serial_number: str | None = None
    serial_number_matches_card: bool | None = None
    slot: int | None = None
    slot_matches: bool | None = None
    trust_model: int | None = None
    trust_model_matches: bool | None = None
    public_key_matches_card: bool | None = None

    @property
    def verified(self) -> bool:
        """True only when the chain holds and every binding that could be checked holds."""
        bindings = (
            self.serial_number_matches_card,
            self.slot_matches,
            self.trust_model_matches,
            self.public_key_matches_card,
        )
        return self.chain_verified and all(b is True for b in bindings)

    def to_dict(self) -> dict[str, object]:
        return {
            "verified": self.verified,
            "chain_verified": self.chain_verified,
            "chain": self.chain,
            "reasons": self.reasons,
            "subject": self.subject,
            "issuer": self.issuer,
            "leaf_sha256": self.leaf_sha256,
            "serial_number": self.serial_number,
            "serial_number_matches_card": self.serial_number_matches_card,
            "slot": f"{self.slot:02X}" if self.slot is not None else None,
            "slot_matches": self.slot_matches,
            "trust_model": self.trust_model,
            "trust_model_matches": self.trust_model_matches,
            "public_key_matches_card": self.public_key_matches_card,
        }


def leaf_from_pem(pem: str | bytes) -> bytes:
    """DER of the first certificate in a PEM blob."""
    raw = pem.encode("utf-8") if isinstance(pem, str) else bytes(pem)
    certs = x509.load_pem_x509_certificates(raw)
    if not certs:
        raise ValueError("no certificate in the PEM data")
    return certs[0].public_bytes(serialization.Encoding.DER)


def der_integer(value: bytes) -> int | None:
    """Decode a DER-encoded INTEGER, or ``None`` if the bytes are not one."""
    if len(value) < 3 or value[0] != 0x02:
        return None
    length = value[1]
    if length == 0 or length > 4 or len(value) != 2 + length:
        return None
    return int.from_bytes(value[2 : 2 + length], "big", signed=True)


def extension_integer(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> int | None:
    """The INTEGER value of a private extension, or ``None`` when absent or malformed."""
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None
    value = ext.value
    if isinstance(value, x509.UnrecognizedExtension):
        return der_integer(value.value)
    return None


def _spki(der: bytes) -> bytes:
    return (
        x509.load_der_x509_certificate(der)
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def verify_returned_attestation(
    leaf_der: bytes,
    *,
    slot: int,
    cplc_uid: str | None,
    on_card_der: bytes | None,
    anchors: tuple[list[bytes], list[bytes]] | None = None,
    at_time: datetime.datetime | None = None,
) -> AttestVerification:
    """Check a returned attestation leaf against the pinned anchors and the card.

    ``anchors`` is ``(roots, intermediates)`` in DER; the bundled store is used
    when omitted. ``on_card_der`` is the certificate read from the card's
    attestation container after the operation, or ``None`` if it could not be
    read; the public-key binding is then reported as unchecked.
    """
    roots, intermediates = anchors if anchors is not None else trust.load_anchors()
    chain = verify_attestation_chain(leaf_der, intermediates, roots, at_time=at_time)
    cert = x509.load_der_x509_certificate(leaf_der)
    out = AttestVerification(
        chain_verified=chain.verified,
        chain=chain.chain,
        reasons=list(chain.reasons),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        leaf_sha256=hashlib.sha256(leaf_der).hexdigest().upper(),
    )

    serials = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    serial = str(serials[0].value) if serials else None
    out.serial_number = serial
    if serial is None:
        out.serial_number_matches_card = False
        out.reasons.append("certificate subject carries no serialNumber")
    elif cplc_uid:
        out.serial_number_matches_card = serial.strip().upper() == cplc_uid.strip().upper()
        if not out.serial_number_matches_card:
            out.reasons.append("certificate serialNumber is not this card's CPLC UID")

    out.slot = extension_integer(cert, OID_PIV_SLOT)
    if out.slot is None:
        out.slot_matches = False
        out.reasons.append("certificate carries no cryptnoxPivSlot extension")
    else:
        out.slot_matches = out.slot == slot
        if not out.slot_matches:
            out.reasons.append(
                f"certificate attests slot {out.slot:02X}, the operation asked for {slot:02X}"
            )

    out.trust_model = extension_integer(cert, OID_TRUST_MODEL)
    if out.trust_model is None:
        out.trust_model_matches = False
        out.reasons.append("certificate carries no cryptnoxAttestTrustModel extension")
    else:
        out.trust_model_matches = out.trust_model == TRUST_MODEL_SERVER_DRIVEN
        if not out.trust_model_matches:
            out.reasons.append(
                f"certificate trust model is {out.trust_model}, expected "
                f"{TRUST_MODEL_SERVER_DRIVEN} (server-driven on-card generation)"
            )

    if on_card_der is not None:
        out.public_key_matches_card = _spki(leaf_der) == _spki(on_card_der)
        if not out.public_key_matches_card:
            out.reasons.append(
                "the certified public key differs from the certificate stored on the card"
            )

    return out
