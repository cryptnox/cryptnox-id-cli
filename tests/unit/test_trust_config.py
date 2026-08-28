"""Configurable trust store: bundled anchors plus $CRYPTNOX_TRUST_DIR / an explicit dir.

The anchor set decides whether an attestation chain can be verified at all, so the
loader must stay additive, classify roots vs intermediates by inspection, collapse
duplicates, and contribute nothing from a directory that holds no CA material - a
chain no anchor covers has to report "cannot verify" instead of passing silently.

The bundled Cryptnox PKI is a non-empty baseline, so tests here assert the *delta* a
configured directory adds rather than an absolute result.
"""

from __future__ import annotations

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli import trust

_NB = datetime.datetime(2020, 1, 1)
_NA = datetime.datetime(2045, 1, 1)


def _ca(subject: str, issuer_name=None, issuer_key=None, *, ca: bool = True):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    self_signed = issuer_key is None
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name if self_signed else issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key if self_signed else issuer_key, hashes.SHA256())
    )
    return key, name, cert


def _write(dirpath, filename: str, *certs) -> None:
    pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    (dirpath / filename).write_bytes(pem)


def _bundled():
    """The baseline every other case is measured against: bundled anchors only."""
    saved = os.environ.pop(trust.TRUST_DIR_ENV, None)
    try:
        return trust.load_anchors()
    finally:
        if saved is not None:
            os.environ[trust.TRUST_DIR_ENV] = saved


def test_empty_dir_adds_nothing(tmp_path, monkeypatch):
    """An empty trust dir contributes no anchors - it cannot widen what is trusted."""
    monkeypatch.setenv(trust.TRUST_DIR_ENV, str(tmp_path))  # empty dir
    assert trust.load_anchors() == _bundled()


def test_env_dir_supplies_root_and_intermediate(tmp_path, monkeypatch):
    root_key, root_name, root = _ca("TEST ROOT")
    _, _, sub = _ca("TEST SUB", root_name, root_key)
    _write(tmp_path, "anchors.pem", root, sub)

    monkeypatch.setenv(trust.TRUST_DIR_ENV, str(tmp_path))
    roots, inters = trust.load_anchors()
    assert root.public_bytes(serialization.Encoding.DER) in roots  # self-issued -> root
    assert sub.public_bytes(serialization.Encoding.DER) in inters  # issued by root


def test_explicit_dir_argument_is_honoured(tmp_path, monkeypatch):
    monkeypatch.delenv(trust.TRUST_DIR_ENV, raising=False)
    _, _, root = _ca("EXPLICIT ROOT")
    _write(tmp_path, "root.pem", root)

    roots, _ = trust.load_anchors(tmp_path)
    assert root.public_bytes(serialization.Encoding.DER) in roots


def test_duplicate_anchor_from_two_sources_is_collapsed(tmp_path, monkeypatch):
    _, _, root = _ca("DUPE ROOT")
    env_dir, arg_dir = tmp_path / "env", tmp_path / "arg"
    env_dir.mkdir()
    arg_dir.mkdir()
    _write(env_dir, "root.pem", root)
    _write(arg_dir, "root.pem", root)  # same certificate, both places

    monkeypatch.setenv(trust.TRUST_DIR_ENV, str(env_dir))
    roots, _ = trust.load_anchors(arg_dir)
    assert roots.count(root.public_bytes(serialization.Encoding.DER)) == 1


def test_non_ca_material_is_ignored(tmp_path, monkeypatch):
    _, _, leaf = _ca("NOT A CA", ca=False)
    _write(tmp_path, "leaf.pem", leaf)

    monkeypatch.setenv(trust.TRUST_DIR_ENV, str(tmp_path))
    assert trust.load_anchors() == _bundled()  # a leaf never becomes an anchor


def test_missing_directory_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv(trust.TRUST_DIR_ENV, str(tmp_path / "does-not-exist"))
    assert trust.load_anchors() == _bundled()


def test_bundled_set_is_the_cryptnox_pki(monkeypatch):
    """Lock the pinned set: exactly one root, every anchor chaining to it, no dev PKI.

    A second self-issued root appearing here would silently widen what the CLI accepts,
    so the count is asserted, not just membership.
    """
    monkeypatch.delenv(trust.TRUST_DIR_ENV, raising=False)
    roots, inters = trust.load_anchors()

    assert len(roots) == 1, "more than one pinned root would widen trust"
    root = x509.load_der_x509_certificate(roots[0])
    assert root.subject.rfc4514_string() == "CN=CRYPTNOX ROOT CA,O=CRYPTNOX SA,ST=GENEVA,C=CH"

    # Every bundled intermediate must be reachable from the root by issuer links; an
    # anchor that chains nowhere is either a mistake or an unrelated CA.
    certs = [x509.load_der_x509_certificate(d) for d in inters]
    reachable = {root.subject}
    for _ in range(len(certs)):
        reachable |= {c.subject for c in certs if c.issuer in reachable}
    unreachable = [c for c in certs if c.subject not in reachable]
    assert not unreachable, [c.subject.rfc4514_string() for c in unreachable]

    for cert in [root, *certs]:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert "(DEV)" not in cn, f"dev PKI certificate bundled as an anchor: {cn}"
