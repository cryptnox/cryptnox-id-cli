"""Pinned trust anchors for offline attestation-chain verification.

PEM certificates dropped into ``trust/genuine/`` are bundled into the package (and the
PyInstaller binary) and loaded here. Anchors are classified by inspection, not by filename:

* self-issued (issuer == subject) **CA** certificates  -> **roots** (pinned anchors)
* non-self-issued **CA** certificates                  -> **intermediates**

A relying party trusts a chain only because it terminates at one of these pinned roots — never
because a root happens to appear in a chain read off a card. If the directory is empty, the
loaders return empty lists and callers must report that the chain cannot be verified rather
than silently passing.

The bundled set is the Cryptnox production PKI: ``CN=CRYPTNOX ROOT CA`` (the anchor) plus its
intermediates. Only the root grants trust; the intermediates are shipped so chain building
works offline when a card omits part of its chain.
"""

from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_GENUINE_PKG = "cryptnox_id_cli.trust"
_GENUINE_DIR = "genuine"

#: Point this at a directory of PEM anchors to use a trust store without rebuilding
#: the package - e.g. anchors fetched from the Cryptnox PKI, or a lab/dev CA. Its
#: certificates are added to whatever ships bundled; it never disables the bundled set.
TRUST_DIR_ENV = "CRYPTNOX_TRUST_DIR"


def _parse_pem_dir(root) -> list[x509.Certificate]:
    """Parse every ``*.pem`` in a directory (each file may hold >1 certificate)."""
    out: list[x509.Certificate] = []
    if not root.is_dir():
        return out
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.name.lower().endswith(".pem") and entry.is_file():
            out.extend(x509.load_pem_x509_certificates(entry.read_bytes()))
    return out


def _load_all(extra_dir: str | os.PathLike[str] | None = None) -> list[x509.Certificate]:
    """Bundled anchors, plus any from ``$CRYPTNOX_TRUST_DIR`` and ``extra_dir``."""
    out = _parse_pem_dir(files(_GENUINE_PKG).joinpath(_GENUINE_DIR))
    for candidate in (os.environ.get(TRUST_DIR_ENV), extra_dir):
        if candidate:
            out.extend(_parse_pem_dir(Path(candidate)))
    return out


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def load_anchors(
    extra_dir: str | os.PathLike[str] | None = None,
) -> tuple[list[bytes], list[bytes]]:
    """Return ``(roots_der, intermediates_der)`` from the configured trust store.

    Sources, in order and additive: the bundled ``trust/genuine/``, the directory named
    by ``$CRYPTNOX_TRUST_DIR``, then ``extra_dir``. Duplicates are collapsed, so the same
    anchor supplied twice is harmless. Roots are self-issued CAs (the pinned anchors);
    intermediates are the remaining CAs. An empty result means callers must report that
    the chain cannot be verified - never that it passed.
    """
    roots: list[bytes] = []
    intermediates: list[bytes] = []
    seen: set[bytes] = set()
    for cert in _load_all(extra_dir):
        if not _is_ca(cert):
            continue  # ignore non-CA material in the trust dir
        der = _der(cert)
        if der in seen:
            continue
        seen.add(der)
        (roots if cert.issuer == cert.subject else intermediates).append(der)
    return roots, intermediates
