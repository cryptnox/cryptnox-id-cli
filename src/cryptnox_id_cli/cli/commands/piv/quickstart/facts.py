# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What quickstart reads from the card before it plans."""

from __future__ import annotations

import contextlib

from cryptnox_id_cli.applets.piv import inventory as inventory_mod
from cryptnox_id_cli.applets.piv import keyimport, verifier
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.state import StateDetector, counts_as_set
from cryptnox_id_cli.transport.errors import CryptnoxError

from ..primitives import (
    _ALGORITHM_NAMES,
    SLOT_CERT_OBJECT,
    _certificate_mechanism,
    _read_cert_der,
    _select,
    _signing_siblings,
)
from .plan import CardFacts


def _collect_quickstart_facts(session, ref: int, mech: int) -> tuple[CardFacts, str]:
    """Read-only detection pass: lifecycle state, verifier status, object presence,
    and the applet's own key-object listing (the non-destructive (slot, mechanism)
    probe stands in when the listing is withheld)."""
    st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
    note = verifier.refused_note(st.piv_pin, st.piv_puk)
    if note is None and st.piv_apt is not None:
        note = verifier.unread_note(st.piv_pin, st.piv_puk)
    if note:
        raise CryptnoxError(f"quickstart cannot tell whether the PIN and PUK are set: {note}")
    piv = _select(session)
    key_objects = None
    verifiers = None
    with contextlib.suppress(CryptnoxError):
        key_objects = inventory_mod.read_keys(piv)
        verifiers = inventory_mod.read_verifiers(piv)
    pin_configured = counts_as_set(st.piv_pin)
    puk_configured = counts_as_set(st.piv_puk)
    key_object_can_sign: bool | None = None
    signing_siblings: tuple[str, ...] = ()
    if key_objects is None:
        probe = session.transmit(keyimport.probe_apdu(ref, mech), context="probe quickstart")
        key_object_present = probe.sw != 0x6A86
        structure_present = key_object_present or pin_configured or puk_configured
    else:
        match = next((k for k in key_objects if k.ref == ref and k.mechanism == mech), None)
        key_object_present = match is not None
        if match is not None:
            key_object_can_sign = preperso_mod.key_signs(match.role, match.mechanism)
        signing_siblings = tuple(_signing_siblings(key_objects, ref, mech))
        structure_present = bool(key_objects) or bool(verifiers)
    # "Certificate present" means a PARSEABLE certificate: a created-but-unused
    # container is zero-length per SP 800-73 4.1.1, and factory containers can
    # hold non-certificate placeholder data - neither should stop quickstart
    # from provisioning the slot.
    obj_name = SLOT_CERT_OBJECT.get(ref)
    cert_der = _read_cert_der(piv, obj_name) if obj_name is not None else None
    cert_present = False
    other_cert: str | None = None
    other_cert_replaceable = False
    if cert_der is not None:
        cert_mech = _certificate_mechanism(cert_der)
        if cert_mech == mech and key_object_present:
            cert_present = True
        else:
            other_cert = "unrecognised"
            if cert_mech is not None:
                other_cert = _ALGORITHM_NAMES.get(cert_mech, other_cert)
            if cert_mech == mech:  # its key is not on the card
                other_cert_replaceable = True
            elif cert_mech is not None and key_objects is not None:
                cert_key = next(
                    (k for k in key_objects if k.ref == ref and k.mechanism == cert_mech), None
                )
                other_cert_replaceable = cert_key is None or not preperso_mod.key_signs(
                    cert_key.role, cert_key.mechanism
                )
    objs = st.piv_objects or {}
    facts = CardFacts(
        pin_configured=pin_configured,
        puk_configured=puk_configured,
        structure_present=structure_present,
        key_object_present=key_object_present,
        cert_present=cert_present,
        chuid_present=objs.get("chuid"),
        ccc_present=objs.get("ccc"),
        key_object_can_sign=key_object_can_sign,
        signing_siblings=signing_siblings,
        applet_secured=bool(st.piv_secured),
        other_cert=other_cert,
        other_cert_replaceable=other_cert_replaceable,
        listing_withheld=key_objects is None,
    )
    return facts, st.piv.label
