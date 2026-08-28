"""Read-only card-state detector. Probes each independent applet defensively so
that one failing probe never aborts the others. Never mutates the card."""

from __future__ import annotations

import contextlib

from cryptnox_id_cli.applets.genuine.genuine import GenuinenessApplet
from cryptnox_id_cli.applets.piv import objects as piv_obj
from cryptnox_id_cli.applets.piv.constants import REF_PIV_PIN, REF_PUK
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.state.model import (
    CardPresence,
    CardState,
    DesfireState,
    FidoState,
    GenuinenessState,
    PivState,
)
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import (
    CardAccessDeniedError,
    CryptnoxError,
    TransportError,
)
from cryptnox_id_cli.transport.pcsc import CardSession, is_contactless_interface

# FIDO AID + CTAP getInfo; the full FIDO module arrives in Phase 7.
FIDO_AID = bytes.fromhex("A0000006472F0001")
CTAP_GETINFO = bytes([0x04])

_MANDATORY = ("chuid", "ccc", "discovery")
_PROBE_OBJECTS = (
    "chuid",
    "ccc",
    "discovery",
    "security-object",
    "auth-cert",
    "card-auth-cert",
    "sign-cert",
    "keymgmt-cert",
    "printed",
)


class StateDetector:
    def __init__(
        self,
        session: CardSession,
        *,
        probe_fido: bool = True,
        probe_desfire: bool = True,
        probe_genuine: bool = True,
    ) -> None:
        self.s = session
        self.probe_fido = probe_fido
        self.probe_desfire = probe_desfire
        self.probe_genuine = probe_genuine

    def _safe_atr(self) -> bytes | None:
        try:
            return self.s.atr
        except Exception:  # pragma: no cover - defensive
            return None

    def detect(self) -> CardState:
        st = CardState()
        try:
            st.atr = self.s.atr
            st.presence = CardPresence.PRESENT
        except Exception:  # pragma: no cover - defensive
            st.presence = CardPresence.UNKNOWN
        # DESFire first: it is the card's DEFAULT applet, so it must be probed
        # before any SELECT leaves a JavaCard applet answering the interface.
        if self.probe_desfire:
            self._detect_desfire(st)
        self._detect_piv(st)
        if self.probe_fido:
            self._detect_fido(st)
        if self.probe_genuine:
            self._detect_genuineness(st)
        return st

    # ------------------------------------------------------------------ PIV #
    def _detect_piv(self, st: CardState) -> None:
        piv = PivApplet(self.s)
        try:
            apt = piv.try_select()
        except CryptnoxError as exc:
            st.piv = PivState.UNKNOWN
            st.notes.append(f"PIV select error: {exc}")
            return
        if apt is None:
            st.piv = PivState.NOT_PRESENT
            return
        st.piv_apt = apt
        st.piv = PivState.SELECTABLE

        with contextlib.suppress(CryptnoxError):
            st.piv_pin = piv.pin_status(REF_PIV_PIN)
            st.piv_puk = piv.pin_status(REF_PUK)

        present: dict[str, bool] = {}
        for name in _PROBE_OBJECTS:
            obj = piv_obj.object_by_name(name)
            if obj is None:
                continue
            try:
                present[name] = piv.object_present(obj.oid)
            except CryptnoxError:
                present[name] = False
        st.piv_objects = present

        any_verifier = bool(
            (st.piv_pin and st.piv_pin.configured) or (st.piv_puk and st.piv_puk.configured)
        )
        any_object = any(present.values())
        mandatory_present = all(present.get(n) for n in _MANDATORY)

        if not any_verifier and not any_object:
            st.piv = PivState.PRE_PERSONALIZED
        elif mandatory_present and st.piv_pin and st.piv_pin.configured:
            st.piv = PivState.PERSONALIZED
        else:
            st.piv = PivState.PARTIALLY_PERSONALIZED
        if st.piv in (PivState.PRE_PERSONALIZED, PivState.PARTIALLY_PERSONALIZED):
            st.notes.append(
                "PIV SECURED (locked) state cannot be confirmed read-only; "
                "it requires opening the admin channel (Phase 3.5)."
            )

    # ----------------------------------------------------------------- FIDO #
    def _detect_fido(self, st: CardState) -> None:
        try:
            resp = self.s.transmit(
                APDU(0x00, 0xA4, 0x04, 0x00, data=FIDO_AID, le=256), context="SELECT FIDO"
            )
        except CardAccessDeniedError:
            st.fido = FidoState.BLOCKED_BY_OS
            st.notes.append(
                "FIDO2 selection blocked by the OS (Windows). Run from an Administrator "
                "terminal to manage FIDO2."
            )
            return
        except TransportError as exc:
            st.fido = FidoState.UNKNOWN
            st.notes.append(f"FIDO2 select error: {exc}")
            return
        if resp.sw == 0x6A82:
            st.fido = FidoState.NOT_PRESENT
            return
        if not resp.ok:
            st.fido = FidoState.UNKNOWN
            st.notes.append(f"FIDO2 select returned SW={resp.sw:04X}.")
            return
        st.fido = FidoState.SELECTABLE
        try:
            gi = self.s.transmit(
                APDU(0x80, 0x10, 0x00, 0x00, data=CTAP_GETINFO, le=256), context="CTAP getInfo"
            )
        except (CardAccessDeniedError, TransportError) as exc:
            st.notes.append(f"CTAP getInfo error: {exc}")
            return
        if gi.ok and gi.data and gi.data[0] == 0x00:
            st.fido = FidoState.PERSONALIZED
            with contextlib.suppress(Exception):
                import cbor2

                info = cbor2.loads(gi.data[1:])
                versions = info.get(1) if isinstance(info, dict) else None
                if isinstance(versions, list):
                    st.fido_versions = [str(v) for v in versions]

    # ------------------------------------------------------------- Genuine #
    def _reset_selection(self) -> None:
        """Best-effort return to the card's default-selected applet (empty SELECT).

        The JCRE hands a SELECT for an *unknown* AID to the currently selected applet
        as an ordinary command, so after a successful FIDO probe the U2F applet - not
        the card manager - answers the genuineness SELECT, with whatever SW it likes
        (6D00 observed on Windows; nothing guarantees even that). Resetting first
        makes the card manager the responder, so absent really means absent. Failure
        here is harmless: the SW mapping in ``GenuinenessApplet.select`` remains as a
        backstop."""
        with contextlib.suppress(CardAccessDeniedError, TransportError, CryptnoxError):
            resp = self.s.transmit(APDU(0x00, 0xA4, 0x04, 0x00, le=256), context="SELECT default")
            if resp.sw == 0x6700:  # same case-4 quirk as the applet SELECTs: retry without Le
                self.s.transmit(APDU(0x00, 0xA4, 0x04, 0x00), context="SELECT default (no Le)")

    def _detect_genuineness(self, st: CardState) -> None:
        """Detect the Cryptnox genuineness / attestation applet (read-only): SELECT,
        then GET INFO + GET CERT to tell present-but-blank from personalized. The
        applet is contact-only, so 6A82 over a contactless interface (DESFire
        reachable) is reported as NEEDS_CONTACT_READER, not a plain absence.

        Runs after the FIDO probe, so the selection state is reset first - otherwise
        the verdict depends on which applet a preceding probe left selected."""
        self._reset_selection()
        gen = GenuinenessApplet(self.s)
        try:
            present = gen.try_select()
        except CryptnoxError as exc:
            st.genuine = GenuinenessState.UNKNOWN
            st.notes.append(f"Genuineness select error: {exc}")
            return
        if not present:
            if st.desfire == DesfireState.REACHABLE:
                st.genuine = GenuinenessState.NEEDS_CONTACT_READER
                st.notes.append(
                    "Genuineness applet is contact-only; it does not answer over a "
                    "contactless interface. Use a contact reader to check it."
                )
            else:
                st.genuine = GenuinenessState.NOT_PRESENT
            return

        with contextlib.suppress(CryptnoxError):
            info = gen.get_info()
            if info is not None:
                st.genuine_info = info.hex

        leaf_der: bytes | None = None
        with contextlib.suppress(CryptnoxError):
            leaf_der = gen.get_cert()
        if leaf_der:
            st.genuine = GenuinenessState.PERSONALIZED
            with contextlib.suppress(Exception):
                from cryptography import x509

                st.genuine_leaf_subject = x509.load_der_x509_certificate(
                    leaf_der
                ).subject.rfc4514_string()
        else:
            st.genuine = GenuinenessState.PRESENT
        st.notes.append(
            "Genuineness reported from the card only; run `genuine verify` to prove "
            "the device key (ATTEST) and the certificate chain."
        )

    # -------------------------------------------------------------- DESFire #
    def _detect_desfire(self, st: CardState) -> None:
        from cryptnox_id_cli.applets.mifare.desfire import (
            DesfireNotSelectedError,
            DesfireTransport,
        )

        try:
            version = DesfireTransport(self.s).get_version()
        except DesfireNotSelectedError:
            # Same wire outcome, two different diagnoses: on a contact interface the
            # reader is the wrong kind; on a contactless one the reader is right and
            # something else is wrong (card not freshly presented, or the reader does
            # not pass native DESFire APDUs). Recommending "use a contactless reader"
            # to someone already on one points them away from the actual problem.
            if is_contactless_interface(getattr(self.s, "reader_name", None), self._safe_atr()):
                st.desfire = DesfireState.NO_ANSWER_CONTACTLESS
                st.notes.append(
                    "DESFire did not answer on this contactless interface. Re-present the "
                    "card (no JavaCard applet selected), and check the reader passes native "
                    "DESFire APDUs (ACS ACR1252/1552 verified)."
                )
            else:
                st.desfire = DesfireState.NEEDS_CONTACTLESS_READER
                st.notes.append(
                    "DESFire EV2 (the default MIFARE applet) did not answer on this "
                    "interface; use a DESFire-capable contactless PC/SC reader."
                )
        except (CardAccessDeniedError, TransportError, CryptnoxError, ValueError):
            st.desfire = DesfireState.UNKNOWN
            st.notes.append("DESFire probe failed; state unknown.")
        else:
            st.desfire = DesfireState.REACHABLE
            st.desfire_version = version.to_dict()
