"""The composite card-state model.

The plan lists a flat vocabulary (PivPrePersonalized, FidoBlockedByOS, …). Because
the three applets are independent, we model the state as one sub-state per applet
plus card presence; each enum exposes the plan's CamelCase ``label``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from cryptnox_id_cli.applets.piv.apt import APTInfo
from cryptnox_id_cli.applets.piv.piv import PinStatus


class CardPresence(str, Enum):
    UNKNOWN = "unknown"
    NO_CARD = "no_card"
    PRESENT = "present"

    @property
    def label(self) -> str:
        return {"unknown": "Unknown", "no_card": "NoCard", "present": "CardPresent"}[self.value]


class PivState(str, Enum):
    UNKNOWN = "unknown"
    NOT_PRESENT = "not_present"
    SELECTABLE = "selectable"
    PRE_PERSONALIZED = "pre_personalized"
    PARTIALLY_PERSONALIZED = "partially_personalized"
    PERSONALIZED = "personalized"
    SECURED = "secured"

    @property
    def label(self) -> str:
        return {
            "unknown": "Unknown",
            "not_present": "PivNotPresent",
            "selectable": "PivSelectable",
            "pre_personalized": "PivPrePersonalized",
            "partially_personalized": "PivPartiallyPersonalized",
            "personalized": "PivPersonalized",
            "secured": "PivSecured",
        }[self.value]


class FidoState(str, Enum):
    UNKNOWN = "unknown"
    NOT_PRESENT = "not_present"
    BLOCKED_BY_OS = "blocked_by_os"
    SELECTABLE = "selectable"
    PERSONALIZED = "personalized"

    @property
    def label(self) -> str:
        return {
            "unknown": "Unknown",
            "not_present": "FidoNotPresent",
            "blocked_by_os": "FidoBlockedByOS",
            "selectable": "FidoSelectable",
            "personalized": "FidoPersonalized",
        }[self.value]


class DesfireState(str, Enum):
    UNKNOWN = "unknown"
    NOT_PRESENT = "not_present"
    REACHABLE = "reachable"
    NEEDS_CONTACTLESS_READER = "needs_contactless_reader"
    # Already on a contactless interface, yet DESFire gave no native answer - a
    # different situation from "wrong interface": the reader is the right kind, so
    # the advice must not be "get a contactless reader".
    NO_ANSWER_CONTACTLESS = "no_answer_contactless"

    @property
    def label(self) -> str:
        return {
            "unknown": "Unknown",
            "not_present": "DesfireNotPresent",
            "reachable": "DesfireReachable",
            "needs_contactless_reader": "DesfireNeedsContactlessReader",
            "no_answer_contactless": "DesfireNoAnswerContactless",
        }[self.value]


class GenuinenessState(str, Enum):
    UNKNOWN = "unknown"
    NOT_PRESENT = "not_present"
    PRESENT = "present"  # selectable but no device leaf certificate
    PERSONALIZED = "personalized"  # device leaf present -> attestable
    NEEDS_CONTACT_READER = "needs_contact_reader"  # contact-only; not seen over contactless

    @property
    def label(self) -> str:
        return {
            "unknown": "Unknown",
            "not_present": "GenuinenessNotPresent",
            "present": "GenuinenessPresent",
            "personalized": "GenuinenessPersonalized",
            "needs_contact_reader": "GenuinenessNeedsContactReader",
        }[self.value]


@dataclass
class CardState:
    presence: CardPresence = CardPresence.UNKNOWN
    atr: bytes | None = None
    piv: PivState = PivState.UNKNOWN
    fido: FidoState = FidoState.UNKNOWN
    desfire: DesfireState = DesfireState.UNKNOWN
    genuine: GenuinenessState = GenuinenessState.UNKNOWN
    piv_apt: APTInfo | None = None
    piv_pin: PinStatus | None = None
    piv_puk: PinStatus | None = None
    piv_objects: dict[str, bool] = field(default_factory=dict)
    fido_versions: list[str] | None = None
    desfire_version: dict[str, object] | None = None
    genuine_leaf_subject: str | None = None
    genuine_info: str | None = None  # raw GET INFO bytes, hex
    notes: list[str] = field(default_factory=list)

    @property
    def atr_hex(self) -> str | None:
        return self.atr.hex().upper() if self.atr is not None else None

    def to_dict(self) -> dict[str, object]:
        return {
            "presence": self.presence.label,
            "atr": self.atr_hex,
            "piv": {
                "state": self.piv.label,
                "apt": self.piv_apt.to_dict() if self.piv_apt else None,
                "pin": self.piv_pin.to_dict() if self.piv_pin else None,
                "puk": self.piv_puk.to_dict() if self.piv_puk else None,
                "objects_present": self.piv_objects,
            },
            "fido": {"state": self.fido.label, "versions": self.fido_versions},
            "desfire": {"state": self.desfire.label, "version": self.desfire_version},
            "genuine": {
                "state": self.genuine.label,
                "leaf_subject": self.genuine_leaf_subject,
                "info": self.genuine_info,
            },
            "notes": self.notes,
        }
