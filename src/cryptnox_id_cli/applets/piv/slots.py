"""PIV key-reference (slot) registry for this applet."""

from __future__ import annotations

from dataclasses import dataclass

from cryptnox_id_cli.applets.piv import constants as c


@dataclass(frozen=True)
class PivSlot:
    ref: int
    name: str
    usage: str

    @property
    def ref_hex(self) -> str:
        return f"{self.ref:02X}"


PIV_SLOTS: list[PivSlot] = [
    PivSlot(c.KEYREF_PIV_AUTH, "authentication", "PIV authentication (9A)"),
    PivSlot(c.KEYREF_DIGITAL_SIGNATURE, "digital_signature", "Document signing (9C)"),
    PivSlot(c.KEYREF_KEY_MANAGEMENT, "key_management", "Key management / decryption (9D)"),
    PivSlot(c.KEYREF_CARD_AUTH, "card_authentication", "Card authentication (9E)"),
    PivSlot(c.KEYREF_ADMIN, "management", "Management/admin key, AES only (9B)"),
    PivSlot(c.KEYREF_SECURE_MESSAGING, "secure_messaging", "PIV secure messaging (04)"),
]

# Retired key-management slots 82..95.
PIV_SLOTS += [
    PivSlot(
        ref,
        f"retired_{ref - c.KEYREF_RETIRED_FIRST + 1:02d}",
        f"Retired key management ({ref:02X})",
    )
    for ref in range(c.KEYREF_RETIRED_FIRST, c.KEYREF_RETIRED_LAST + 1)
]

SLOTS_BY_REF: dict[int, PivSlot] = {s.ref: s for s in PIV_SLOTS}


def slot_by_ref(ref: int) -> PivSlot | None:
    return SLOTS_BY_REF.get(ref)
