"""The card manager (issuer security domain): lifecycle, loaded content, the JCOP fuse.

Everything here runs inside a secure channel opened to the card manager; the builders
return plain APDUs and the caller's channel wraps them.

Fusing a card is the manufacturer's last step and cannot be undone: the JCOP sample
modules and then the configuration module are deleted, which seals the chip's
configuration, the lifecycle moves to SECURED, and the card-manager key is replaced.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..transport.apdu import APDU, Response
from ..util import tlv

OP_READY = 0x01
INITIALIZED = 0x07
SECURED = 0x0F
CARD_LOCKED = 0x7F
TERMINATED = 0xFF

LIFECYCLE_NAMES = {
    OP_READY: "OP_READY",
    INITIALIZED: "INITIALIZED",
    SECURED: "SECURED",
    CARD_LOCKED: "CARD_LOCKED",
    TERMINATED: "TERMINATED",
}


@dataclass(frozen=True)
class JcopModule:
    key: str
    label: str
    aid: bytes


#: Deleted in this order. The configuration module goes last, as in the factory flow.
FUSE_MODULES: tuple[JcopModule, ...] = (
    JcopModule(
        "egovaccelerators",
        "egovaccelerators sample module",
        bytes.fromhex("D276000085304A434F506E"),
    ),
    JcopModule("fips", "fips sample module", bytes.fromhex("D276000085304A434F504D4F4407")),
    JcopModule("piv", "piv sample module", bytes.fromhex("D276000085304A434F5076")),
    JcopModule(
        "configuration", "configuration module", bytes.fromhex("D276000085304A434F504D4F4406")
    ),
)
CONFIG_MODULE_AID = FUSE_MODULES[-1].aid

SCOPE_ISD = 0x80
SCOPE_APPLICATIONS = 0x40
SCOPE_LOAD_FILES_AND_MODULES = 0x10

_TAG_ENTRY = 0xE3
_TAG_AID = 0x4F
_TAG_LIFECYCLE = 0x9F70
_TAG_MODULE_AID = 0x84
_SW_MORE_DATA = 0x6310

Send = Callable[[APDU], Response]


def lifecycle_name(state: int | None) -> str:
    if state is None:
        return "unknown"
    return LIFECYCLE_NAMES.get(state, f"0x{state:02X}")


def get_status_apdu(scope: int, *, tlv_format: bool = True, next_occurrence: bool = False) -> APDU:
    p2 = (0x02 if tlv_format else 0x00) | (0x01 if next_occurrence else 0x00)
    return APDU(0x80, 0xF2, scope, p2, data=bytes([_TAG_AID, 0x00]), le=256)


def delete_aid_apdu(aid: bytes) -> APDU:
    """DELETE an object and the objects related to it (P2 = 80), as ``gp --delete -f``."""
    return APDU(0x80, 0xE4, 0x00, 0x80, data=bytes([_TAG_AID, len(aid)]) + aid, le=256)


def set_card_lifecycle_apdu(state: int) -> APDU:
    return APDU(0x80, 0xF0, SCOPE_ISD, state)


@dataclass(frozen=True)
class StatusEntry:
    aid: bytes
    lifecycle: int | None
    modules: tuple[bytes, ...] = ()


def parse_status_tlv(data: bytes) -> list[StatusEntry]:
    entries = []
    for node in tlv.parse(data):
        if node.tag != _TAG_ENTRY:
            continue
        aid = tlv.find(node.children, _TAG_AID)
        if aid is None:
            continue
        state = tlv.find(node.children, _TAG_LIFECYCLE)
        modules = tuple(child.value for child in node.children if child.tag == _TAG_MODULE_AID)
        entries.append(
            StatusEntry(aid.value, state.value[0] if state and state.value else None, modules)
        )
    return entries


def parse_status_legacy(data: bytes, scope: int) -> list[StatusEntry]:
    """The pre-GlobalPlatform-2.2 layout: length, AID, lifecycle, then per scope either a
    privileges byte or a count of module AIDs."""
    entries = []
    off = 0
    while off < len(data):
        n = data[off]
        aid = data[off + 1 : off + 1 + n]
        off += 1 + n
        state = data[off] if off < len(data) else None
        off += 1
        modules: list[bytes] = []
        if scope in (SCOPE_ISD, SCOPE_APPLICATIONS):
            off += 1
        elif scope == SCOPE_LOAD_FILES_AND_MODULES and off < len(data):
            count = data[off]
            off += 1
            for _ in range(count):
                m = data[off]
                modules.append(data[off + 1 : off + 1 + m])
                off += 1 + m
        entries.append(StatusEntry(bytes(aid), state, tuple(modules)))
    return entries


def read_status(send: Send, scope: int) -> list[StatusEntry] | None:
    """GET STATUS over every occurrence; ``None`` when the card answers neither format."""
    resp = send(get_status_apdu(scope))
    if resp.sw in (0x6A86, 0x6D00):
        legacy = send(get_status_apdu(scope, tlv_format=False))
        if legacy.sw == 0x6A88:
            return []
        if not (legacy.ok or legacy.sw == _SW_MORE_DATA):
            return None
        return parse_status_legacy(legacy.data, scope)
    if resp.sw == 0x6A88:
        return []
    entries: list[StatusEntry] = []
    while True:
        if not (resp.ok or resp.sw == _SW_MORE_DATA):
            return None
        entries.extend(parse_status_tlv(resp.data))
        if resp.sw != _SW_MORE_DATA:
            return entries
        resp = send(get_status_apdu(scope, next_occurrence=True))


@dataclass(frozen=True)
class CardState:
    lifecycle: int | None
    loaded: frozenset[bytes] | None

    def present(self, aid: bytes) -> bool | None:
        return None if self.loaded is None else aid in self.loaded

    def to_dict(self) -> dict[str, object]:
        return {
            "lifecycle": lifecycle_name(self.lifecycle),
            "jcop_modules": {m.key: self.present(m.aid) for m in FUSE_MODULES},
        }


def read_card_state(send: Send) -> CardState:
    isd = read_status(send, SCOPE_ISD)
    lifecycle = isd[0].lifecycle if isd else None
    files = read_status(send, SCOPE_LOAD_FILES_AND_MODULES)
    apps = read_status(send, SCOPE_APPLICATIONS)
    if files is None and apps is None:
        return CardState(lifecycle, None)
    loaded: set[bytes] = set()
    for entry in (files or []) + (apps or []):
        loaded.add(entry.aid)
        loaded.update(entry.modules)
    return CardState(lifecycle, frozenset(loaded))
