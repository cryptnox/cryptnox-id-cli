"""Keyless inventory of the PIV applet: version, status, config, and the structure
(key objects, verifiers, containers) with their access rules.

OpenFIPS201 answers GET DATA for the extended identifiers ``2F47xx`` without any
authentication. Only the structure listing can be withheld, by the applet's
``restrict-enumeration`` config flag (``6986``); version, status and config always
answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv.objects import PIV_OBJECTS
from cryptnox_id_cli.applets.piv.slots import slot_by_ref
from cryptnox_id_cli.transport.errors import StatusWordError
from cryptnox_id_cli.util import tlv

if TYPE_CHECKING:
    from cryptnox_id_cli.applets.piv.piv import PivApplet

# Extended data identifiers: the two bytes after 0x2F.
ID_VERSION = 0x4756
ID_STATUS = 0x4753
ID_CONFIG = 0x4743
ID_CONTAINER = 0x4744
ID_KEY = 0x474B
ID_VERIFIER = 0x4750

TAG_DATA = 0x53

# GlobalPlatform application life-cycle state as the applet reports it.
STATE_SELECTABLE = 0x07
STATE_SECURED = 0x0F  # applet-specific: SECURE APPLET (finalize) done

SW_NOT_FOUND = 0x6A82
SW_NOT_ALLOWED = 0x6986

APPLET_TRUE = 0xA5

# Access-mode byte: the low five bits are the cardholder condition (0x1F = ALWAYS),
# the high bits are independent qualifiers.
_MODE_ALWAYS = 0x1F
_MODE_BITS = ((0x01, "PIN"), (0x02, "PIN-ALWAYS"), (0x04, "OCC"))
_MODE_SM = 0x40
_MODE_VCI = 0x60
_MODE_USER_ADMIN = 0x80

_ROLE_BITS = ((0x01, "AUTHENTICATE"), (0x02, "KEY-ESTABLISH"), (0x04, "SIGN"))
_ATTR_BITS = (
    (0x04, "PERMIT-EXTERNAL"),
    (0x08, "PERMIT-MUTUAL"),
    (0x10, "IMPORTABLE"),
    (0x20, "RSA-CRT"),
)

VERIFIER_NAMES = {
    0x00: "global PIN",
    0x80: "PIN",
    0x81: "PUK",
    0x96: "OCC primary",
    0x97: "OCC secondary",
    0x98: "pairing code",
}

_CONTAINER_NAMES = {o.oid: o.name for o in PIV_OBJECTS}

# Every slot with more than one mechanism still fits.
_MAX_INDEX = 128


def describe_state(state: int) -> str:
    return {STATE_SELECTABLE: "SELECTABLE", STATE_SECURED: "SECURED"}.get(state, f"{state:#04x}")


def describe_mode(mode: int) -> str:
    """Words for an access-mode byte, e.g. ``PIN``, ``ALWAYS``, ``NEVER, SM``."""
    base = mode & _MODE_ALWAYS
    parts = (
        ["ALWAYS"]
        if base == _MODE_ALWAYS
        else [name for bit, name in _MODE_BITS if base & bit] or ["NEVER"]
    )
    if mode & _MODE_VCI == _MODE_VCI:
        parts.append("VCI")
    elif mode & _MODE_SM:
        parts.append("SM")
    if mode & _MODE_USER_ADMIN:
        parts.append("USER-ADMIN")
    return ", ".join(parts)


def role_names(role: int) -> list[str]:
    return [name for bit, name in _ROLE_BITS if role & bit]


def attribute_names(attributes: int) -> list[str]:
    return [name for bit, name in _ATTR_BITS if attributes & bit]


def _fields(data: bytes) -> dict[int, bytes]:
    """The primitive fields inside the 0x53 wrapper, by tag."""
    nodes = tlv.parse(data, recurse=False)
    wrapper = next((n for n in nodes if n.tag == TAG_DATA), None)
    inner = tlv.parse(wrapper.value, recurse=False) if wrapper is not None else nodes
    return {n.tag: n.value for n in inner}


def _byte(fields: dict[int, bytes], tag: int, default: int = 0) -> int:
    value = fields.get(tag)
    return value[0] if value else default


def _flag(fields: dict[int, bytes], tag: int) -> bool:
    return _byte(fields, tag) != 0


@dataclass(frozen=True)
class AppletVersion:
    label: str
    major: int
    minor: int
    revision: int
    debug: bool

    @property
    def version(self) -> str:
        return f"{self.major}.{self.minor}.{self.revision}"

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "version": self.version,
            "debug": self.debug,
        }


@dataclass(frozen=True)
class AppletStatus:
    state: int
    operator_roles: int
    operator_id: int
    immediate: bool
    sm_established: bool
    vci_established: bool
    contactless: bool
    fips_mode: bool

    @property
    def secured(self) -> bool:
        return self.state == STATE_SECURED

    def to_dict(self) -> dict[str, object]:
        return {
            "state": describe_state(self.state),
            "state_raw": f"{self.state:02X}",
            "secured": self.secured,
            "operator_roles": f"{self.operator_roles:02X}",
            "operator_id": f"{self.operator_id:02X}",
            "immediate": self.immediate,
            "sm_established": self.sm_established,
            "vci_established": self.vci_established,
            "contactless": self.contactless,
            "fips_mode": self.fips_mode,
        }


@dataclass(frozen=True)
class AppletConfig:
    restrict_contactless_global: bool
    restrict_contactless_admin: bool
    restrict_enumeration: bool
    restrict_get_random: bool
    vci_compatibility: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "restrict_contactless_global": self.restrict_contactless_global,
            "restrict_contactless_admin": self.restrict_contactless_admin,
            "restrict_enumeration": self.restrict_enumeration,
            "restrict_get_random": self.restrict_get_random,
            "vci_compatibility": self.vci_compatibility,
        }


@dataclass(frozen=True)
class KeyObject:
    ref: int
    mode_contact: int
    mode_contactless: int
    admin_key: int
    mechanism: int
    role: int
    attributes: int

    @property
    def slot_name(self) -> str:
        slot = slot_by_ref(self.ref)
        return slot.name if slot else "-"

    @property
    def mechanism_name(self) -> str:
        return c.ALGORITHMS.get(self.mechanism, f"{self.mechanism:#04x}")

    def to_dict(self) -> dict[str, object]:
        return {
            "ref": f"{self.ref:02X}",
            "slot": self.slot_name,
            "mechanism": self.mechanism_name,
            "mechanism_raw": f"{self.mechanism:02X}",
            "roles": role_names(self.role),
            "attributes": attribute_names(self.attributes),
            "mode_contact": describe_mode(self.mode_contact),
            "mode_contact_raw": f"{self.mode_contact:02X}",
            "mode_contactless": describe_mode(self.mode_contactless),
            "mode_contactless_raw": f"{self.mode_contactless:02X}",
            "admin_key": f"{self.admin_key:02X}",
        }


@dataclass(frozen=True)
class VerifierObject:
    ref: int
    mode_contact: int
    mode_contactless: int
    min_length: int
    max_length: int
    retries_contact: int
    retries_contactless: int
    charset: int
    history: int
    sequence: int
    repeat: int
    restrict_update: bool

    @property
    def name(self) -> str:
        return VERIFIER_NAMES.get(self.ref, "-")

    def to_dict(self) -> dict[str, object]:
        return {
            "ref": f"{self.ref:02X}",
            "name": self.name,
            "mode_contact": describe_mode(self.mode_contact),
            "mode_contact_raw": f"{self.mode_contact:02X}",
            "mode_contactless": describe_mode(self.mode_contactless),
            "mode_contactless_raw": f"{self.mode_contactless:02X}",
            "min_length": self.min_length,
            "max_length": self.max_length,
            "retries_contact": self.retries_contact,
            "retries_contactless": self.retries_contactless,
            "charset": f"{self.charset:02X}",
            "history": self.history,
            "sequence": self.sequence,
            "repeat": self.repeat,
            "restrict_update": self.restrict_update,
        }


@dataclass(frozen=True)
class ContainerObject:
    oid: bytes
    mode_contact: int
    mode_contactless: int
    admin_key: int

    @property
    def oid_hex(self) -> str:
        return self.oid.hex().upper()

    @property
    def name(self) -> str:
        return _CONTAINER_NAMES.get(self.oid, "-")

    def to_dict(self) -> dict[str, object]:
        return {
            "oid": self.oid_hex,
            "name": self.name,
            "mode_contact": describe_mode(self.mode_contact),
            "mode_contact_raw": f"{self.mode_contact:02X}",
            "mode_contactless": describe_mode(self.mode_contactless),
            "mode_contactless_raw": f"{self.mode_contactless:02X}",
            "admin_key": f"{self.admin_key:02X}",
        }


def parse_version(data: bytes) -> AppletVersion:
    f = _fields(data)
    return AppletVersion(
        label=f.get(0x80, b"").decode("ascii", "replace"),
        major=_byte(f, 0x81),
        minor=_byte(f, 0x82),
        revision=_byte(f, 0x83),
        debug=_flag(f, 0x84),
    )


def parse_status(data: bytes) -> AppletStatus:
    f = _fields(data)
    return AppletStatus(
        state=_byte(f, 0x80),
        operator_roles=_byte(f, 0x81),
        operator_id=_byte(f, 0x82),
        immediate=_flag(f, 0x83),
        sm_established=_flag(f, 0x84),
        vci_established=_flag(f, 0x85),
        contactless=_flag(f, 0x86),
        fips_mode=_flag(f, 0x87),
    )


def parse_config(data: bytes) -> AppletConfig:
    f = _fields(data)
    return AppletConfig(
        restrict_contactless_global=_flag(f, 0x80),
        restrict_contactless_admin=_flag(f, 0x81),
        restrict_enumeration=_flag(f, 0x82),
        restrict_get_random=_flag(f, 0x83),
        vci_compatibility=_flag(f, 0x84),
    )


def parse_key(data: bytes) -> KeyObject:
    f = _fields(data)
    return KeyObject(
        ref=_byte(f, 0x8B),
        mode_contact=_byte(f, 0x8C),
        mode_contactless=_byte(f, 0x8D),
        admin_key=_byte(f, 0x91),
        mechanism=_byte(f, 0x8E),
        role=_byte(f, 0x8F),
        attributes=_byte(f, 0x90),
    )


def parse_verifier(data: bytes) -> VerifierObject:
    f = _fields(data)
    return VerifierObject(
        ref=_byte(f, 0x8B),
        mode_contact=_byte(f, 0x8C),
        mode_contactless=_byte(f, 0x8D),
        min_length=_byte(f, 0x8E),
        max_length=_byte(f, 0x8F),
        retries_contact=_byte(f, 0x90),
        retries_contactless=_byte(f, 0x91),
        charset=_byte(f, 0x92),
        history=_byte(f, 0x93),
        sequence=_byte(f, 0x94),
        repeat=_byte(f, 0x95),
        restrict_update=_byte(f, 0x96) == APPLET_TRUE,
    )


def parse_container(data: bytes) -> ContainerObject:
    f = _fields(data)
    return ContainerObject(
        oid=bytes(f.get(0x8B, b"")),
        mode_contact=_byte(f, 0x8C),
        mode_contactless=_byte(f, 0x8D),
        admin_key=_byte(f, 0x91),
    )


def read_version(piv: PivApplet) -> AppletVersion | None:
    resp = piv.get_data_extended(ID_VERSION)
    return parse_version(resp.data) if resp.ok else None


def read_status(piv: PivApplet) -> AppletStatus | None:
    resp = piv.get_data_extended(ID_STATUS)
    return parse_status(resp.data) if resp.ok else None


def read_config(piv: PivApplet) -> AppletConfig | None:
    resp = piv.get_data_extended(ID_CONFIG)
    return parse_config(resp.data) if resp.ok else None


def _enumerate(piv: PivApplet, ident: int, parse):  # noqa: ANN001, ANN202
    """Every entry of one object kind, or ``None`` when the applet withholds them."""
    out = []
    for index in range(_MAX_INDEX):
        resp = piv.get_data_extended(ident, index)
        if resp.sw == SW_NOT_FOUND:
            break
        if resp.sw == SW_NOT_ALLOWED:
            return None
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context=f"GET DATA 2F{ident:04X}")
        out.append(parse(resp.data))
    return out


@dataclass(frozen=True)
class Inventory:
    version: AppletVersion | None
    status: AppletStatus | None
    config: AppletConfig | None
    keys: list[KeyObject] | None
    verifiers: list[VerifierObject] | None
    containers: list[ContainerObject] | None

    @property
    def restricted(self) -> bool:
        """True when the applet withheld the structure (restrict-enumeration set)."""
        return self.keys is None or self.verifiers is None or self.containers is None

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version.to_dict() if self.version else None,
            "status": self.status.to_dict() if self.status else None,
            "config": self.config.to_dict() if self.config else None,
            "restricted": self.restricted,
            "keys": [k.to_dict() for k in self.keys] if self.keys is not None else None,
            "verifiers": (
                [v.to_dict() for v in self.verifiers] if self.verifiers is not None else None
            ),
            "containers": (
                [o.to_dict() for o in self.containers] if self.containers is not None else None
            ),
        }


def read_inventory(piv: PivApplet) -> Inventory:
    """Everything the selected applet reports about itself without authentication."""
    return Inventory(
        version=read_version(piv),
        status=read_status(piv),
        config=read_config(piv),
        keys=_enumerate(piv, ID_KEY, parse_key),
        verifiers=_enumerate(piv, ID_VERIFIER, parse_verifier),
        containers=_enumerate(piv, ID_CONTAINER, parse_container),
    )
