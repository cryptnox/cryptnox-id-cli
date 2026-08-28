"""PIV pre-personalization profiles: a validated model that compiles to a BULK
PUT DATA ADMIN payload. ``cryptnox-default`` reproduces the applet's own reference
profile byte-for-byte.

Profiles are user-facing YAML (names, not magic numbers); the model resolves names
to the applet's byte values and validates against what THIS applet supports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv import preperso as pp
from cryptnox_id_cli.transport.errors import CryptnoxError

# Name <-> byte maps (user-friendly YAML).
MECHANISMS = {
    "AES128": 0x08,
    "AES192": 0x0A,
    "AES256": 0x0C,
    "RSA2048": 0x07,
    "RSA3072": 0x05,
    "ECCP256": 0x11,
    "ECCP384": 0x14,
    "CS2": 0x27,
    "CS7": 0x2E,
}
MODES = {
    "NEVER": pp.MODE_NEVER,
    "PIN": pp.MODE_PIN,
    "OCC": pp.MODE_OCC,
    "SM": pp.MODE_SM,
    "VCI": pp.MODE_VCI,
    "VCI_PIN": pp.MODE_VCI_PIN,
    "ALWAYS": pp.MODE_ALWAYS,
}
ROLES = {
    "AUTHENTICATE": pp.ROLE_AUTHENTICATE,
    "KEY_ESTABLISH": pp.ROLE_KEY_ESTABLISH,
    "SIGN": pp.ROLE_SIGN,
}
ATTRS = {
    "PERMIT_EXTERNAL": pp.ATTR_PERMIT_EXTERNAL,
    "PERMIT_MUTUAL": pp.ATTR_PERMIT_MUTUAL,
    "IMPORTABLE": pp.ATTR_IMPORTABLE,
    "RSA_CRT": pp.ATTR_RSA_CRT,
}
CHARSETS = {"numeric": 0x00, "alpha": 0x01, "alpha_invariant": 0x02, "raw": 0x03}

_REV_MECH = {v: k for k, v in MECHANISMS.items()}


class ProfileError(CryptnoxError):
    """Profile parse/validation failure (aggregates all messages)."""

    code = "profile_error"
    exit_code = 8


@dataclass
class PinPolicy:
    min_length: int
    max_length: int
    retries: int
    charset: int = 0x00


@dataclass
class ContainerDef:
    oid: bytes
    name: str
    contact: int
    contactless: int
    admin_key: int = c.KEYREF_ADMIN


@dataclass
class KeyDef:
    ref: int
    name: str
    mechanism: int
    role: int
    contact: int
    contactless: int
    attributes: int
    admin_key: int | None = None


@dataclass
class PivProfile:
    name: str
    mode: str
    admin_key_ref: int
    admin_mechanism: int
    pin: PinPolicy
    puk: PinPolicy
    containers: list[ContainerDef] = field(default_factory=list)
    keys: list[KeyDef] = field(default_factory=list)

    # -- compile ------------------------------------------------------------ #
    def build_ops(self) -> list[tuple[str, bytes]]:
        """Ordered (label, op-bytes): containers, PIN, PUK, then keys."""
        ops: list[tuple[str, bytes]] = []
        for ct in self.containers:
            ops.append(
                (
                    f"container {ct.name} {ct.oid.hex().upper()}",
                    pp.create_container(ct.oid, ct.contact, ct.contactless, admin_key=ct.admin_key),
                )
            )
        ops.append(
            (
                "verifier PIN (80)",
                pp.create_verifier(
                    c.REF_PIV_PIN,
                    pp.MODE_ALWAYS,
                    pp.MODE_NEVER,
                    self.pin.min_length,
                    self.pin.max_length,
                    self.pin.retries,
                    0,
                    charset=self.pin.charset,
                ),
            )
        )
        ops.append(
            (
                "verifier PUK (81)",
                pp.create_verifier(
                    c.REF_PUK,
                    pp.MODE_ALWAYS,
                    pp.MODE_NEVER,
                    self.puk.min_length,
                    self.puk.max_length,
                    self.puk.retries,
                    0,
                    charset=self.puk.charset,
                ),
            )
        )
        for k in self.keys:
            ops.append(
                (
                    f"key {k.name} ({k.ref:02X})",
                    pp.create_key(
                        k.ref,
                        k.contact,
                        k.contactless,
                        k.mechanism,
                        k.role,
                        k.attributes,
                        admin_key=k.admin_key,
                    ),
                )
            )
        return ops

    def build_payload(self) -> bytes:
        """The full BULK PUT DATA ADMIN CDATA."""
        return pp.build_bulk([op for _, op in self.build_ops()])

    # -- validation --------------------------------------------------------- #
    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.admin_mechanism not in (0x08, 0x0A, 0x0C):
            errors.append(
                "admin key mechanism must be AES-128/192/256 (this applet: 9B is AES-only)"
            )
        for label, pol, floor in (("PIN", self.pin, 6), ("PUK", self.puk, 6)):
            if pol.min_length < floor:
                errors.append(f"{label} min_length {pol.min_length} < minimum {floor}")
            if pol.max_length < pol.min_length:
                errors.append(f"{label} max_length < min_length")
            if not (0 <= pol.retries <= 10):
                errors.append(f"{label} retries {pol.retries} out of range (max 10)")
        for k in self.keys:
            if k.ref == c.KEYREF_ADMIN:
                continue  # admin key checked above
            if k.mechanism not in c.SUPPORTED_ALGORITHMS:
                name = _REV_MECH.get(k.mechanism, hex(k.mechanism))
                errors.append(f"key {k.ref:02X} mechanism {name} not supported by this applet")
        if not self.containers and not self.keys:
            errors.append("profile defines no containers or keys")
        return errors

    def ensure_valid(self) -> None:
        errs = self.validate()
        if errs:
            raise ProfileError("; ".join(errs))

    # -- (de)serialization -------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        def mode_name(v: int) -> str:
            return next((n for n, x in MODES.items() if x == v), hex(v))

        return {
            "name": self.name,
            "mode": self.mode,
            "admin": {
                "key_ref": f"{self.admin_key_ref:02X}",
                "mechanism": _REV_MECH.get(self.admin_mechanism, hex(self.admin_mechanism)),
            },
            "pin": {
                "min": self.pin.min_length,
                "max": self.pin.max_length,
                "retries": self.pin.retries,
                "charset": next(
                    (n for n, x in CHARSETS.items() if x == self.pin.charset), self.pin.charset
                ),
            },
            "puk": {
                "min": self.puk.min_length,
                "max": self.puk.max_length,
                "retries": self.puk.retries,
                "charset": next(
                    (n for n, x in CHARSETS.items() if x == self.puk.charset), self.puk.charset
                ),
            },
            "containers": [
                {
                    "oid": ct.oid.hex().upper(),
                    "name": ct.name,
                    "contact": mode_name(ct.contact),
                    "contactless": mode_name(ct.contactless),
                }
                for ct in self.containers
            ],
            "keys": [
                {
                    "ref": f"{k.ref:02X}",
                    "name": k.name,
                    "mechanism": _REV_MECH.get(k.mechanism, hex(k.mechanism)),
                    "role": _role_name(k.role),
                    "contact": mode_name(k.contact),
                    "contactless": mode_name(k.contactless),
                    "attributes": [n for n, x in ATTRS.items() if k.attributes & x],
                }
                for k in self.keys
            ],
        }

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False)


def _mode(v: Any) -> int:
    if isinstance(v, int):
        return v
    key = str(v).upper()
    if key not in MODES:
        raise ProfileError(f"unknown access mode {v!r}")
    return MODES[key]


def _role(v: Any) -> int:
    """Parse a key role: one name, a '+'-combined string ('SIGN+AUTHENTICATE'),
    a list of names, or a raw int. The applet tests roles as a bitmask."""
    if isinstance(v, int):
        return v
    parts = [str(p) for p in v] if isinstance(v, (list, tuple)) else str(v).split("+")
    out = 0
    for part in parts:
        key = part.strip().upper()
        if key not in ROLES:
            raise ProfileError(f"unknown key role {part.strip()!r}")
        out |= ROLES[key]
    return out


def _role_name(v: int) -> str:
    exact = next((n for n, x in ROLES.items() if x == v), None)
    if exact:
        return exact
    bits = [n for n, x in ROLES.items() if v & x]
    if bits and sum(ROLES[n] for n in bits) == v:
        return "+".join(bits)
    return hex(v)


def _attrs(values: Any) -> int:
    out = 0
    for a in values or []:
        key = str(a).upper()
        if key not in ATTRS:
            raise ProfileError(f"unknown key attribute {a!r}")
        out |= ATTRS[key]
    return out


def from_dict(d: dict[str, Any]) -> PivProfile:
    try:
        admin = d["admin"]
        pin, puk = d["pin"], d["puk"]
        prof = PivProfile(
            name=str(d["name"]),
            mode=str(d.get("mode", "production")),
            admin_key_ref=int(str(admin["key_ref"]), 16),
            admin_mechanism=MECHANISMS[str(admin["mechanism"]).upper()],
            pin=PinPolicy(
                int(pin["min"]),
                int(pin["max"]),
                int(pin["retries"]),
                CHARSETS.get(str(pin.get("charset", "numeric")), 0x00),
            ),
            puk=PinPolicy(
                int(puk["min"]),
                int(puk["max"]),
                int(puk["retries"]),
                CHARSETS.get(str(puk.get("charset", "numeric")), 0x00),
            ),
            containers=[
                ContainerDef(
                    bytes.fromhex(str(ct["oid"])),
                    str(ct.get("name", "")),
                    _mode(ct["contact"]),
                    _mode(ct["contactless"]),
                )
                for ct in d.get("containers", [])
            ],
            keys=[
                KeyDef(
                    int(str(k["ref"]), 16),
                    str(k.get("name", "")),
                    MECHANISMS[str(k["mechanism"]).upper()],
                    _role(k["role"]),
                    _mode(k["contact"]),
                    _mode(k["contactless"]),
                    _attrs(k.get("attributes")),
                    admin_key=int(str(k["admin_key"]), 16) if k.get("admin_key") else None,
                )
                for k in d.get("keys", [])
            ],
        )
    except (KeyError, ValueError) as exc:
        raise ProfileError(f"invalid profile: {exc}") from exc
    return prof


def from_yaml(text: str) -> PivProfile:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ProfileError("profile must be a YAML mapping")
    return from_dict(data)


# --------------------------------------------------------------------------- #
# Built-in profiles                                                            #
# --------------------------------------------------------------------------- #
def _cryptnox_default() -> PivProfile:
    """Byte-exact to the applet's own reference profile (AES-256 admin, ECC-P256)."""
    A = pp.MODE_ALWAYS
    N = pp.MODE_NEVER
    P = pp.MODE_PIN
    VCI = pp.MODE_VCI
    VCIP = pp.MODE_VCI_PIN
    containers = [
        ContainerDef(bytes.fromhex("5FC102"), "chuid", A, A),
        ContainerDef(bytes.fromhex("5FC107"), "ccc", A, VCI),
        ContainerDef(bytes.fromhex("5FC105"), "auth-cert", A, VCI),
        ContainerDef(bytes.fromhex("5FC101"), "card-auth-cert", A, A),
        ContainerDef(bytes.fromhex("5FC10A"), "sign-cert", A, VCI),
        ContainerDef(bytes.fromhex("5FC10B"), "keymgmt-cert", A, VCI),
        ContainerDef(bytes.fromhex("5FC106"), "security-object", A, VCI),
        ContainerDef(bytes.fromhex("5FC103"), "fingerprints", P, VCIP),
        ContainerDef(bytes.fromhex("5FC108"), "facial", P, VCIP),
        ContainerDef(bytes.fromhex("5FC109"), "printed", P, VCIP),
    ]
    keys = [
        KeyDef(
            c.KEYREF_ADMIN,
            "admin",
            0x0C,
            pp.ROLE_AUTHENTICATE,
            A,
            N,
            pp.ATTR_IMPORTABLE | pp.ATTR_PERMIT_MUTUAL | pp.ATTR_PERMIT_EXTERNAL,
        ),
        KeyDef(c.KEYREF_PIV_AUTH, "auth", 0x11, pp.ROLE_AUTHENTICATE, P, N, pp.ATTR_IMPORTABLE),
        KeyDef(c.KEYREF_DIGITAL_SIGNATURE, "sign", 0x11, pp.ROLE_SIGN, P, N, pp.ATTR_IMPORTABLE),
        KeyDef(
            c.KEYREF_KEY_MANAGEMENT,
            "keymgmt",
            0x11,
            pp.ROLE_KEY_ESTABLISH,
            P,
            N,
            pp.ATTR_IMPORTABLE,
        ),
        KeyDef(
            c.KEYREF_CARD_AUTH, "card-auth", 0x11, pp.ROLE_AUTHENTICATE, A, A, pp.ATTR_IMPORTABLE
        ),
    ]
    return PivProfile(
        name="cryptnox-default",
        mode="production",
        admin_key_ref=c.KEYREF_ADMIN,
        admin_mechanism=0x0C,
        pin=PinPolicy(6, 8, 6, 0x00),
        puk=PinPolicy(8, 8, 6, 0x00),
        containers=containers,
        keys=keys,
    )


def _developer() -> PivProfile:
    prof = _cryptnox_default()
    prof.name = "developer"
    prof.mode = "developer-not-for-production"
    return prof


def _npivp_lab() -> PivProfile:
    prof = _cryptnox_default()
    prof.name = "npivp-lab"
    prof.mode = "lab"
    return prof


def _ms_logon() -> PivProfile:
    """Windows smart-card logon / Remote Desktop. This applet dispatches PKI
    challenge signing on ROLE_SIGN only, so the 9A (PIV Authentication) keys get
    SIGN+AUTHENTICATE — that is what makes client authentication (PKINIT, SSH,
    TLS) and on-card CSR generation work on 9A. A second, importable RSA-2048
    object coexists on 9A for AD-issued credentials (CSR -> CA -> import, or
    PKCS#12 import). The role must NOT include KEY_ESTABLISH: the applet routes
    challenge-response to key transport before signing."""
    prof = _cryptnox_default()
    prof.name = "ms-logon"
    auth_role = pp.ROLE_SIGN | pp.ROLE_AUTHENTICATE
    for k in prof.keys:
        if k.ref == c.KEYREF_PIV_AUTH:
            k.role = auth_role
    prof.keys.append(
        KeyDef(
            c.KEYREF_PIV_AUTH,
            "auth-rsa",
            MECHANISMS["RSA2048"],
            auth_role,
            pp.MODE_PIN,
            pp.MODE_NEVER,
            pp.ATTR_IMPORTABLE | pp.ATTR_RSA_CRT,
        )
    )
    return prof


def _ssh() -> PivProfile:
    """SSH auth (raw public key or SSH user certificates) via PKCS#11
    (``ssh-agent`` / OpenSC), on either path. 9A (PIV Authentication) gets
    SIGN added to its role -- the applet only dispatches challenge-response
    signing on ROLE_SIGN, so plain AUTHENTICATE-only 9A cannot produce the
    signature SSH needs. 9C cannot substitute: OpenSC's PIV driver treats key
    reference 0x9C as requiring re-authentication before every signature
    (PKCS#11 CKA_ALWAYS_AUTHENTICATE, matching the PIV spec's non-repudiation
    convention for that slot), which neither ssh-agent nor ssh's own PKCS#11
    client can satisfy. Unlike ms-logon, no second RSA object is added on 9A:
    there is no AD-issued-credential path to support here."""
    prof = _cryptnox_default()
    prof.name = "ssh"
    for k in prof.keys:
        if k.ref == c.KEYREF_PIV_AUTH:
            k.role = pp.ROLE_SIGN | pp.ROLE_AUTHENTICATE
    return prof


_BUILTINS = {
    "cryptnox-default": _cryptnox_default,
    "npivp-lab": _npivp_lab,
    "developer": _developer,
    "ssh": _ssh,
    "ms-logon": _ms_logon,
}


def builtin(name: str) -> PivProfile:
    if name not in _BUILTINS:
        raise ProfileError(f"unknown built-in profile {name!r}; choose from {', '.join(_BUILTINS)}")
    return _BUILTINS[name]()


def builtin_names() -> list[str]:
    return list(_BUILTINS)
