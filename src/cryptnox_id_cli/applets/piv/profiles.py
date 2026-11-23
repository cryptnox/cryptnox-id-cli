# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

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
from cryptnox_id_cli.applets.piv.verifier import VALUE_LENGTH
from cryptnox_id_cli.transport.errors import CryptnoxError

# Retry caps stay at or under 15: a 63Cx answer reports no more.
PIN_MIN_LENGTH_FIPS = 6
PIN_RETRY_CAP_FIPS = 10
PIN_MIN_LENGTH = 4
PIN_RETRY_CAP = 15
PIN_MAX_LENGTH = VALUE_LENGTH

# Name <-> byte maps (user-friendly YAML).
MECHANISMS = {
    "AES128": 0x08,
    "AES192": 0x0A,
    "AES256": 0x0C,
    "RSA2048": 0x07,
    "RSA3072": 0x05,
    "RSA4096": 0x16,
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
    "SM_PIN": pp.MODE_SM_PIN,
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


# How many of a PIN's tries the contactless interface may use in the built-in
# profile for logon over NFC: wrong PINs over the air stop there, and the rest
# stay for the contact interface.
CONTACTLESS_RETRIES_NFC = 3


@dataclass
class PinPolicy:
    min_length: int
    max_length: int
    retries: int
    charset: int = 0x00
    #: NEVER: the value is accepted on the contact interface only. ALWAYS: also over
    #: the contactless interface, in clear; only the build with FIPS mode off takes it.
    contactless: int = pp.MODE_NEVER
    #: how many of ``retries`` the contactless interface may use. At 0 the applet
    #: answers 6983 to every value presented over contactless.
    contactless_retries: int = 0

    @property
    def over_contactless(self) -> bool:
        return self.contactless != pp.MODE_NEVER


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
    #: the source file named a mode VCI or VCI_PIN, whose bytes changed after 1.1
    names_vci: bool = False
    #: False for a profile written for the applet build with FIPS mode off: the PIN
    #: and PUK bounds are then that build's, and the FIPS-mode build refuses it.
    fips_mode: bool = True

    def pin_bounds(self) -> tuple[int, int]:
        """(minimum length, most retries) a PIN or PUK policy of this profile may ask for."""
        if self.fips_mode:
            return PIN_MIN_LENGTH_FIPS, PIN_RETRY_CAP_FIPS
        return PIN_MIN_LENGTH, PIN_RETRY_CAP

    def fips_mode_note(self) -> str | None:
        """What a profile for the build with FIPS mode off asks of the card, else ``None``."""
        if self.fips_mode:
            return None
        return (
            f"profile '{self.name}' is written for the PIV applet build with FIPS mode off "
            "(fips_mode: false). The FIPS-mode build refuses what goes beyond its bounds: a "
            "PIN or PUK shorter than 6, more than 15 retries, a PIN or PUK over the "
            "contactless interface without secure messaging."
        )

    def contactless_pin_warning(self) -> str | None:
        """The warning for a profile whose PIN or PUK is usable over contactless, else ``None``."""
        names = [
            label for label, pol in (("PIN", self.pin), ("PUK", self.puk)) if pol.over_contactless
        ]
        if not names:
            return None
        return (
            f"profile '{self.name}' makes the {' and the '.join(names)} usable over the "
            "contactless interface without secure messaging: the value crosses the radio "
            "link in clear. The setting is permanent once written."
        )

    def vci_warning(self) -> str | None:
        """The warning for a profile file that uses the VCI mode names, else ``None``."""
        if not self.names_vci:
            return None
        return (
            f"profile '{self.name}' uses VCI or VCI_PIN, which mean the applet's VCI modes "
            "(0x60, 0x61). Files written by version 1.1 used these names for 0x40 and 0x41, "
            "now called SM and SM_PIN; change such a file before loading it."
        )

    def can_sign(self, ref: int) -> bool:
        """Whether any key object this profile creates on ``ref`` can sign."""
        return any(k.ref == ref and pp.key_signs(k.role, k.mechanism) for k in self.keys)

    def piv_auth_warning(self) -> str | None:
        """The warning for a profile whose 9A key cannot sign, else ``None``."""
        if not any(k.ref == c.KEYREF_PIV_AUTH for k in self.keys):
            return None
        if self.can_sign(c.KEYREF_PIV_AUTH):
            return None
        return (
            f"profile '{self.name}' gives slot 9A a key that can authenticate but not sign. "
            "macOS login, SSH, TLS client authentication and Windows logon sign with 9A; "
            "for those, use the ssh or ms-logon profile. A key's role cannot be changed "
            "once written."
        )

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
                    self.pin.contactless,
                    self.pin.min_length,
                    self.pin.max_length,
                    self.pin.retries,
                    self.pin.contactless_retries,
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
                    self.puk.contactless,
                    self.puk.min_length,
                    self.puk.max_length,
                    self.puk.retries,
                    self.puk.contactless_retries,
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
        floor, cap = self.pin_bounds()
        # What the build with FIPS mode off would accept, said once where it helps.
        hint = (
            " (the PIV applet build with FIPS mode off accepts it: set fips_mode: false in "
            "the profile and install that build)"
        )
        for label, pol in (("PIN", self.pin), ("PUK", self.puk)):
            if pol.min_length < floor:
                wider = self.fips_mode and pol.min_length >= PIN_MIN_LENGTH
                errors.append(
                    f"{label} min_length {pol.min_length} < minimum {floor}"
                    + (hint if wider else "")
                )
            if pol.max_length < pol.min_length:
                errors.append(f"{label} max_length < min_length")
            if pol.max_length != PIN_MAX_LENGTH:
                errors.append(
                    f"{label} max_length {pol.max_length} must be {PIN_MAX_LENGTH}: this tool "
                    f"sends every PIN and PUK as {PIN_MAX_LENGTH} bytes, and the card takes "
                    "only values of exactly max_length"
                )
            if not (0 <= pol.retries <= cap):
                wider = self.fips_mode and 0 <= pol.retries <= PIN_RETRY_CAP
                errors.append(
                    f"{label} retries {pol.retries} out of range (max {cap})"
                    + (hint if wider else "")
                )
            errors.extend(self._contactless_errors(label, pol, hint))
        for k in self.keys:
            if k.ref == c.KEYREF_ADMIN:
                continue  # admin key checked above
            if k.mechanism not in c.SUPPORTED_ALGORITHMS:
                name = _REV_MECH.get(k.mechanism, hex(k.mechanism))
                errors.append(f"key {k.ref:02X} mechanism {name} not supported by this applet")
        if not self.containers and not self.keys:
            errors.append("profile defines no containers or keys")
        return errors

    def _contactless_errors(self, label: str, pol: PinPolicy, hint: str) -> list[str]:
        """What is wrong with the contactless side of a PIN or PUK policy."""
        if pol.contactless not in (pp.MODE_NEVER, pp.MODE_ALWAYS):
            # The applet also knows "inside secure messaging only"; this tool has no
            # secure-messaging client and does not write a verifier it cannot use.
            return [f"{label} contactless must be NEVER or ALWAYS"]
        if not 0 <= pol.contactless_retries <= pol.retries:
            return [
                f"{label} contactless_retries {pol.contactless_retries} out of range "
                f"(0 to retries, {pol.retries})"
            ]
        if not pol.over_contactless:
            return []
        errors = []
        if self.fips_mode:
            errors.append(
                f"{label} contactless ALWAYS lets the {label} cross the contactless interface "
                "without secure messaging, which the FIPS-mode build refuses" + hint
            )
        if pol.contactless_retries == 0:
            errors.append(
                f"{label} contactless ALWAYS needs contactless_retries of at least 1: at 0 "
                f"the applet refuses every {label} presented over contactless (6983)"
            )
        return errors

    def ensure_valid(self) -> None:
        errs = self.validate()
        if errs:
            raise ProfileError("; ".join(errs))

    # -- (de)serialization -------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        def mode_name(v: int) -> str:
            return next((n for n, x in MODES.items() if x == v), hex(v))

        def policy(pol: PinPolicy) -> dict[str, Any]:
            out: dict[str, Any] = {
                "min": pol.min_length,
                "max": pol.max_length,
                "retries": pol.retries,
                "charset": next((n for n, x in CHARSETS.items() if x == pol.charset), pol.charset),
            }
            # Written only when the value leaves the contact interface, so files for
            # contact-only cards read as they always did.
            if pol.over_contactless or pol.contactless_retries:
                out["contactless"] = mode_name(pol.contactless)
                out["contactless_retries"] = pol.contactless_retries
            return out

        return {
            "name": self.name,
            "mode": self.mode,
            # Written only when it departs from the default, so files for the
            # FIPS-mode build read as they always did.
            **({} if self.fips_mode else {"fips_mode": False}),
            "admin": {
                "key_ref": f"{self.admin_key_ref:02X}",
                "mechanism": _REV_MECH.get(self.admin_mechanism, hex(self.admin_mechanism)),
            },
            "pin": policy(self.pin),
            "puk": policy(self.puk),
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
                    "role": role_name(k.role),
                    "contact": mode_name(k.contact),
                    "contactless": mode_name(k.contactless),
                    "attributes": [n for n, x in ATTRS.items() if k.attributes & x],
                }
                for k in self.keys
            ],
        }

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False)


def parse_mode(v: Any) -> int:
    if isinstance(v, int):
        return v
    key = str(v).upper()
    if key not in MODES:
        raise ProfileError(f"unknown access mode {v!r}")
    return MODES[key]


def parse_role(v: Any) -> int:
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


def role_name(v: int) -> str:
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


def _policy(d: dict[str, Any]) -> PinPolicy:
    return PinPolicy(
        int(d["min"]),
        int(d["max"]),
        int(d["retries"]),
        CHARSETS.get(str(d.get("charset", "numeric")), 0x00),
        contactless=parse_mode(d.get("contactless", "NEVER")),
        contactless_retries=int(d.get("contactless_retries", 0)),
    )


def from_dict(d: dict[str, Any]) -> PivProfile:
    fips_mode = d.get("fips_mode", True)
    if not isinstance(fips_mode, bool):
        raise ProfileError("invalid profile: fips_mode must be true or false")
    try:
        admin = d["admin"]
        pin, puk = d["pin"], d["puk"]
        prof = PivProfile(
            name=str(d["name"]),
            mode=str(d.get("mode", "production")),
            admin_key_ref=int(str(admin["key_ref"]), 16),
            admin_mechanism=MECHANISMS[str(admin["mechanism"]).upper()],
            pin=_policy(pin),
            puk=_policy(puk),
            containers=[
                ContainerDef(
                    bytes.fromhex(str(ct["oid"])),
                    str(ct.get("name", "")),
                    parse_mode(ct["contact"]),
                    parse_mode(ct["contactless"]),
                )
                for ct in d.get("containers", [])
            ],
            keys=[
                KeyDef(
                    int(str(k["ref"]), 16),
                    str(k.get("name", "")),
                    MECHANISMS[str(k["mechanism"]).upper()],
                    parse_role(k["role"]),
                    parse_mode(k["contact"]),
                    parse_mode(k["contactless"]),
                    _attrs(k.get("attributes")),
                    admin_key=int(str(k["admin_key"]), 16) if k.get("admin_key") else None,
                )
                for k in d.get("keys", [])
            ],
        )
    except (KeyError, ValueError) as exc:
        raise ProfileError(f"invalid profile: {exc}") from exc
    modes = [
        str(o.get(side, "")).upper()
        for o in [*d.get("containers", []), *d.get("keys", [])]
        for side in ("contact", "contactless")
    ]
    prof.names_vci = any(m in ("VCI", "VCI_PIN") for m in modes)
    prof.fips_mode = fips_mode
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
    SM = pp.MODE_SM
    SMP = pp.MODE_SM_PIN
    containers = [
        ContainerDef(bytes.fromhex("5FC102"), "chuid", A, A),
        ContainerDef(bytes.fromhex("5FC107"), "ccc", A, SM),
        ContainerDef(bytes.fromhex("5FC105"), "auth-cert", A, SM),
        ContainerDef(bytes.fromhex("5FC101"), "card-auth-cert", A, A),
        ContainerDef(bytes.fromhex("5FC10A"), "sign-cert", A, SM),
        ContainerDef(bytes.fromhex("5FC10B"), "keymgmt-cert", A, SM),
        ContainerDef(bytes.fromhex("5FC106"), "security-object", A, SM),
        ContainerDef(bytes.fromhex("5FC103"), "fingerprints", P, SMP),
        ContainerDef(bytes.fromhex("5FC108"), "facial", P, SMP),
        ContainerDef(bytes.fromhex("5FC109"), "printed", P, SMP),
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


def _ms_logon_nfc() -> PivProfile:
    """Windows smart-card logon with the card on an NFC reader. For the applet
    build with FIPS mode off only: the FIPS-mode build refuses a PIN that crosses
    the contactless interface without secure messaging, and the driver Windows
    ships has no secure messaging.

    It is ms-logon with what the logon needs opened to the contactless interface:
    the PIN (in clear; 3 of its 6 tries), the 9A keys after the PIN, and the 9A
    certificate and the CCC for anyone to read (the CHUID already is). The PUK,
    the other keys and the other certificates stay as in ms-logon."""
    prof = _ms_logon()
    prof.name = "ms-logon-nfc"
    prof.fips_mode = False
    prof.pin.contactless = pp.MODE_ALWAYS
    prof.pin.contactless_retries = CONTACTLESS_RETRIES_NFC
    for k in prof.keys:
        if k.ref == c.KEYREF_PIV_AUTH:
            k.contactless = pp.MODE_PIN
    for ct in prof.containers:
        if ct.name in ("auth-cert", "ccc"):
            ct.contactless = pp.MODE_ALWAYS
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
    "ms-logon-nfc": _ms_logon_nfc,
}


def builtin(name: str) -> PivProfile:
    if name not in _BUILTINS:
        raise ProfileError(f"unknown built-in profile {name!r}; choose from {', '.join(_BUILTINS)}")
    return _BUILTINS[name]()


def builtin_names() -> list[str]:
    return list(_BUILTINS)
