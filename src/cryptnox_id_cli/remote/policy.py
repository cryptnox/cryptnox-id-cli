# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""What the relay will and will not send to the card.

The service chooses every command; this module decides whether it reaches the
card. The card carries more than the PIV function (a wallet, FIDO2 passkeys, a
genuineness key, DESFire), and none of those has any business in a PIV
operation. So the policy is an allow-list, per operation, over what a command
header reveals: which applet is selected, the class byte, the instruction, and
for a SELECT the target AID. Anything not listed is refused, the operation is
aborted, and the refusal names the header so the list can be reviewed against
what the service actually needs.

Where the service works inside a secure channel, only the class and instruction
bytes stay in the clear. The policy is honest about that: it fences which
security domain the channel was opened to and which instructions pass through
it, and it cannot see what an encrypted command carries. Where a command's data
does travel in the clear, the policy reads it: a DELETE may only name the PIV
instance, the PIV package or the PIV security domain, and a DELETE whose target
cannot be read is refused unless the channel is known to encrypt command data.
The selected applet is tracked from the card's answers, not the service's
requests; an answer that leaves the selection uncertain admits nothing but
another SELECT.

Counters guard the other way a command can do harm without being forbidden:
a failed GlobalPlatform authentication decrements a bounded retry counter, so
the number of authentication attempts per security domain is capped, and a
failed authentication ends the operation on the spot. The one exception is the
card manager refusing security level 0x33 during ``consumer-lock``: the service
may open it again at 0x13. Any other failure, or a second in a row, ends the
operation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..transport.errors import RemotePolicyError

# --------------------------------------------------------------------------- #
# Applets the relay knows about                                               #
# --------------------------------------------------------------------------- #
ISD_AID = bytes.fromhex("A000000151000000")
PIV_SSD_AID = bytes.fromhex("A00000015153504101")
PIV_AID = bytes.fromhex("A000000308000010000100")
PIV_PACKAGE_AID = bytes.fromhex("A0000003084F46323031")

#: Contexts a command can be evaluated in, keyed by the selected AID.
ISD = "isd"
PIV_SSD = "piv-ssd"
PIV = "piv"
#: After a SELECT the card answered with neither success nor a plain failure.
UNKNOWN = "unknown"

_CONTEXT_BY_AID: dict[bytes, str] = {ISD_AID: ISD, PIV_SSD_AID: PIV_SSD, PIV_AID: PIV}

#: SW1 values after which the selection may or may not have taken effect:
#: warnings (the command ran, with a caveat) and a wrong Le the card wants
#: corrected and re-sent.
_UNCERTAIN_SW1: frozenset[int] = frozenset({0x62, 0x63, 0x6C})

#: EXTERNAL AUTHENTICATE P1 bit requesting command encryption (C-DECRYPTION).
_SECURITY_LEVEL_C_DEC = 0x02

#: SCP03 security levels the service opens a domain at: 0x33 first, then 0x13.
_LEVEL_HARDENED = 0x33
_LEVEL_FALLBACK = 0x13
#: Status words of an EXTERNAL AUTHENTICATE that refused the requested level.
_LEVEL_REFUSED_SW: frozenset[tuple[int, int]] = frozenset({(0x69, 0x82), (0x69, 0x85)})
#: Refused levels admitted per security domain: one per authenticated open,
#: three per replaced key.
_MAX_LEVEL_REFUSALS = {ISD: 3, PIV_SSD: 6}

#: Operations grouped by what they may do to the card.
READ_ONLY_OPS = ("authenticate", "inspect")
DESTRUCTIVE_OPS = ("reset", "dev-reset")
KEY_OPS = ("attest",)

#: The PIV management key reference: the only key GENERAL AUTHENTICATE may
#: address during a remote operation, and the only reference whose value
#: CHANGE REFERENCE DATA may set.
MANAGEMENT_KEY_REF = 0x9B

#: Card-holder references. Their retry counters are the card holder's to spend,
#: so no remote operation may address them, ever.
CARDHOLDER_REFS: frozenset[int] = frozenset({0x80, 0x81})

# Instructions, by name, so the tables read as prose.
INS_SELECT = 0xA4
INS_GET_DATA_GP = 0xCA
INS_GET_DATA_PIV = 0xCB
INS_GET_STATUS = 0xF2
INS_INITIALIZE_UPDATE = 0x50
INS_EXTERNAL_AUTHENTICATE = 0x82
INS_GET_RESPONSE = 0xC0
INS_VERIFY = 0x20
INS_CHANGE_REFERENCE_DATA = 0x24
INS_RESET_RETRY_COUNTER = 0x2C
INS_GENERAL_AUTHENTICATE = 0x87
INS_GENERATE_ASYMMETRIC = 0x47
INS_PUT_DATA = 0xDB
INS_PUT_KEY = 0xD8
INS_DELETE = 0xE4
INS_INSTALL = 0xE6
INS_LOAD = 0xE8
INS_STORE_DATA = 0xE2
INS_CTAP_MSG = 0x10

#: Never, in any operation or context: card-holder verifiers and anything that
#: decrements a retry counter the service has no business touching.
_ALWAYS_DENIED_INS: frozenset[int] = frozenset(
    {INS_VERIFY, INS_CHANGE_REFERENCE_DATA, INS_RESET_RETRY_COUNTER}
)


@dataclass(frozen=True)
class OpRules:
    """The allow-list for one operation."""

    #: AIDs a SELECT may target. The empty AID (select the default) counts as ISD.
    selectable: frozenset[bytes]
    #: Instructions allowed per context, over plain and secure-messaging classes.
    allowed_ins: dict[str, frozenset[int]]
    #: Largest number of commands relayed in one operation.
    max_apdus: int
    #: Longest an operation may run, in seconds, measured from the first command.
    max_seconds: float
    #: INITIALIZE UPDATE attempts allowed per security domain.
    max_initialize_updates: int
    #: EXTERNAL AUTHENTICATE attempts allowed per security domain (0 = never).
    max_external_authenticates: int = 0
    #: AIDs a DELETE may name when its data is readable. ``None`` = no DELETE.
    delete_targets: frozenset[bytes] | None = None
    #: LOAD blocks allowed in one operation (0 = no LOAD).
    max_load_blocks: int = 0
    #: Whether GENERATE and GENERAL AUTHENTICATE are bound to a slot and the
    #: management key. Only meaningful for key operations.
    slot_bound: bool = False
    #: Whether the operation may set the PIV management key's value. The
    #: service does this over the secure channel before generating a key.
    #: Card-holder references stay denied regardless.
    allow_management_key_change: bool = False
    #: Whether a security domain may refuse security level 0x33 at EXTERNAL
    #: AUTHENTICATE and be opened at 0x13 instead (see RelayPolicy.observe).
    level_fallback: bool = False
    #: Whether a refusal mid-run leaves keys on the card worth waiting for: the
    #: relay then tells the service and reads on for its result.
    sealing: bool = False


_GP_READS: frozenset[int] = frozenset(
    {INS_SELECT, INS_GET_DATA_GP, INS_GET_STATUS, INS_GET_RESPONSE}
)
_GP_AUTH: frozenset[int] = frozenset({INS_INITIALIZE_UPDATE, INS_EXTERNAL_AUTHENTICATE})
_GP_CONTENT: frozenset[int] = frozenset({INS_DELETE, INS_INSTALL, INS_LOAD})
_GP_KEYS: frozenset[int] = frozenset({INS_PUT_KEY, INS_STORE_DATA})
_PIV_READS: frozenset[int] = frozenset({INS_SELECT, INS_GET_DATA_PIV, INS_GET_RESPONSE})

#: What the service may delete: the PIV instance, its package, its security
#: domain. Never a package or instance of any other card function.
_PIV_DELETE_TARGETS: frozenset[bytes] = frozenset({PIV_AID, PIV_PACKAGE_AID, PIV_SSD_AID})

_RESET_RULES = OpRules(
    selectable=frozenset({ISD_AID, PIV_SSD_AID, PIV_AID}),
    allowed_ins={
        # Card content management happens through the card manager only.
        ISD: _GP_READS | _GP_AUTH | _GP_CONTENT | _GP_KEYS,
        # The PIV security domain is created, keyed and verified; it never
        # loads or deletes anything itself.
        PIV_SSD: _GP_READS | _GP_AUTH | _GP_KEYS,
        # The fresh applet is checked and may receive its baseline structure
        # and its management key through its own admin channel; no key use, no
        # key generation.
        PIV: _PIV_READS | _GP_AUTH | {INS_PUT_DATA, INS_CHANGE_REFERENCE_DATA},
    },
    # A CAP of ~190 KB loads in ~800 blocks; the rest is bookkeeping.
    max_apdus=1500,
    max_seconds=1800.0,
    # The service re-opens the card manager's channel for each step of the
    # operation (delete, load, install, create the security domain, key it,
    # extradite, verify), so the count is per step, not per operation. Observed:
    # four before the security domain was keyed. The real protection against a
    # spent retry is not this ceiling but the abort on the first FAILED
    # authentication in observe(); this only bounds a runaway.
    max_initialize_updates=16,
    max_external_authenticates=16,
    delete_targets=_PIV_DELETE_TARGETS,
    max_load_blocks=1500,
    allow_management_key_change=True,
)

_CONSUMER_LOCK_RULES = OpRules(
    selectable=frozenset({ISD_AID, PIV_SSD_AID, PIV_AID}),
    allowed_ins={
        # Keys are only ever replaced in place: nothing is loaded, installed or deleted.
        ISD: _GP_READS | _GP_AUTH | {INS_PUT_KEY},
        PIV_SSD: _GP_READS | _GP_AUTH | {INS_PUT_KEY},
        PIV: _PIV_READS
        | _GP_AUTH
        | {INS_PUT_DATA, INS_CHANGE_REFERENCE_DATA, INS_GENERAL_AUTHENTICATE},
    },
    max_apdus=500,
    # Above the service's 300 s budget plus its 20 s card handshake, so its deadline fires first.
    max_seconds=420.0,
    # Two keys replaced in the PIV security domain, each open possibly retried at 0x13.
    max_initialize_updates=14,
    max_external_authenticates=12,
    allow_management_key_change=True,
    level_fallback=True,
    sealing=True,
)

#: A dry run reads and authenticates, so the relay holds it to that even if the
#: service ignored the flag.
_CONSUMER_LOCK_DRY_RUN_RULES = OpRules(
    selectable=frozenset({ISD_AID, PIV_SSD_AID, PIV_AID}),
    allowed_ins={
        ISD: _GP_READS | _GP_AUTH,
        PIV_SSD: _GP_READS | _GP_AUTH,
        PIV: _PIV_READS | _GP_AUTH | {INS_GENERAL_AUTHENTICATE},
    },
    max_apdus=300,
    max_seconds=300.0,
    max_initialize_updates=2,
    max_external_authenticates=2,
    level_fallback=True,
    sealing=True,
)

RULES: dict[str, OpRules] = {
    "authenticate": OpRules(
        selectable=frozenset({ISD_AID}),
        allowed_ins={
            ISD: _GP_READS,
            PIV_SSD: frozenset(),
            PIV: frozenset(),
        },
        max_apdus=20,
        max_seconds=60.0,
        max_initialize_updates=0,
    ),
    "inspect": OpRules(
        selectable=frozenset({ISD_AID, PIV_SSD_AID, PIV_AID}),
        allowed_ins={
            ISD: _GP_READS | {INS_INITIALIZE_UPDATE},
            PIV_SSD: _GP_READS | {INS_INITIALIZE_UPDATE},
            # The applet hosts its own admin channel; the service probes its
            # secure-channel version the same way, without authenticating.
            PIV: _PIV_READS | {INS_INITIALIZE_UPDATE},
        },
        max_apdus=60,
        max_seconds=120.0,
        # The service enumerates key versions by repeated INITIALIZE UPDATE with
        # different P1 values (observed: KVN 00, then KVN 01). None of them costs
        # a retry as long as EXTERNAL AUTHENTICATE stays refused.
        max_initialize_updates=4,
    ),
    "reset": _RESET_RULES,
    "dev-reset": _RESET_RULES,
    "attest": OpRules(
        selectable=frozenset({ISD_AID, PIV_SSD_AID, PIV_AID}),
        allowed_ins={
            ISD: _GP_READS | {INS_INITIALIZE_UPDATE},
            PIV_SSD: _GP_READS | _GP_AUTH,
            # The applet's admin channel for the key-object setup, then the
            # management-key handshake, key generation and the certificate write.
            PIV: _PIV_READS
            | _GP_AUTH
            | {
                INS_GENERAL_AUTHENTICATE,
                INS_GENERATE_ASYMMETRIC,
                INS_PUT_DATA,
                INS_CHANGE_REFERENCE_DATA,
            },
        },
        max_apdus=200,
        max_seconds=600.0,
        max_initialize_updates=6,
        max_external_authenticates=4,
        slot_bound=True,
        allow_management_key_change=True,
    ),
    "consumer-lock": _CONSUMER_LOCK_RULES,
}

DRY_RUN_RULES: dict[str, OpRules] = {"consumer-lock": _CONSUMER_LOCK_DRY_RUN_RULES}


def rules_for(op: str, *, dry_run: bool = False) -> OpRules:
    """The rule set for an operation; refuses operations with no rules."""
    table, kind = (DRY_RUN_RULES, "dry-run relay policy") if dry_run else (RULES, "relay policy")
    try:
        return table[op]
    except KeyError:
        raise RemotePolicyError(f"no {kind} exists for operation {op!r}") from None


@dataclass(frozen=True)
class Header:
    cla: int
    ins: int
    p1: int
    p2: int

    @property
    def hex(self) -> str:
        return f"{self.cla:02X}{self.ins:02X}{self.p1:02X}{self.p2:02X}"

    @property
    def channel(self) -> int:
        """Logical channel number encoded in the class byte."""
        if self.cla & 0x40:
            return 4 + (self.cla & 0x0F)
        return self.cla & 0x03

    @property
    def secure_messaging(self) -> bool:
        """GlobalPlatform secure messaging (class bit 3) is in use."""
        return bool(self.cla & 0x04) and not (self.cla & 0x40)


def parse_header(apdu: bytes) -> Header:
    if len(apdu) < 4:
        raise RemotePolicyError("command shorter than an APDU header", header=apdu.hex().upper())
    return Header(apdu[0], apdu[1], apdu[2], apdu[3])


def command_data(apdu: bytes) -> bytes:
    """The data field of a command, in the short or the extended encoding.

    A command whose length fields do not match its size is refused: a command
    the relay cannot parse is one it cannot vouch for.
    """
    header = parse_header(apdu)
    body = apdu[4:]
    if not body:
        return b""
    if body[0] != 0 or len(body) == 1:
        # Short form: Lc, data, optional Le. A lone 00 is a short Le with no data.
        lc = body[0]
        data = body[1 : 1 + lc]
        trailer = len(body) - 1 - lc
        if len(data) != lc or trailer > 1:
            raise RemotePolicyError(
                "command data does not match its length fields", header=header.hex
            )
        return data
    if len(body) == 3:
        return b""  # extended Le, no data
    lc = int.from_bytes(body[1:3], "big")
    data = body[3 : 3 + lc]
    trailer = len(body) - 3 - lc
    if len(body) < 4 or lc == 0 or len(data) != lc or trailer not in (0, 2):
        raise RemotePolicyError("command data does not match its length fields", header=header.hex)
    return data


def select_target(apdu: bytes) -> bytes | None:
    """The AID a SELECT-by-name command targets, or ``None`` if it is not one.

    Only P1 = 04 (select by DF name) is recognised. Anything else that looks like
    a SELECT is refused by the caller, because a SELECT the relay cannot read is
    a SELECT it cannot vouch for. An empty AID selects the default applet.
    """
    header = parse_header(apdu)
    if header.ins != INS_SELECT:
        return None
    if header.p1 != 0x04:
        raise RemotePolicyError(
            f"SELECT with P1={header.p1:02X} is not select-by-name; refused", header=header.hex
        )
    return command_data(apdu)


def delete_target(apdu: bytes) -> bytes | None:
    """The AID a DELETE names, when its data is readable; ``None`` when it is not.

    With a MAC alone the ``4F`` AID template is in the clear and the MAC trails
    it. Under command encryption the data is opaque.
    """
    data = command_data(apdu)
    if len(data) < 3 or data[0] != 0x4F:
        return None
    length = data[1]
    if not 5 <= length <= 16 or len(data) < 2 + length:
        return None
    return data[2 : 2 + length]


@dataclass
class RelayPolicy:
    """Stateful gate over one operation's command stream.

    Call :meth:`check` before transmitting and :meth:`observe` with the card's
    answer afterwards, so the selected-applet tracking follows what the card
    actually did rather than what the service asked for.
    """

    op: str
    #: For key operations: the slot the operation was asked to generate into.
    slot: int | None = None
    #: Hold the operation to its read-only dry-run rules.
    dry_run: bool = False
    rules: OpRules = field(init=False)
    #: Context after a fresh connection: the card manager answers by default.
    context: str = ISD
    apdus: int = 0
    load_blocks: int = 0
    initialize_updates: dict[str, int] = field(default_factory=dict)
    external_authenticates: dict[str, int] = field(default_factory=dict)
    open_initialize_updates: dict[str, int] = field(default_factory=dict)
    _pending_select: bytes | None = field(default=None, init=False, repr=False)
    #: Whether the open secure channel encrypts command data, from the security
    #: level the last successful EXTERNAL AUTHENTICATE asked for.
    _command_encryption: bool = field(default=False, init=False, repr=False)
    #: Domains whose last EXTERNAL AUTHENTICATE was a refused level, not yet retried.
    _level_refused: set[str] = field(default_factory=set, init=False, repr=False)
    _level_refusals: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.rules = rules_for(self.op, dry_run=self.dry_run)
        if self.rules.slot_bound and self.slot is None:
            raise RemotePolicyError(f"the {self.op} policy needs the target slot")

    # -- evaluation -------------------------------------------------------- #
    def check(self, apdu: bytes) -> Header:
        """Refuse or allow one command. Returns the parsed header on allow."""
        header = parse_header(apdu)
        self._pending_select = None
        rules = self.rules

        if self.apdus >= rules.max_apdus:
            raise RemotePolicyError(
                f"the service sent more than {rules.max_apdus} commands in one {self.op} operation",
                header=header.hex,
            )
        if header.channel != 0:
            raise RemotePolicyError(
                f"logical channel {header.channel} refused; only the basic channel is relayed",
                header=header.hex,
            )
        if (header.cla & 0xF0) == 0x90:
            raise RemotePolicyError("DESFire-wrapped command refused", header=header.hex)
        if (header.cla & 0x0C) == 0x0C:
            # Both secure-messaging bits: ISO 7816-4 SM, which nothing here speaks.
            # GlobalPlatform SM sets only bit 2 (CLA 84) and passes.
            raise RemotePolicyError("ISO secure messaging refused", header=header.hex)
        if (header.cla & 0xF0) == 0x80 and header.ins == INS_CTAP_MSG:
            raise RemotePolicyError("FIDO2 CTAP command refused", header=header.hex)
        if header.ins in _ALWAYS_DENIED_INS:
            # Setting the management key's value is administration, not a
            # card-holder verifier: 9B has no card-holder retry counter, and the
            # service loads it before generating a key. Every other reference,
            # and every other instruction in this set, stays denied.
            managing_9b = (
                header.ins == INS_CHANGE_REFERENCE_DATA
                and header.p2 == MANAGEMENT_KEY_REF
                and rules.allow_management_key_change
            )
            if not managing_9b:
                raise RemotePolicyError(
                    f"INS {header.ins:02X} is never relayed (card-holder verifier)",
                    header=header.hex,
                )
        if header.ins == INS_EXTERNAL_AUTHENTICATE and rules.max_external_authenticates == 0:
            raise RemotePolicyError(
                f"EXTERNAL AUTHENTICATE is not allowed during {self.op}; a failed attempt "
                "burns a card-management retry",
                header=header.hex,
            )

        aid = select_target(apdu)
        if aid is not None:
            target = ISD_AID if aid == b"" else aid
            if target not in rules.selectable:
                raise RemotePolicyError(
                    f"SELECT of AID {target.hex().upper()} is not allowed during {self.op}",
                    header=header.hex,
                )
            if target not in _CONTEXT_BY_AID:
                raise RemotePolicyError(
                    f"SELECT of AID {target.hex().upper()} has no relay context; refused",
                    header=header.hex,
                )
            self._pending_select = target
            return header

        allowed = rules.allowed_ins.get(self.context, frozenset())
        if header.ins not in allowed:
            where = (
                "the selected applet is unknown"
                if self.context == UNKNOWN
                else f"the {self.context} is selected"
            )
            raise RemotePolicyError(
                f"INS {header.ins:02X} is not allowed while {where} during {self.op}",
                header=header.hex,
            )

        if header.ins == INS_INITIALIZE_UPDATE:
            self._enforce_cap(
                self.initialize_updates, rules.max_initialize_updates, "INITIALIZE UPDATE", header
            )
        elif header.ins == INS_EXTERNAL_AUTHENTICATE:
            self._enforce_cap(
                self.external_authenticates,
                rules.max_external_authenticates,
                "EXTERNAL AUTHENTICATE",
                header,
            )
            if self.context in self._level_refused and header.p1 != _LEVEL_FALLBACK:
                raise RemotePolicyError(
                    f"EXTERNAL AUTHENTICATE at level {header.p1:02X} refused; after the "
                    f"{self.context} refused level {_LEVEL_HARDENED:02X}, only "
                    f"{_LEVEL_FALLBACK:02X} may follow",
                    header=header.hex,
                )
        elif header.ins == INS_DELETE:
            if rules.delete_targets is None:
                raise RemotePolicyError(
                    f"DELETE is not allowed during {self.op}", header=header.hex
                )
            deleted = delete_target(apdu)
            if deleted is None:
                if not self._command_encryption:
                    raise RemotePolicyError(
                        "DELETE names a target the relay cannot read, on a channel that does "
                        "not encrypt commands; refused",
                        header=header.hex,
                    )
            elif deleted not in rules.delete_targets:
                raise RemotePolicyError(
                    f"DELETE of {deleted.hex().upper()} refused; only the PIV instance, "
                    "package and security domain may be deleted",
                    header=header.hex,
                )
        elif header.ins == INS_LOAD:
            if self.load_blocks >= rules.max_load_blocks:
                raise RemotePolicyError(
                    f"more than {rules.max_load_blocks} LOAD blocks in one {self.op} operation",
                    header=header.hex,
                )
        elif rules.slot_bound and header.ins == INS_GENERATE_ASYMMETRIC and header.p2 != self.slot:
            raise RemotePolicyError(
                f"GENERATE for slot {header.p2:02X} refused; this operation was asked "
                f"for slot {self.slot:02X}",
                header=header.hex,
            )
        elif header.ins == INS_GENERAL_AUTHENTICATE and header.p2 != MANAGEMENT_KEY_REF:
            raise RemotePolicyError(
                f"GENERAL AUTHENTICATE with key {header.p2:02X} refused; only the "
                "management key may be exercised, never a slot key",
                header=header.hex,
            )
        return header

    def _enforce_cap(self, counter: dict[str, int], cap: int, what: str, header: Header) -> None:
        if counter.get(self.context, 0) >= cap:
            raise RemotePolicyError(
                f"{what} to the {self.context} more than {cap} time(s) during {self.op}",
                header=header.hex,
            )

    def observe(self, apdu: bytes, sw1: int, sw2: int) -> None:
        """Record what the card did with an allowed command."""
        self.apdus += 1
        header = parse_header(apdu)
        # 61XX is success with response bytes waiting for GET RESPONSE.
        ok = (sw1 == 0x90 and sw2 == 0x00) or sw1 == 0x61
        if self._pending_select is not None:
            target, self._pending_select = self._pending_select, None
            if ok:
                self.context = _CONTEXT_BY_AID[target]
                self._command_encryption = False  # selecting closes any secure channel
            elif sw1 in _UNCERTAIN_SW1:
                self.context = UNKNOWN
                self._command_encryption = False
            return
        if header.ins == INS_INITIALIZE_UPDATE:
            self.initialize_updates[self.context] = self.initialize_updates.get(self.context, 0) + 1
            self.open_initialize_updates[self.context] = (
                self.open_initialize_updates.get(self.context, 0) + 1
            )
            self._command_encryption = False
        elif header.ins == INS_EXTERNAL_AUTHENTICATE:
            self.external_authenticates[self.context] = (
                self.external_authenticates.get(self.context, 0) + 1
            )
            if not ok:
                if self._admit_level_refusal(header, sw1, sw2):
                    return
                raise RemotePolicyError(
                    f"EXTERNAL AUTHENTICATE failed (SW={sw1:02X}{sw2:02X}); stopping before "
                    "another attempt can burn a retry",
                    header=header.hex,
                )
            self._level_refused.discard(self.context)
            self._command_encryption = bool(header.p1 & _SECURITY_LEVEL_C_DEC)
            self.open_initialize_updates.pop(self.context, None)
        elif header.ins == INS_LOAD:
            self.load_blocks += 1

    def _admit_level_refusal(self, header: Header, sw1: int, sw2: int) -> bool:
        """Whether a failed EXTERNAL AUTHENTICATE is a security domain refusing level 0x33.

        A wrong key fails on the service's side before EXTERNAL AUTHENTICATE is
        sent, so this refusal costs no key retry, and the service retries at 0x13.
        """
        context = self.context
        if not (
            self.rules.level_fallback
            and header.p1 == _LEVEL_HARDENED
            and (sw1, sw2) in _LEVEL_REFUSED_SW
            and context not in self._level_refused
            and self._level_refusals.get(context, 0) < _MAX_LEVEL_REFUSALS.get(context, 0)
        ):
            return False
        self._level_refused.add(context)
        self._level_refusals[context] = self._level_refusals.get(context, 0) + 1
        return True
