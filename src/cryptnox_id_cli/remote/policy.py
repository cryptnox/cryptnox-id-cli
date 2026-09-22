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
instance, the PIV package or the PIV security domain.

Counters guard the other way a command can do harm without being forbidden:
a failed GlobalPlatform authentication decrements a bounded retry counter, so
the number of authentication attempts per security domain is capped, and a
failed authentication ends the operation on the spot.
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

_CONTEXT_BY_AID: dict[bytes, str] = {ISD_AID: ISD, PIV_SSD_AID: PIV_SSD, PIV_AID: PIV}

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
}


def rules_for(op: str) -> OpRules:
    """The rule set for an operation; refuses operations with no rules."""
    try:
        return RULES[op]
    except KeyError:
        raise RemotePolicyError(f"no relay policy exists for operation {op!r}") from None


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


def select_target(apdu: bytes) -> bytes | None:
    """The AID a SELECT-by-name command targets, or ``None`` if it is not one.

    Only the short form with P1 = 04 (select by DF name) is recognised. Anything
    else that looks like a SELECT is refused by the caller, because a SELECT the
    relay cannot read is a SELECT it cannot vouch for.
    """
    header = parse_header(apdu)
    if header.ins != INS_SELECT:
        return None
    if header.p1 != 0x04:
        raise RemotePolicyError(
            f"SELECT with P1={header.p1:02X} is not select-by-name; refused", header=header.hex
        )
    body = apdu[4:]
    if not body:
        return b""  # SELECT with no AID: the default applet
    lc = body[0]
    if lc == 0 and len(body) > 1:
        raise RemotePolicyError("extended-length SELECT refused", header=header.hex)
    aid = body[1 : 1 + lc]
    if len(aid) != lc:
        raise RemotePolicyError("SELECT data shorter than its length byte", header=header.hex)
    return aid


def delete_target(apdu: bytes) -> bytes | None:
    """The AID a DELETE names, when its data travels in the clear.

    Under a secure channel with command encryption the data is opaque and this
    returns ``None``; with a MAC alone the ``4F`` AID template is readable and
    the MAC simply trails it.
    """
    body = apdu[5:]  # past CLA INS P1 P2 Lc
    if len(body) < 3 or body[0] != 0x4F:
        return None
    length = body[1]
    if not 5 <= length <= 16 or len(body) < 2 + length:
        return None
    return body[2 : 2 + length]


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
    rules: OpRules = field(init=False)
    #: Context after a fresh connection: the card manager answers by default.
    context: str = ISD
    apdus: int = 0
    load_blocks: int = 0
    initialize_updates: dict[str, int] = field(default_factory=dict)
    external_authenticates: dict[str, int] = field(default_factory=dict)
    _pending_select: bytes | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.rules = rules_for(self.op)
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
            self._pending_select = target
            return header

        allowed = rules.allowed_ins.get(self.context, frozenset())
        if header.ins not in allowed:
            raise RemotePolicyError(
                f"INS {header.ins:02X} is not allowed while the {self.context} is selected "
                f"during {self.op}",
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
        elif header.ins == INS_DELETE:
            deleted = delete_target(apdu)
            if deleted is not None and (
                rules.delete_targets is None or deleted not in rules.delete_targets
            ):
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
        elif (
            rules.slot_bound
            and header.ins == INS_GENERAL_AUTHENTICATE
            and header.p2 != MANAGEMENT_KEY_REF
        ):
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
        ok = sw1 == 0x90 and sw2 == 0x00
        if self._pending_select is not None:
            if ok:
                self.context = _CONTEXT_BY_AID[self._pending_select]
            self._pending_select = None
            return
        if header.ins == INS_INITIALIZE_UPDATE:
            self.initialize_updates[self.context] = self.initialize_updates.get(self.context, 0) + 1
        elif header.ins == INS_EXTERNAL_AUTHENTICATE:
            self.external_authenticates[self.context] = (
                self.external_authenticates.get(self.context, 0) + 1
            )
            if not ok:
                raise RemotePolicyError(
                    f"EXTERNAL AUTHENTICATE failed (SW={sw1:02X}{sw2:02X}); stopping before "
                    "another attempt can burn a retry",
                    header=header.hex,
                )
        elif header.ins == INS_LOAD:
            self.load_blocks += 1
