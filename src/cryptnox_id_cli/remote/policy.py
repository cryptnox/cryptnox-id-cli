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
it, and it cannot see what an encrypted command carries.

Counters guard the other way a command can do harm without being forbidden:
a failed GlobalPlatform authentication decrements a bounded retry counter, so
the number of authentication attempts per security domain is capped, and a
refused authentication ends the operation on the spot.
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

#: Contexts a command can be evaluated in, keyed by the selected AID.
ISD = "isd"
PIV_SSD = "piv-ssd"
PIV = "piv"

_CONTEXT_BY_AID: dict[bytes, str] = {ISD_AID: ISD, PIV_SSD_AID: PIV_SSD, PIV_AID: PIV}

#: The operations this module has rules for.
READ_ONLY_OPS = ("authenticate", "inspect")

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
    #: Whether EXTERNAL AUTHENTICATE may be relayed at all.
    allow_external_authenticate: bool


_GP_READS: frozenset[int] = frozenset(
    {INS_SELECT, INS_GET_DATA_GP, INS_GET_STATUS, INS_GET_RESPONSE}
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
        allow_external_authenticate=False,
    ),
    "inspect": OpRules(
        selectable=frozenset({ISD_AID, PIV_SSD_AID, PIV_AID}),
        allowed_ins={
            ISD: _GP_READS | {INS_INITIALIZE_UPDATE},
            PIV_SSD: _GP_READS | {INS_INITIALIZE_UPDATE},
            PIV: frozenset({INS_SELECT, INS_GET_DATA_PIV, INS_GET_RESPONSE}),
        },
        max_apdus=60,
        max_seconds=120.0,
        # The service enumerates key versions by repeated INITIALIZE UPDATE with
        # different P1 values (observed: KVN 00, then KVN 01). None of them costs
        # a retry as long as EXTERNAL AUTHENTICATE stays refused.
        max_initialize_updates=4,
        allow_external_authenticate=False,
    ),
}


def rules_for(op: str) -> OpRules:
    """The rule set for an operation; refuses operations with no rules yet."""
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


@dataclass
class RelayPolicy:
    """Stateful gate over one operation's command stream.

    Call :meth:`check` before transmitting and :meth:`observe` with the card's
    answer afterwards, so the selected-applet tracking follows what the card
    actually did rather than what the service asked for.
    """

    op: str
    rules: OpRules = field(init=False)
    #: Context after a fresh connection: the card manager answers by default.
    context: str = ISD
    apdus: int = 0
    initialize_updates: dict[str, int] = field(default_factory=dict)
    _pending_select: bytes | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.rules = rules_for(self.op)

    # -- evaluation -------------------------------------------------------- #
    def check(self, apdu: bytes) -> Header:
        """Refuse or allow one command. Returns the parsed header on allow."""
        header = parse_header(apdu)
        self._pending_select = None

        if self.apdus >= self.rules.max_apdus:
            raise RemotePolicyError(
                f"the service sent more than {self.rules.max_apdus} commands in one "
                f"{self.op} operation",
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
            raise RemotePolicyError(
                f"INS {header.ins:02X} is never relayed (card-holder verifier)", header=header.hex
            )
        if header.ins == INS_EXTERNAL_AUTHENTICATE and not self.rules.allow_external_authenticate:
            raise RemotePolicyError(
                f"EXTERNAL AUTHENTICATE is not allowed during {self.op}; a failed attempt "
                "burns a card-management retry",
                header=header.hex,
            )

        aid = select_target(apdu)
        if aid is not None:
            target = ISD_AID if aid == b"" else aid
            if target not in self.rules.selectable:
                raise RemotePolicyError(
                    f"SELECT of AID {target.hex().upper()} is not allowed during {self.op}",
                    header=header.hex,
                )
            self._pending_select = target
            return header

        allowed = self.rules.allowed_ins.get(self.context, frozenset())
        if header.ins not in allowed:
            raise RemotePolicyError(
                f"INS {header.ins:02X} is not allowed while the {self.context} is selected "
                f"during {self.op}",
                header=header.hex,
            )

        if header.ins == INS_INITIALIZE_UPDATE:
            count = self.initialize_updates.get(self.context, 0)
            if count >= self.rules.max_initialize_updates:
                raise RemotePolicyError(
                    f"INITIALIZE UPDATE to the {self.context} more than "
                    f"{self.rules.max_initialize_updates} time(s) during {self.op}",
                    header=header.hex,
                )
        return header

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
        if header.ins == INS_EXTERNAL_AUTHENTICATE and not ok:
            raise RemotePolicyError(
                f"EXTERNAL AUTHENTICATE failed (SW={sw1:02X}{sw2:02X}); stopping before "
                "another attempt can burn a retry",
                header=header.hex,
            )
