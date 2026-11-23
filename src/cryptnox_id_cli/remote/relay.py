# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The operation loop: announce the operation, answer the proof-of-work, relay
commands under the policy, return the result.

The service drives. This loop only ever answers: it never sends a command of its
own to the card, never reassembles a chained response, and never retries. What
the card says goes back verbatim, status word included, so the service sees the
card exactly as a local reader would. The one thing the loop adds is refusal,
through :class:`~cryptnox_id_cli.remote.policy.RelayPolicy`, and every refusal
ends the operation. In a sealing operation the relay then tells the service and
reads on, for a bounded time, until the service's result arrives, relaying
nothing more to the card: the result may carry keys already written to it.

Relayed commands are written to the transcript with their data masked unless
the instruction is on a short list of known-harmless reads. That is the reverse
of the CLI's own transcript rule, because here the client did not choose the
command and cannot vouch for what it carries.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from ..secrets.redaction import Redactor
from ..transport.errors import (
    CryptnoxError,
    RemoteError,
    RemoteOperationError,
    RemoteProtocolError,
    TransportError,
)
from ..transport.pcsc import RawConnection
from . import pow as rpow
from . import protocol as proto
from . import refusal as rrefusal
from .channel import RECV_TIMEOUT, FrameChannel
from .policy import (
    INS_CHANGE_REFERENCE_DATA,
    INS_GET_DATA_GP,
    INS_GET_DATA_PIV,
    INS_GET_RESPONSE,
    INS_GET_STATUS,
    INS_INITIALIZE_UPDATE,
    INS_PUT_DATA,
    INS_PUT_KEY,
    INS_SELECT,
    ISD,
    PIV,
    RelayPolicy,
)

#: Instructions whose command data is shown in the transcript. Everything else
#: is masked: the service chose it, and the relay cannot tell what it carries.
TRANSCRIPT_CLEAR_INS: frozenset[int] = frozenset(
    {
        INS_SELECT,
        INS_GET_DATA_GP,
        INS_GET_DATA_PIV,
        INS_GET_STATUS,
        INS_GET_RESPONSE,
        INS_INITIALIZE_UPDATE,
    }
)

#: Proof-of-work challenges answered per operation. The service issues one.
MAX_POW_CHALLENGES = 1

#: Requests for owner-supplied values answered per operation.
MAX_KEX_REQUESTS = 1

#: How long, and for how many frames, a stopped sealing operation waits for the
#: service's result.
DRAIN_SECONDS = 30.0
DRAIN_FRAMES = 16

#: Instructions that change what the card holds.
WRITE_INS: frozenset[int] = frozenset({INS_PUT_KEY, INS_PUT_DATA, INS_CHANGE_REFERENCE_DATA})

#: Seconds to wait for the answer to a ping. The service answers at once: it
#: touches neither a card nor a key.
PING_TIMEOUT = 20.0


@dataclass
class RelayReport:
    """What happened during one operation."""

    op: str
    result: dict[str, object]
    apdus_relayed: int = 0
    seconds: float = 0.0
    atr: bytes | None = None
    log_lines: list[str] = field(default_factory=list)
    pow_bits: int | None = None
    kex_fields: tuple[str, ...] = ()
    open_initialize_updates: dict[str, int] = field(default_factory=dict)
    #: A command in :data:`WRITE_INS` was handed to the card.
    card_written: bool = False
    #: Key versions the PUT KEYs named, per security domain they were handed to.
    put_keys: dict[str, list[int]] = field(default_factory=dict)
    #: A write was handed to the PIV applet: an object, its configuration or the management key.
    piv_written: bool = False
    #: Diagnostic outputs that failed during the operation and were switched off.
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.result.get("ok", False))

    @property
    def card_manager_key_written(self) -> bool:
        return bool(self.put_keys.get(ISD))


class _Sink:
    """A diagnostic output that a sealing operation switches off when writing to it fails."""

    def __init__(
        self,
        write: Callable[[str], None] | None,
        name: str,
        report: RelayReport,
        *,
        guarded: bool,
    ) -> None:
        self._write = write
        self._name = name
        self._report = report
        self._guarded = guarded

    def __call__(self, line: str) -> None:
        if self._write is None:
            return
        if not self._guarded:
            self._write(line)
            return
        try:
            self._write(line)
        # Rich turns a broken pipe into SystemExit; neither may stop a seal halfway.
        except (OSError, SystemExit) as exc:
            self._write = None
            reason = str(exc) if isinstance(exc, OSError) else "its stream was closed"
            self._report.warnings.append(
                f"writing the {self._name} failed during {self._report.op} ({reason}); it was "
                "switched off and the operation carried on."
            )


def redact_relayed_command(apdu: bytes, redactor: Redactor, *, unmasked: bool = False) -> str:
    """Transcript rendering of a relayed command: masked unless known-harmless."""
    if unmasked or (len(apdu) >= 4 and apdu[1] in TRANSCRIPT_CLEAR_INS):
        return redactor.redact_command(apdu)
    header = apdu[:4].hex().upper()
    body = apdu[4:]
    if not body:
        return header
    return f"{header}<REDACTED:{len(body)}B>"


def redact_relayed_response(
    data: bytes, sw1: int, sw2: int, ins: int, redactor: Redactor, *, unmasked: bool = False
) -> str:
    """Transcript rendering of a relayed response: masked outside known reads."""
    if unmasked or ins in TRANSCRIPT_CLEAR_INS:
        return redactor.redact_response(data, sw1, sw2, ins=ins)
    if not data:
        return f"{sw1:02X}{sw2:02X}"
    return f"<REDACTED:{len(data)}B>{sw1:02X}{sw2:02X}"


def run_operation(
    channel: FrameChannel,
    card: RawConnection,
    op: str,
    params: Mapping[str, object] | None = None,
    *,
    policy: RelayPolicy | None = None,
    redactor: Redactor | None = None,
    transcript: Callable[[str], None] | None = None,
    unmasked_transcript: bool = False,
    on_log: Callable[[str], None] | None = None,
    answer_kex: Callable[[proto.KexRequest], bytes] | None = None,
    stop_requested: Callable[[], bool] | None = None,
    report: RelayReport | None = None,
    recv_timeout: float = RECV_TIMEOUT,
    clock: Callable[[], float] = time.monotonic,
) -> RelayReport:
    """Run one operation against the service and return its report.

    Raises a :class:`~cryptnox_id_cli.transport.errors.RemoteError` subclass on
    any failure. A result frame with ``ok`` false raises
    :class:`RemoteOperationError` carrying the service's payload. When the relay
    stops a sealing operation itself, the error raised carries the result the
    service sent afterwards, if any, as ``result``.

    ``answer_kex`` encrypts the values a ``kex`` frame asks for; without it, a
    ``kex`` frame ends the operation. ``stop_requested`` is asked before each
    command; when it says so, the operation stops as if the command were refused.
    ``report``, when given, is filled in place, so what happened is still known
    after an error.
    """
    policy = policy or RelayPolicy(op)
    redactor = redactor or Redactor()
    if report is None:
        report = RelayReport(op=op, result={})
    sealing = policy.rules.sealing
    emit = _Sink(transcript, "APDU transcript", report, guarded=sealing)
    log = _Sink(on_log, "service log output", report, guarded=sealing)
    started: float | None = None
    pow_answered = 0
    kex_answered = 0

    channel.send(proto.encode_frame(proto.hello_frame(op, params)))

    while True:
        raw = channel.recv(timeout=recv_timeout)
        for obj in proto.decode_frames(raw):
            frame = proto.parse_server_frame(obj)

            if isinstance(frame, proto.PowChallenge):
                if pow_answered >= MAX_POW_CHALLENGES:
                    raise RemoteProtocolError(
                        "the service issued a second proof-of-work challenge in one operation"
                    )
                nonce = rpow.solve(frame.challenge, frame.bits)
                pow_answered += 1
                report.pow_bits = frame.bits
                channel.send(proto.encode_frame(proto.pow_frame(nonce)))
                continue

            if isinstance(frame, proto.LogMessage):
                report.log_lines.append(frame.message)
                log(frame.message)
                continue

            if isinstance(frame, proto.KexRequest):
                if answer_kex is None:
                    raise RemoteProtocolError(
                        f"the service asked for owner-supplied values during {op}, which takes none"
                    )
                if kex_answered >= MAX_KEX_REQUESTS:
                    raise RemoteProtocolError(
                        "the service asked for owner-supplied values twice in one operation"
                    )
                kex_answered += 1
                try:
                    blob = answer_kex(frame)
                except CryptnoxError as exc:
                    channel.send(proto.encode_frame(proto.kex_error_frame(str(exc))))
                    raise
                report.kex_fields = frame.fields
                channel.send(proto.encode_frame(proto.kex_response_frame(blob)))
                continue

            if isinstance(frame, proto.AtrRequest):
                atr = bytes(card.get_atr())
                report.atr = atr
                channel.send(proto.encode_frame(proto.atr_response_frame(atr)))
                continue

            if isinstance(frame, proto.ApduCommand):
                apdu = frame.apdu
                card_failed = False
                try:
                    if stop_requested is not None and stop_requested():
                        raise RemoteError(f"the {op} operation was stopped on request")
                    if started is None:
                        started = clock()
                    elapsed = clock() - started
                    if elapsed > policy.rules.max_seconds:
                        raise RemoteError(
                            f"the {op} operation exceeded {policy.rules.max_seconds:g} seconds "
                            "of card activity"
                        )
                    policy.check(apdu)  # raises RemotePolicyError; nothing was sent
                    emit(
                        "relay > "
                        + redact_relayed_command(apdu, redactor, unmasked=unmasked_transcript)
                    )
                    if apdu[1] in WRITE_INS:
                        report.card_written = True
                        if apdu[1] == INS_PUT_KEY:
                            report.put_keys.setdefault(policy.context, []).append(apdu[2])
                        elif policy.context == PIV:
                            report.piv_written = True
                    try:
                        data, sw1, sw2 = card.transmit(list(apdu))
                    except TransportError as exc:
                        card_failed = True
                        raise RemoteError(f"the card stopped answering: {exc}") from exc
                    body = bytes(data)
                    emit(
                        "relay < "
                        + redact_relayed_response(
                            body, sw1, sw2, apdu[1], redactor, unmasked=unmasked_transcript
                        )
                    )
                    report.apdus_relayed += 1
                    policy.observe(apdu, sw1, sw2)  # may raise after a failed authentication
                except RemoteError as exc:
                    if sealing:
                        exc.result = _drain(channel, str(exc), report, log, clock)
                    elif card_failed:
                        channel.send(proto.encode_frame(proto.apdu_error_frame(str(exc))))
                    raise
                channel.send(proto.encode_frame(proto.apdu_response_frame(body, sw1, sw2)))
                continue

            if isinstance(frame, proto.OpResult):
                report.result = frame.payload
                report.open_initialize_updates = {
                    ctx: n for ctx, n in policy.open_initialize_updates.items() if n
                }
                if started is not None:
                    report.seconds = clock() - started
                if not frame.ok:
                    raise _operation_error(op, frame.payload)
                return report

            raise RemoteProtocolError(f"unhandled frame {type(frame).__name__}")


def _drain(
    channel: FrameChannel,
    reason: str,
    report: RelayReport,
    log: Callable[[str], None],
    clock: Callable[[], float],
) -> dict[str, object] | None:
    """Refuse the command at hand and read on, within bounds, for the service's result.

    Every further command is answered with an error and none reaches the card.
    ``None`` when no result arrives.
    """
    refusal = proto.encode_frame(proto.apdu_error_frame(reason))
    deadline = clock() + DRAIN_SECONDS
    frames = 0
    try:
        channel.send(refusal)
        while frames < DRAIN_FRAMES:
            remaining = deadline - clock()
            if remaining <= 0:
                return None
            for obj in proto.decode_frames(channel.recv(timeout=remaining)):
                frames += 1
                if frames > DRAIN_FRAMES:
                    return None
                frame = proto.parse_server_frame(obj)
                if isinstance(frame, proto.LogMessage):
                    report.log_lines.append(frame.message)
                    log(frame.message)
                elif isinstance(frame, proto.ApduCommand):
                    # The service may swallow a refused command and send another.
                    channel.send(refusal)
                elif isinstance(frame, proto.OpResult):
                    return frame.payload
                else:
                    return None
    except RemoteError:
        return None
    return None


def ping(channel: FrameChannel, *, recv_timeout: float = PING_TIMEOUT) -> dict[str, object]:
    """Ask the service what it runs and what it offers. No card is involved.

    Returns the service's answer: its build, the operations it serves, the PIV
    applet builds it can install, its secure-channel policy. The service answers
    before any card exchange, so a frame that asks for the card is a protocol
    violation here rather than something to relay.
    """
    channel.send(proto.encode_frame(proto.hello_frame("ping")))
    pow_answered = 0
    while True:
        raw = channel.recv(timeout=recv_timeout)
        for obj in proto.decode_frames(raw):
            frame = proto.parse_server_frame(obj)

            if isinstance(frame, proto.LogMessage):
                continue

            if isinstance(frame, proto.PowChallenge):
                if pow_answered >= MAX_POW_CHALLENGES:
                    raise RemoteProtocolError(
                        "the service issued a second proof-of-work challenge in one operation"
                    )
                pow_answered += 1
                nonce = rpow.solve(frame.challenge, frame.bits)
                channel.send(proto.encode_frame(proto.pow_frame(nonce)))
                continue

            if isinstance(frame, proto.OpResult):
                if not frame.ok:
                    raise _operation_error("ping", frame.payload)
                return frame.payload

            raise RemoteProtocolError(
                "the service asked for the card during a ping, which involves none"
            )


def _operation_error(op: str, payload: dict[str, object]) -> RemoteOperationError:
    """The error for a result frame with ``ok`` false, classified."""
    found = rrefusal.classify(op, payload)
    return RemoteOperationError(
        found.message,
        result=payload,
        reason=found.reason,
        retry_in_seconds=found.retry_in_seconds,
        ref=found.ref,
    )
