"""DESFire EV2 authentication (AuthenticateEV2First) and secure messaging.

Session keys are derived per NXP AN12343 with an AES-CMAC KDF:

    SV1 = A5 5A 00 01 00 80 || RndA[15..14] || (RndA[13..8] XOR RndB[15..10])
          || RndB[9..0] || RndA[7..0]          -> SesAuthENC = CMAC(Kx, SV1)
    SV2 = 5A A5 00 01 00 80 || (same tail)     -> SesAuthMAC = CMAC(Kx, SV2)

(``RndA[15..14]`` is MSB-first notation: the first two bytes on the wire.)

Command MAC input is ``Cmd || CmdCtr(2 LE) || TI(4) || header+data``; the
transmitted MACt is the odd-indexed 8 bytes of the full CMAC. The counter
increments after each command; the response MAC covers
``RC || CmdCtr' || TI || data``. Authentication itself encrypts with the
*auth key* (AES-CBC, zero IV).
"""

from __future__ import annotations

import os
import zlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from cryptnox_id_cli.applets.mifare.desfire import (
    CMD_CHANGE_FILE_SETTINGS,
    CMD_CHANGE_KEY,
    CMD_FORMAT_PICC,
    STATUS_ADDITIONAL_FRAME,
    STATUS_OK,
    DesfireError,
    DesfireTransport,
)
from cryptnox_id_cli.transport.errors import CryptnoxError

CMD_AUTHENTICATE_EV2_FIRST = 0x71
CMD_ADDITIONAL_FRAME = 0xAF


class Ev2Error(CryptnoxError):
    """EV2 authentication / secure-messaging failure."""

    code = "ev2_error"
    exit_code = 11


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def _cbc(key: bytes, data: bytes, *, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _aes_cbc_iv(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    op = cipher.encryptor() if encrypt else cipher.decryptor()
    return op.update(data) + op.finalize()


def _pad_full(data: bytes) -> bytes:
    """EV2 encrypted-data padding (ISO 9797-1 method 2): ALWAYS append 0x80 then 0x00s to
    the next 16-byte boundary - a *whole* padding block when the data is already aligned.

    DESFire FULL writes require this. A block-aligned plaintext sent without the extra pad
    block desyncs the card's secure messaging: it keeps requesting additional frames and the
    command never completes (live-reproduced: a 16-byte FULL write hangs; 20-byte works)."""
    pad_len = 16 - (len(data) % 16)  # 1..16 - always >= 1, a full block when aligned
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def desfire_crc32(data: bytes) -> bytes:
    """DESFire CRC32 (reflected, poly 0xEDB88320, init 0xFFFFFFFF, NO final inversion),
    4 bytes little-endian. This is zlib's CRC32 *without* its final XOR, so the empty
    string maps to FF FF FF FF. Used inside the cross-key ChangeKey cryptogram."""
    return ((zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF).to_bytes(4, "little")


def rot_left(data: bytes) -> bytes:
    """Rotate a byte string left by one byte (RndA' / RndB')."""
    return data[1:] + data[:1]


def build_sv_base(rnda: bytes, rndb: bytes) -> bytes:
    """The 26-byte tail shared by SV1 and SV2."""
    xored = bytes(a ^ b for a, b in zip(rnda[2:8], rndb[0:6], strict=True))
    return rnda[0:2] + xored + rndb[6:16] + rnda[8:16]


def derive_session_keys(key: bytes, rnda: bytes, rndb: bytes) -> tuple[bytes, bytes]:
    base = build_sv_base(rnda, rndb)
    ses_enc = _aes_cmac(key, bytes([0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]) + base)
    ses_mac = _aes_cmac(key, bytes([0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]) + base)
    return ses_enc, ses_mac


def truncate_mac(full_cmac: bytes) -> bytes:
    """EV2 MACt: the odd-indexed bytes (1, 3, ..., 15) of the 16-byte CMAC."""
    return full_cmac[1::2]


@dataclass
class Ev2Session:
    k_enc: bytes
    k_mac: bytes
    ti: bytes
    cmd_ctr: int = 0
    key_no: int = field(default=0)

    def _mact(self, data: bytes) -> bytes:
        return truncate_mac(_aes_cmac(self.k_mac, data))

    def command_mac(self, cmd: int, payload: bytes) -> bytes:
        return self._mact(bytes([cmd]) + self.cmd_ctr.to_bytes(2, "little") + self.ti + payload)

    def response_mac(self, rc: int, data: bytes) -> bytes:
        return self._mact(bytes([rc]) + self.cmd_ctr.to_bytes(2, "little") + self.ti + data)


def authenticate_ev2_first(
    transport: DesfireTransport,
    key_no: int,
    key: bytes,
    *,
    rnda: bytes | None = None,
) -> Ev2Session:
    """Run AuthenticateEV2First with an AES key; returns an authenticated session.

    Raises :class:`Ev2Error` if the card's RndA' proof fails (wrong key / bad
    crypto) and :class:`DesfireError` on card-side rejection.
    """
    if len(key) != 16:
        raise Ev2Error("EV2 authentication requires a 16-byte AES key.")
    status, enc_rndb = transport.raw_command(
        CMD_AUTHENTICATE_EV2_FIRST, bytes([key_no, 0x00]), context="AuthenticateEV2First"
    )
    if status != STATUS_ADDITIONAL_FRAME:
        raise DesfireError(status, "AuthenticateEV2First")
    if len(enc_rndb) != 16:
        raise Ev2Error(f"unexpected E(RndB) length {len(enc_rndb)}.")
    rndb = _cbc(key, enc_rndb, encrypt=False)
    rnda = rnda or os.urandom(16)
    part2 = _cbc(key, rnda + rot_left(rndb), encrypt=True)
    status, enc_final = transport.raw_command(
        CMD_ADDITIONAL_FRAME, part2, context="AuthenticateEV2First (part 2)"
    )
    if status != STATUS_OK:
        raise DesfireError(status, "AuthenticateEV2First (part 2)")
    if len(enc_final) != 32:
        raise Ev2Error(f"unexpected final auth response length {len(enc_final)}.")
    final = _cbc(key, enc_final, encrypt=False)
    ti, rnda_proof = final[0:4], final[4:20]
    if rnda_proof != rot_left(rnda):
        raise Ev2Error("card RndA' proof mismatch - wrong key or broken session crypto.")
    ses_enc, ses_mac = derive_session_keys(key, rnda, rndb)
    return Ev2Session(k_enc=ses_enc, k_mac=ses_mac, ti=ti, key_no=key_no)


# Max bytes of the (header+data+MAC) stream per native frame. The ACR1252+card accept
# a single-frame Lc up to 54 here (probed); 48 keeps a safety margin. Larger payloads
# are split across 0x3D then 0xAF command-chaining frames.
MAX_COMMAND_FRAME = 0x30

# Upper bound on response-chaining (0xAF) frames pulled for one command. Generous - real
# responses fit in a handful of frames - but finite, so a desynced card that keeps asking
# for frames raises instead of hanging the CLI forever (see _pad_full for one trigger).
MAX_RESPONSE_FRAMES = 64


def _drain_response_frames(
    transport: DesfireTransport, status: int, acc: bytearray, ctx: str
) -> int:
    """Pull 0xAF response-continuation frames into ``acc``; return the final status."""
    frames = 0
    while status == STATUS_ADDITIONAL_FRAME:
        frames += 1
        if frames > MAX_RESPONSE_FRAMES:
            raise Ev2Error(
                f"{ctx}: card kept requesting response frames (>{MAX_RESPONSE_FRAMES}); "
                "aborting to avoid a hang."
            )
        status, more = transport.raw_command(CMD_ADDITIONAL_FRAME, context=f"{ctx} (AF)")
        acc += more
    return status


def command_macked(
    transport: DesfireTransport,
    session: Ev2Session,
    cmd: int,
    payload: bytes = b"",
    *,
    context: str | None = None,
    terminates_session: bool = False,
    max_frame: int = MAX_COMMAND_FRAME,
) -> bytes:
    """Send a command in EV2 CommMode.MAC and verify the response MAC.

    The MAC is computed over the whole command and appended; the resulting
    ``header||data||MAC`` stream is split across native frames when it exceeds one
    frame (first frame carries the real opcode, continuations use 0xAF, the card
    ACKs each non-final frame with 0x91AF). The command counter advances once.

    Commands that destroy the authenticated context (e.g. DeleteApplication of the
    selected application) end the session on success and reply WITHOUT a response
    MAC - pass ``terminates_session=True`` for those.
    """
    ctx = context or f"DESFire {cmd:02X} (MAC)"
    full = bytes(payload) + session.command_mac(cmd, payload)
    chunks = [full[i : i + max_frame] for i in range(0, len(full), max_frame)] or [b""]

    status, first = transport.raw_command(cmd, chunks[0], context=ctx)
    acc = bytearray(first)
    # Send the remaining command chunks; the card requests each with 0x91AF.
    for idx, chunk in enumerate(chunks[1:], start=1):
        if status != STATUS_ADDITIONAL_FRAME:
            raise Ev2Error(
                f"{ctx}: card did not request command frame {idx} (status 0x{status:02X})."
            )
        status, more = transport.raw_command(
            CMD_ADDITIONAL_FRAME, chunk, context=f"{ctx} (cmd frame {idx})"
        )
        acc += more
    # Then pull any response-chaining frames (card has more response data to send).
    status = _drain_response_frames(transport, status, acc, ctx)

    session.cmd_ctr += 1
    if status != STATUS_OK:
        raise DesfireError(status, ctx)
    if terminates_session and len(acc) == 0:
        return b""
    if len(acc) < 8:
        raise Ev2Error(f"{ctx}: response MAC missing.")
    data, mact_recv = bytes(acc[:-8]), bytes(acc[-8:])
    if session.response_mac(status, data) != mact_recv:
        raise Ev2Error(f"{ctx}: response MAC verification failed.")
    return data


def _full_iv(session: Ev2Session, marker: tuple[int, int]) -> bytes:
    block = bytes(marker) + session.ti + session.cmd_ctr.to_bytes(2, "little") + bytes(8)
    return _aes_ecb(session.k_enc, block)


def command_full(
    transport: DesfireTransport,
    session: Ev2Session,
    cmd: int,
    *,
    header: bytes = b"",
    plaintext: bytes = b"",
    response_len: int = 0,
    context: str | None = None,
    max_frame: int = MAX_COMMAND_FRAME,
) -> bytes:
    """Send a command in EV2 CommMode.FULL: the command header stays in the clear, the
    ``plaintext`` data is AES-CBC encrypted (IV = E(Kenc, A55A||TI||CmdCtr||0)), the
    whole ``header||ciphertext`` is MACed and chain-sent, and the response data is
    MAC-verified then decrypted (IV uses 5AA5||TI||CmdCtr after the counter advances).
    Returns the decrypted response truncated to ``response_len`` (0 = all)."""
    ctx = context or f"DESFire {cmd:02X} (FULL)"
    enc = (
        _aes_cbc_iv(
            session.k_enc, _full_iv(session, (0xA5, 0x5A)), _pad_full(plaintext), encrypt=True
        )
        if plaintext
        else b""
    )
    macked = bytes(header) + enc
    full = macked + session.command_mac(cmd, macked)
    chunks = [full[i : i + max_frame] for i in range(0, len(full), max_frame)] or [b""]

    status, first = transport.raw_command(cmd, chunks[0], context=ctx)
    acc = bytearray(first)
    for idx, chunk in enumerate(chunks[1:], start=1):
        if status != STATUS_ADDITIONAL_FRAME:
            raise Ev2Error(f"{ctx}: card did not request command frame {idx} (0x{status:02X}).")
        status, more = transport.raw_command(
            CMD_ADDITIONAL_FRAME, chunk, context=f"{ctx} (cmd {idx})"
        )
        acc += more
    status = _drain_response_frames(transport, status, acc, ctx)

    session.cmd_ctr += 1
    if status != STATUS_OK:
        raise DesfireError(status, ctx)
    if len(acc) == 0:
        return b""
    if len(acc) < 8:
        raise Ev2Error(f"{ctx}: response MAC missing.")
    resp_enc, mact_recv = bytes(acc[:-8]), bytes(acc[-8:])
    if session.response_mac(status, resp_enc) != mact_recv:
        raise Ev2Error(f"{ctx}: response MAC verification failed.")
    if not resp_enc:
        return b""
    plain = _aes_cbc_iv(session.k_enc, _full_iv(session, (0x5A, 0xA5)), resp_enc, encrypt=False)
    return plain[:response_len] if response_len else plain


def change_key_same(
    transport: DesfireTransport,
    session: Ev2Session,
    key_no: int,
    new_key: bytes,
    *,
    key_version: int = 0,
    context: str | None = None,
) -> None:
    """ChangeKey for the key the session is authenticated with (KeyNo == auth key).

    The encrypted KeyData is just ``NewKey || KeyVersion`` (no CRC - the secure-channel
    MAC provides integrity for the same-key case). The session is invalidated on
    success; re-authenticate with the new key. Cross-key change (XOR + CRC32) is not
    implemented.
    """
    if len(new_key) != 16:
        raise Ev2Error("AES key must be 16 bytes.")
    command_full(
        transport,
        session,
        CMD_CHANGE_KEY,
        header=bytes([key_no]),
        plaintext=bytes(new_key) + bytes([key_version & 0xFF]),
        context=context or "ChangeKey",
    )


def change_key_cross(
    transport: DesfireTransport,
    session: Ev2Session,
    key_no: int,
    new_key: bytes,
    old_key: bytes,
    *,
    key_version: int = 0,
    context: str | None = None,
) -> None:
    """ChangeKey for a key OTHER than the authentication key (KeyNo != auth key).

    The card cannot derive the target key from the session, so the encrypted KeyData is
    ``(NewKey XOR OldKey) || KeyVersion || CRC32(NewKey)``: the card XORs the first field
    with its stored old key and checks the recovered key against the CRC32. A wrong
    ``old_key`` therefore makes the CRC mismatch and the card rejects the change - it
    cannot silently brick the slot. Re-authenticate with the new key afterwards.
    """
    if len(new_key) != 16 or len(old_key) != 16:
        raise Ev2Error("AES keys must be 16 bytes.")
    xored = bytes(a ^ b for a, b in zip(new_key, old_key, strict=True))
    plaintext = xored + bytes([key_version & 0xFF]) + desfire_crc32(new_key)
    command_full(
        transport,
        session,
        CMD_CHANGE_KEY,
        header=bytes([key_no]),
        plaintext=plaintext,
        context=context or "ChangeKey (cross)",
    )


def format_picc(
    transport: DesfireTransport,
    session: Ev2Session,
    *,
    context: str | None = None,
) -> None:
    """FormatPICC: erase ALL applications and files. The PICC master key and its
    settings survive. Must be authenticated with the PICC master key (AID 000000);
    sent in CommMode.MAC."""
    command_macked(transport, session, CMD_FORMAT_PICC, b"", context=context or "FormatPICC")


def change_file_settings(
    transport: DesfireTransport,
    session: Ev2Session,
    file_no: int,
    settings: bytes,
    *,
    context: str | None = None,
) -> None:
    """ChangeFileSettings (CommMode.FULL). ``settings`` = FileOption || AccessRights(2)
    [ || SDM config ]. To attach a Secure Dynamic Messaging config the file must have been
    created with the SDM file-option bit set (EV3: SDM is enabled at file creation)."""
    command_full(
        transport,
        session,
        CMD_CHANGE_FILE_SETTINGS,
        header=bytes([file_no]),
        plaintext=settings,
        context=context or "ChangeFileSettings",
    )


# --- Secure Dynamic Messaging (SDM / SUN) verification -- per NXP AN12196 (public). ---
# The card mirrors EncryptedPICCData (UID + read counter) and an SDMMAC into a free-read
# file; these helpers recover and verify them host-side.
def sdm_decrypt_picc(meta_read_key: bytes, enc_picc_data: bytes) -> tuple[bytes, int]:
    """Decrypt the mirrored EncryptedPICCData -> (uid, read_counter). AES-CBC, zero IV."""
    plain = _aes_cbc_iv(meta_read_key, bytes(16), enc_picc_data, encrypt=False)
    uid = plain[1:8]  # plain[0] = PICCDataTag; UID is 7 bytes; counter is 3 bytes LE
    read_counter = int.from_bytes(plain[8:11], "little")
    return uid, read_counter


def sdm_file_read_mac(
    file_read_key: bytes, uid: bytes, read_counter: int, mac_input: bytes = b""
) -> bytes:
    """SDMMAC over ``mac_input`` (8-byte truncated CMAC) under the per-read SDM session key."""
    sv = b"\x3c\xc3\x00\x01\x00\x80" + uid + read_counter.to_bytes(3, "little")
    session_key = _aes_cmac(file_read_key, sv)
    return truncate_mac(_aes_cmac(session_key, mac_input))
