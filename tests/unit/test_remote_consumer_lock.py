"""``remote consumer-lock``: relay rules, the key exchange, and the command. No socket, no card."""

import base64
import contextlib
import hashlib
import json
import os
import signal
import stat

import pytest
from _cardfakes import wire_session
from click.testing import CliRunner
from test_remote_gates import _FakeSys

from cryptnox_id_cli.cli.commands.remote import consumer_lock as remote_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.remote import channel as rchannel
from cryptnox_id_cli.remote import keysheet, relay
from cryptnox_id_cli.remote import policy as pol
from cryptnox_id_cli.remote import protocol as proto
from cryptnox_id_cli.transport.errors import (
    CryptnoxError,
    RemoteConnectError,
    RemoteError,
    RemotePolicyError,
    RemoteProtocolError,
    TransportError,
)

ATR = "3BFA1300FF910131FE000031C173C84000009000D2"
CPLC_CMD = "80CA9F7F00"
CPLC_RESP = (
    "9F7F2A4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
)
CARD_UID = "4301012345670042"
SELECT_ISD = "00A4040008A00000015100000000"
SELECT_SSD = "00A4040009A0000001515350410100"
INIT_UPDATE = "8050010008112233445566778800"
PUT_KEY = "84D8018118" + "AA" * 24
SELECT_PIV = "00A404000BA00000030800001000010000"
CRD_9B = "8424089B12" + "00" * 18
VERIFY_PIN = "0020008008" + "FF" * 8

NEW_KVN1 = "00112233445566778899AABBCCDDEEFF"
NEW_9B = "0F0E0D0C0B0A09080706050403020100"


def sheet(**overrides):
    out = {
        "v": 1,
        "op": "consumer-lock",
        "uid_sha256": hashlib.sha256(CARD_UID.lower().encode()).hexdigest(),
        "created": "2026-11-09T10:00:00Z",
        "scp": "SCP03",
        "ssd_kvn1": None,
        "mgmt_key_9b": {"AES128": NEW_9B},
        "kcv": {"mgmt_key_9b_aes128": keysheet.kcv_aes(bytes.fromhex(NEW_9B)).hex().upper()},
    }
    out.update(overrides)
    return out


def apdu(cla, ins, p1=0, p2=0, data=b"", le=True):
    out = bytes([cla, ins, p1, p2])
    if data:
        out += bytes([len(data)]) + data
    if le:
        out += b"\x00"
    return out


def select(aid: bytes) -> bytes:
    return apdu(0x00, 0xA4, 0x04, 0x00, aid)


def allow(policy, command, sw=(0x90, 0x00)):
    policy.check(command)
    policy.observe(command, *sw)


IU = apdu(0x80, 0x50, 0x01, 0x00, bytes(8))
EA_33 = apdu(0x84, 0x82, 0x33, 0x00, bytes(16), le=False)
PUT_KEY_CMD = apdu(0x84, 0xD8, 0x01, 0x81, bytes(24))


# --------------------------------------------------------------------------- #
# Relay rules                                                                 #
# --------------------------------------------------------------------------- #
def test_the_lock_sequence_passes():
    p = pol.RelayPolicy("consumer-lock")
    for aid in (pol.PIV_SSD_AID, pol.PIV_SSD_AID, pol.ISD_AID):
        allow(p, select(aid))
        allow(p, apdu(0x80, 0xCA, 0x00, 0xE0))
        allow(p, IU)
        allow(p, EA_33)
        allow(p, PUT_KEY_CMD)
    allow(p, select(pol.PIV_AID))
    allow(p, IU)
    allow(p, EA_33)
    allow(p, apdu(0x84, 0xCB, 0x3F, 0xFF, bytes(8)))  # enumeration, status, random
    allow(p, apdu(0x84, 0xDB, 0x3F, 0x00, bytes(16), le=False))  # create objects, NFC lock
    allow(p, apdu(0x84, 0x24, 0x08, 0x9B, bytes(18), le=False))  # 9B CLEAR + import
    allow(p, apdu(0x84, 0x87, 0x08, 0x9B, bytes(4)))  # 9B proof through the channel
    assert not p.open_initialize_updates.get(pol.PIV_SSD)


@pytest.mark.parametrize(
    ("context_aid", "command"),
    [
        (pol.ISD_AID, apdu(0x84, 0xE4, 0x00, 0x80, bytes.fromhex("4F07A0000010000112"))),
        (pol.ISD_AID, apdu(0x84, 0xE6, 0x0C, 0x00, bytes(20))),
        (pol.ISD_AID, apdu(0x84, 0xE8, 0x00, 0x00, bytes(20))),
        (pol.ISD_AID, apdu(0x84, 0xE2, 0x80, 0x00, bytes(20))),
        (pol.PIV_SSD_AID, apdu(0x84, 0xE4, 0x00, 0x80, bytes(10))),
        (pol.PIV_AID, apdu(0x00, 0x47, 0x00, 0x9A, bytes(5))),
        (pol.PIV_AID, apdu(0x00, 0x87, 0x07, 0x9A, bytes(4))),
        (pol.PIV_AID, apdu(0x00, 0x24, 0x00, 0x80, bytes(16))),
        (pol.PIV_AID, apdu(0x00, 0x24, 0x00, 0x81, bytes(16))),
        (pol.PIV_AID, apdu(0x00, 0x20, 0x00, 0x80, bytes(8))),
    ],
)
def test_nothing_beyond_replacing_keys_passes(context_aid, command):
    p = pol.RelayPolicy("consumer-lock")
    allow(p, select(context_aid))
    with pytest.raises(RemotePolicyError):
        p.check(command)


def test_the_wallet_stays_out_of_reach():
    p = pol.RelayPolicy("consumer-lock")
    with pytest.raises(RemotePolicyError, match="not allowed"):
        p.check(select(bytes.fromhex("A0000010000112")))


def test_authentication_attempts_are_capped_per_domain():
    p = pol.RelayPolicy("consumer-lock")
    allow(p, select(pol.PIV_SSD_AID))
    for _ in range(p.rules.max_initialize_updates):
        allow(p, IU)
    with pytest.raises(RemotePolicyError, match="more than"):
        p.check(IU)


@pytest.mark.parametrize(
    ("context_aid", "command"),
    [
        (pol.ISD_AID, PUT_KEY_CMD),
        (pol.PIV_SSD_AID, PUT_KEY_CMD),
        (pol.PIV_SSD_AID, IU),
        (pol.PIV_AID, apdu(0x84, 0xDB, 0x3F, 0x00, bytes(16), le=False)),
        (pol.PIV_AID, apdu(0x84, 0x24, 0x08, 0x9B, bytes(18), le=False)),
        (pol.PIV_AID, apdu(0x00, 0x87, 0x08, 0x9B, bytes(4))),
    ],
)
def test_a_dry_run_cannot_write_even_if_the_service_tries(context_aid, command):
    p = pol.RelayPolicy("consumer-lock", dry_run=True)
    allow(p, select(context_aid))
    with pytest.raises(RemotePolicyError):
        p.check(command)


def test_a_dry_run_reads_and_opens_the_applet_channel():
    p = pol.RelayPolicy("consumer-lock", dry_run=True)
    allow(p, apdu(0x80, 0xCA, 0x9F, 0x7F))
    allow(p, select(pol.PIV_SSD_AID))
    allow(p, apdu(0x80, 0xCA, 0x00, 0xE0))
    allow(p, select(pol.PIV_AID))
    allow(p, IU)
    allow(p, EA_33)
    allow(p, apdu(0x84, 0xCB, 0x3F, 0xFF, bytes(8)))


def test_other_operations_have_no_dry_run_rules():
    with pytest.raises(RemotePolicyError, match="no dry-run relay policy"):
        pol.RelayPolicy("reset", dry_run=True)


# --------------------------------------------------------------------------- #
# The kex frame                                                               #
# --------------------------------------------------------------------------- #
def kex_frame(public_key: bytes | None = None, **overrides):
    if public_key is None:
        public_key = keysheet.public_bytes(keysheet.generate_kex())
    frame = {
        "type": "kex",
        "pub": base64.b64encode(public_key).decode(),
        "fields": ["ssd_kvn1"],
        "context": keysheet.PROVIDED_CONTEXT.decode(),
    }
    frame.update(overrides)
    return frame


def test_a_kex_frame_parses():
    pub = keysheet.public_bytes(keysheet.generate_kex())
    frame = proto.parse_server_frame(kex_frame(pub, fields=["ssd_kvn1", "mgmt_key_9b"]))
    assert frame == proto.KexRequest(
        public_key=pub,
        fields=("ssd_kvn1", "mgmt_key_9b"),
        context="cryptnox/consumer-lock/provided/v1",
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"pub": "not base64!"},
        {"pub": "QQ==" * 40},
        {"pub": base64.b64encode(b"\x04" + bytes(64)).decode()},
        {"pub": base64.b64encode(bytes(65)).decode()},
        {"fields": []},
        {"fields": "ssd_kvn1"},
        {"fields": ["a", "b", "c", "d", "e"]},
        {"fields": [1]},
        {"context": "x" * 65},
        {"context": None},
    ],
)
def test_a_malformed_kex_frame_is_refused(overrides):
    with pytest.raises(RemoteProtocolError):
        proto.parse_server_frame(kex_frame(**overrides))


class ScriptedChannel:
    """Plays server frames in order. A callable entry builds its frame from what was sent."""

    def __init__(self, script):
        self.script = list(script)
        self.sent: list[dict] = []

    def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    def recv(self, timeout=None) -> str:
        if not self.script:
            raise RemoteConnectError("script exhausted: the service went silent")
        item = self.script.pop(0)
        return json.dumps(item(self.sent) if callable(item) else item)

    def close(self) -> None:
        pass


def test_the_relay_hands_a_kex_to_the_callback(mock_connection):
    channel = ScriptedChannel([kex_frame(), {"type": "result", "ok": True}])
    seen = []

    def answer(frame):
        seen.append(frame.fields)
        return b"\x01\x02"

    report = relay.run_operation(
        channel, mock_connection(ATR, {}, []), "consumer-lock", answer_kex=answer
    )
    assert seen == [("ssd_kvn1",)]
    assert report.kex_fields == ("ssd_kvn1",)
    assert channel.sent[1] == {"type": "kex_resp", "blob": "AQI="}


def test_a_kex_without_a_callback_ends_the_operation(mock_connection):
    channel = ScriptedChannel([kex_frame()])
    with pytest.raises(RemoteProtocolError, match="takes none"):
        relay.run_operation(channel, mock_connection(ATR, {}, []), "inspect")


def test_a_second_kex_is_refused(mock_connection):
    channel = ScriptedChannel([kex_frame(), kex_frame()])
    with pytest.raises(RemoteProtocolError, match="twice"):
        relay.run_operation(
            channel, mock_connection(ATR, {}, []), "consumer-lock", answer_kex=lambda f: b"x"
        )


def test_a_refused_kex_is_answered_with_an_error_then_ends(mock_connection):
    channel = ScriptedChannel([kex_frame()])

    def answer(frame):
        raise CryptnoxError("no such value here")

    with pytest.raises(CryptnoxError, match="no such value"):
        relay.run_operation(
            channel, mock_connection(ATR, {}, []), "consumer-lock", answer_kex=answer
        )
    assert channel.sent[-1] == {"type": "kex_resp", "error": "no such value here"}


# --------------------------------------------------------------------------- #
# The command                                                                 #
# --------------------------------------------------------------------------- #
@pytest.fixture
def wired(monkeypatch, mock_connection):
    conn = mock_connection(
        ATR,
        {
            SELECT_ISD: "6F108408A000000151000000A5049F6501FF|9000",
            CPLC_CMD: f"{CPLC_RESP}|9000",
            SELECT_SSD: "|9000",
            INIT_UPDATE: "00" * 29 + "|9000",
            PUT_KEY: "01" + "AABBCC" * 3 + "|9000",
            SELECT_PIV: "|9000",
            CRD_9B: "|9000",
        },
        [],
    )
    wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
    holder: dict = {"conn": conn, "sessions": 0}
    real_open_session = AppContext.open_session

    def counted_open_session(self):
        holder["sessions"] += 1
        return real_open_session(self)

    monkeypatch.setattr(AppContext, "open_session", counted_open_session)

    @contextlib.contextmanager
    def fake_open(url, **kwargs):
        holder["url"] = url
        yield holder["channel"]

    monkeypatch.setattr(rchannel, "open_channel", fake_open)
    monkeypatch.delenv(rchannel.URL_ENV, raising=False)
    for name in (
        remote_cmd.KEYSHEET_PASSPHRASE_ENV,
        remote_cmd.PROVIDED_SSD_KEY1_ENV,
        remote_cmd.PROVIDED_MGMT_KEY_ENV,
    ):
        monkeypatch.delenv(name, raising=False)

    def arm(script):
        holder["channel"] = ScriptedChannel(script)
        return holder["channel"]

    holder["arm"] = arm
    return holder


def run(args, **kwargs):
    return CliRunner().invoke(root, args, **kwargs)


def client_key(sent) -> bytes:
    return base64.b64decode(sent[0]["params"]["client_kex_pub"])


def delivered(payload_sheet, **result):
    """A result frame carrying ``payload_sheet`` encrypted to the client's key."""

    def build(sent):
        blob = keysheet.encrypt_to(
            client_key(sent), payload_sheet, context=keysheet.KEY_SHEET_CONTEXT
        )
        return {
            "type": "result",
            "op": "consumer-lock",
            "cplc_uid": CARD_UID,
            "key_sheet": base64.b64encode(blob).decode(),
            **result,
        }

    return build


LOCK = ["remote", "consumer-lock", "--i-understand-this-is-irreversible"]
SCRIPT = [
    {"type": "apdu", "hex": SELECT_SSD},
    {"type": "apdu", "hex": INIT_UPDATE},
    {"type": "apdu", "hex": PUT_KEY},
]


@pytest.fixture
def unreachable(monkeypatch):
    """Neither the reader nor the service may be reached."""

    def boom(*a, **k):
        raise AssertionError("neither the reader nor the service may be reached")

    monkeypatch.setattr(AppContext, "open_session", boom)
    monkeypatch.setattr(rchannel, "open_channel", boom)
    monkeypatch.delenv(rchannel.URL_ENV, raising=False)


def test_delivered_keys_need_somewhere_to_go(unreachable):
    result = run(LOCK)
    assert result.exit_code == 2
    assert "--sheet-out" in result.output


def test_keep_needs_somewhere_to_go(unreachable):
    result = run([*LOCK, "--ssd-key1", "keep", "--mgmt-key", "skip"])
    assert result.exit_code == 2
    assert "--sheet-out" in result.output


def test_show_once_needs_a_terminal(unreachable, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: False)
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 2
    assert "terminal" in result.output


def test_a_lock_saves_the_keys_encrypted_and_prints_none(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    channel = wired["arm"]([*SCRIPT, delivered(sheet(), ok=True, stage="done")])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 0, result.output

    hello = channel.sent[0]
    assert hello["op"] == "consumer-lock"
    params = hello["params"]
    assert params["confirm"] == "SEAL-CARD"
    assert params["fused"] is True
    assert params["dry_run"] is False
    assert (params["ssd_key1"], params["mgmt_key"]) == ("seal", "generate")
    assert len(client_key(channel.sent)) == 65

    assert NEW_9B not in result.output
    payload = json.loads(result.stdout)
    assert payload["result"]["key_sheet"] == "decrypted locally"
    assert payload["key_sheet"]["saved_to"] == str(out)
    assert payload["key_sheet"]["keys"] == ["mgmt_key_9b_aes128"]
    assert payload["verified_locally"]["key_sheet_kcv_match"] is True
    assert payload["verified_locally"]["key_sheet_for_this_card"] is True
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()

    shown = run(["--json", "remote", "key-sheet", str(out)])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.stdout)["keys"] == {"mgmt_key_9b_aes128": NEW_9B}


def test_a_wrong_passphrase_on_the_sheet_exits_17(wired, tmp_path, monkeypatch):
    out = tmp_path / "card.cnxks"
    out.write_bytes(keysheet.seal_file(sheet(), "right"))
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "wrong")
    result = run(["remote", "key-sheet", str(out)])
    assert result.exit_code == 17


def test_show_once_prints_the_keys_on_stderr(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(["--json", *LOCK, "--show-once"])
    assert result.exit_code == 0, result.output
    assert NEW_9B not in result.stdout
    assert NEW_9B in result.stderr
    assert json.loads(result.stdout)["key_sheet"]["shown"] is True


@pytest.mark.parametrize("uid_sha256", [hashlib.sha256(b"0000000000000000").hexdigest(), "00" * 32])
def test_a_sheet_for_another_card_exits_17(wired, monkeypatch, uid_sha256):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    wired["arm"]([delivered(sheet(uid_sha256=uid_sha256), ok=True)])
    result = run(["--json", *LOCK, "--show-once"])
    assert result.exit_code == 17, result.output
    error = json.loads(result.stdout)
    assert error["error"] == "key_sheet"
    assert "made for another card" in error["message"]
    assert "shown on the terminal as delivered" in error["message"]
    assert error["verified_locally"]["key_sheet_for_this_card"] is False
    assert error["key_sheet"]["shown"] is True
    assert NEW_9B in result.stderr


def test_keys_that_do_not_match_their_check_values_exit_17(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(kcv={"mgmt_key_9b_aes128": "000000"}), ok=True)])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 17, result.output
    error = json.loads(result.stdout)
    assert error["error"] == "key_sheet"
    assert "do not match the check values" in error["message"]
    assert f"saved to {out} as delivered" in error["message"]
    assert error["key_sheet"]["kcv_match"] is False
    assert error["verified_locally"]["key_sheet_kcv_match"] is False
    assert error["result"]["ok"] is True
    assert keysheet.open_file(out.read_bytes(), "sheet pass")["kcv"] == {
        "mgmt_key_9b_aes128": "000000"
    }


def test_a_check_mismatch_is_reported_once_in_human_output(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(kcv={"mgmt_key_9b_aes128": "000000"}), ok=True)])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 17, result.output
    assert "check values match: no" in result.stdout
    assert result.stderr.count("do not match the check values") == 1


def test_owner_values_travel_encrypted_to_the_service(wired, monkeypatch):
    monkeypatch.setenv(remote_cmd.PROVIDED_SSD_KEY1_ENV, NEW_KVN1.lower())
    monkeypatch.setenv(remote_cmd.PROVIDED_MGMT_KEY_ENV, NEW_9B)
    service_key = keysheet.generate_kex()
    received = {}

    def result_after_kex(sent):
        blob = base64.b64decode(sent[-1]["blob"])
        received.update(keysheet.decrypt(service_key, blob, context=keysheet.PROVIDED_CONTEXT))
        return {"type": "result", "ok": True, "cplc_uid": CARD_UID, "key_sheet": None}

    channel = wired["arm"](
        [
            kex_frame(keysheet.public_bytes(service_key), fields=["ssd_kvn1", "mgmt_key_9b"]),
            result_after_kex,
        ]
    )
    result = run(["--json", *LOCK, "--ssd-key1", "provided", "--mgmt-key", "provided"])
    assert result.exit_code == 0, result.output
    assert received == {"ssd_kvn1": NEW_KVN1, "mgmt_key_9b": NEW_9B}
    wire = json.dumps(channel.sent).upper()
    assert NEW_KVN1 not in wire
    assert NEW_9B not in wire
    assert json.loads(result.stdout)["key_sheet"] == {"delivered": False}


def test_a_value_the_run_does_not_supply_is_refused(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    channel = wired["arm"]([kex_frame(fields=["ssd_kvn1"])])
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 14
    assert channel.sent[-1]["type"] == "kex_resp"
    assert "does not supply" in channel.sent[-1]["error"]


def test_a_kex_under_another_context_is_refused(wired, monkeypatch):
    monkeypatch.setenv(remote_cmd.PROVIDED_SSD_KEY1_ENV, NEW_KVN1)
    wired["arm"]([kex_frame(context="cryptnox/something-else/v1")])
    result = run([*LOCK, "--ssd-key1", "provided", "--mgmt-key", "skip"])
    assert result.exit_code == 14
    assert "unknown context" in result.output


@pytest.mark.parametrize("value", ["00" * 15, "zz" * 16])
def test_a_bad_owner_value_stops_before_the_card(wired, monkeypatch, value):
    monkeypatch.setenv(remote_cmd.PROVIDED_SSD_KEY1_ENV, value)
    wired["arm"]([])
    result = run([*LOCK, "--ssd-key1", "provided", "--mgmt-key", "skip"])
    assert result.exit_code == 3
    assert "url" not in wired
    assert wired["sessions"] == 0


def failed_after(payload_sheet, **extra):
    return delivered(
        payload_sheet,
        ok=False,
        error="GpKeyError: PUT KEY refused",
        stage="partial:ssd_kvn1",
        recovery="retry",
        **extra,
    )


def test_a_failure_after_delivery_still_saves_the_keys(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([*SCRIPT, failed_after(sheet())])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 16
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()
    text = " ".join(result.output.split())
    assert "The 9B management key may already be on the delivered value" in text
    assert "key version 1" not in text.split("partly changed")[1]
    assert f"saved, encrypted, to {out}" in text
    assert "check values match: yes" in text
    assert "recovery note: retry" in result.output
    assert NEW_9B not in result.output


def test_a_failure_under_keep_and_skip_names_key_version_1(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    kvn1_sheet = sheet(
        ssd_kvn1=NEW_KVN1,
        mgmt_key_9b={},
        kcv={"ssd_kvn1": keysheet.kcv_aes(bytes.fromhex(NEW_KVN1)).hex().upper()},
    )
    wired["arm"]([*SCRIPT, failed_after(kvn1_sheet)])
    result = run([*LOCK, "--ssd-key1", "keep", "--mgmt-key", "skip", "--sheet-out", str(out)])
    assert result.exit_code == 16, result.output
    text = " ".join(result.output.split())
    assert "Key version 1 of the PIV security domain may already be on the delivered value" in text
    assert "9B" not in text.split("partly changed")[1]


def test_a_failure_with_no_write_relayed_warns_of_no_change(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([failed_after(sheet())])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 16
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()
    assert "partly changed" not in result.output


def test_a_failed_lock_reports_where_the_keys_went_in_json(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([*SCRIPT, failed_after(sheet())])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 16
    error = json.loads(result.stdout)
    assert error["error"] == "remote_failed"
    assert error["key_sheet"]["saved_to"] == str(out)
    assert error["key_sheet"]["kcv_match"] is True
    assert error["result"]["key_sheet"] == "decrypted locally"


def test_a_failed_lock_whose_keys_do_not_decrypt_says_so_in_json(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: False)
    out = tmp_path / "card.cnxks"

    def failed_for_someone_else(sent):
        other = keysheet.public_bytes(keysheet.generate_kex())
        blob = keysheet.encrypt_to(other, sheet(), context=keysheet.KEY_SHEET_CONTEXT)
        return {**PARTIAL, "key_sheet": base64.b64encode(blob).decode()}

    wired["arm"]([*SCRIPT, failed_for_someone_else])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 16, result.output
    error = json.loads(result.stdout)
    assert error["error"] == "remote_failed"
    assert error["key_sheet"]["lost"] is True
    assert error["key_sheet"]["decrypted"] is False
    assert error["result"]["key_sheet"] == "not decrypted"
    assert result.stderr.count("are lost") == 1
    assert not out.exists()


def test_a_failure_before_delivery_leaves_no_file(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([{"type": "result", "ok": False, "error": "refused", "stage": "checks"}])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 16
    assert not out.exists()


def test_an_existing_sheet_file_is_never_overwritten(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    out.write_bytes(b"keep me")
    wired["arm"]([])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 1
    assert "exists" in result.output
    assert out.read_bytes() == b"keep me"
    assert "url" not in wired
    assert wired["sessions"] == 0


def test_an_existing_sheet_file_is_refused_before_the_phrase(wired, tmp_path, monkeypatch):
    monkeypatch.setattr(remote_cmd, "sys", _FakeSys())
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    out.write_bytes(b"keep me")
    wired["arm"]([])
    result = run(["remote", "consumer-lock", "--sheet-out", str(out)], input="SEAL-CARD\n")
    assert result.exit_code == 1
    assert "exists" in result.output
    assert "Type SEAL-CARD" not in result.output
    assert wired["sessions"] == 0


def test_no_consent_no_lock(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([])
    result = run(["remote", "consumer-lock", "--sheet-out", str(out)])
    assert result.exit_code == 1
    assert "--i-understand-this-is-irreversible" in result.output
    assert "url" not in wired
    assert not out.exists()


def test_the_warning_names_what_is_lost(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 0, result.output
    text = " ".join(result.output.split())
    assert "Cryptnox included" in text
    assert "This cannot be undone" in text
    assert "--ssd-key1 seal" in text


def test_a_dry_run_asks_nothing_and_writes_nothing(wired):
    channel = wired["arm"]([{"type": "apdu", "hex": SELECT_SSD}, {"type": "apdu", "hex": PUT_KEY}])
    result = run(["--dry-run", "remote", "consumer-lock"])
    assert result.exit_code == 15, result.output
    assert channel.sent[0]["params"]["dry_run"] is True
    assert "INS D8 is not allowed" in result.output
    assert "error" in channel.sent[-1]


def test_a_dry_run_returns_the_plan(wired):
    wired["arm"](
        [
            {"type": "apdu", "hex": SELECT_SSD},
            {"type": "result", "ok": True, "dry_run": True, "plan": ["R1 rotate 9B"]},
        ]
    )
    result = run(["--json", "--dry-run", "remote", "consumer-lock"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["result"]["plan"] == ["R1 rotate 9B"]


def test_keys_that_do_not_decrypt_are_reported_lost(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)

    def for_someone_else(sent):
        other = keysheet.public_bytes(keysheet.generate_kex())
        blob = keysheet.encrypt_to(other, sheet(), context=keysheet.KEY_SHEET_CONTEXT)
        return {"type": "result", "ok": True, "key_sheet": base64.b64encode(blob).decode()}

    wired["arm"]([for_someone_else])
    result = run(["--json", *LOCK, "--show-once"])
    assert result.exit_code == 17
    error = json.loads(result.stdout)
    assert error["error"] == "key_sheet"
    assert error["key_sheet"]["lost"] is True
    assert error["key_sheet"]["decrypted"] is False
    assert error["result"]["key_sheet"] == "not decrypted"
    assert error["op"] == "consumer-lock"

    wired["arm"]([for_someone_else])
    human = run([*LOCK, "--show-once"])
    assert human.exit_code == 17
    assert human.stderr.count("are lost") == 1


class _Writer:
    """A real file object whose writes go through ``alter``."""

    def __init__(self, fh, alter):
        self._fh = fh
        self._alter = alter

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._fh.close()

    def write(self, data):
        return self._alter(self._fh, data)

    def flush(self):
        self._fh.flush()

    def fileno(self):
        return self._fh.fileno()


def patch_writes(monkeypatch, alter):
    real = os.fdopen
    monkeypatch.setattr(
        remote_cmd.os, "fdopen", lambda fd, *a, **k: _Writer(real(fd, *a, **k), alter)
    )


def disk_full(fh, data):
    fh.write(data[:10])
    fh.flush()
    raise OSError(28, "No space left on device")


def test_a_sheet_that_cannot_be_written_falls_back_to_the_terminal(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    patch_writes(monkeypatch, disk_full)
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 0, result.output
    assert NEW_9B in result.stderr
    assert "shown on the terminal instead" in result.stderr
    assert not out.exists()


def test_a_sheet_that_cannot_be_written_with_no_terminal_is_lost(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: False)
    patch_writes(monkeypatch, disk_full)
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 17, result.output
    assert "lost" in result.stderr
    assert NEW_9B not in result.output
    assert not out.exists()

    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 17
    assert json.loads(result.stdout)["key_sheet"]["lost"] is True
    assert not out.exists()


def test_a_sheet_that_does_not_read_back_is_not_counted_as_saved(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    patch_writes(monkeypatch, lambda fh, data: fh.write(data[:-1] + bytes([data[-1] ^ 1])))
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["key_sheet"]["saved_to"] is None
    assert "does not read back" in result.stderr
    assert NEW_9B in result.stderr
    assert not out.exists()


def test_the_sheet_file_is_opened_in_binary_mode(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    binary = 1 << 30
    monkeypatch.setattr(os, "O_BINARY", binary, raising=False)
    real_open = os.open
    seen = []

    def spy(path, flags, *a, **k):
        seen.append((os.fspath(path), flags))
        return real_open(path, flags & ~binary, *a, **k)

    monkeypatch.setattr(os, "open", spy)
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 0, result.output
    assert [flags & binary for path, flags in seen if path == str(out)] == [binary]
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()


def test_the_sheet_is_synced_to_disk_before_it_counts_as_saved(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    real_fsync = os.fsync
    synced = []

    def spy(fd):
        info = os.fstat(fd)
        synced.append((stat.S_ISREG(info.st_mode), info.st_size))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["key_sheet"]["saved_to"] == str(out)
    assert (True, out.stat().st_size) in synced


def test_human_output_names_the_keys_and_never_shows_them(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([delivered(sheet(), ok=True, stage="done")])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 0, result.output
    assert "Delivered keys" in result.output
    assert "mgmt_key_9b_aes128" in result.output
    assert NEW_9B not in result.output

    shown = run(["remote", "key-sheet", str(out)])
    assert shown.exit_code == 0, shown.output
    assert NEW_9B in shown.output
    assert "PIV_MGMT_KEY" in shown.output


def test_a_kex_key_off_the_curve_is_a_protocol_error(wired, monkeypatch):
    monkeypatch.setenv(remote_cmd.PROVIDED_SSD_KEY1_ENV, NEW_KVN1)
    wired["arm"]([kex_frame(b"\x04" + bytes(64))])
    result = run([*LOCK, "--ssd-key1", "provided", "--mgmt-key", "skip"])
    assert result.exit_code == 14, result.output
    assert "not a P-256 point" in result.output


def test_a_success_without_the_keys_it_should_deliver_exits_17(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"]([*SCRIPT, {"type": "result", "ok": True, "cplc_uid": CARD_UID}])
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 17, result.output
    error = json.loads(result.stdout)
    assert error["error"] == "key_sheet"
    assert error["key_sheet"]["lost"] is True
    assert error["key_sheet"]["delivered"] is False
    assert "delivered no key sheet" in error["message"]
    assert not out.exists()


def test_keys_the_run_did_not_ask_for_are_lost_without_a_terminal(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: False)
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(
        ["--json", *LOCK, "--mgmt-key", "provided"],
        env={remote_cmd.PROVIDED_MGMT_KEY_ENV: NEW_KVN1},
    )
    assert result.exit_code == 17, result.output
    error = json.loads(result.stdout)
    assert error["key_sheet"]["lost"] is True
    assert error["key_sheet"]["decrypted"] is True
    assert "did not ask for" in error["message"]
    assert "ask for none" in result.stderr
    assert NEW_9B not in result.output


def test_keys_the_run_did_not_ask_for_are_shown_on_a_terminal(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(
        ["--json", *LOCK, "--mgmt-key", "provided"],
        env={remote_cmd.PROVIDED_MGMT_KEY_ENV: NEW_KVN1},
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["key_sheet"]["shown"] is True
    assert NEW_9B in result.stderr
    assert NEW_9B not in result.stdout
    assert "ask for none" in result.stderr


AES192 = "000102030405060708090A0B0C0D0E0F1011121314151617"


def test_an_aes192_management_key_names_its_variable(wired, tmp_path, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    s192 = sheet(
        mgmt_key_9b={"AES192": AES192},
        kcv={"mgmt_key_9b_aes192": keysheet.kcv_aes(bytes.fromhex(AES192)).hex().upper()},
    )

    def line_after_key(text):
        lines = text.splitlines()
        return lines[next(n for n, line in enumerate(lines) if AES192 in line) + 1]

    wired["arm"]([delivered(s192, ok=True)])
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 0, result.output
    assert "PIV_MGMT_KEY" in line_after_key(result.stderr)

    out = tmp_path / "card.cnxks"
    out.write_bytes(keysheet.seal_file(s192, "sheet pass"))
    shown = run(
        ["remote", "key-sheet", str(out)], env={remote_cmd.KEYSHEET_PASSPHRASE_ENV: "sheet pass"}
    )
    assert shown.exit_code == 0, shown.output
    assert "PIV_MGMT_KEY" in line_after_key(shown.output)


def test_text_in_a_delivered_sheet_is_printed_inert(wired, tmp_path, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    odd = sheet(scp="SCP02", mgmt_key_9b={"[/b]": "\x1b[2J" + NEW_9B}, kcv={})
    wired["arm"]([delivered(odd, ok=True)])
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stderr
    assert NEW_9B in result.stderr

    out = tmp_path / "card.cnxks"
    out.write_bytes(keysheet.seal_file(odd, "sheet pass"))
    shown = run(
        ["remote", "key-sheet", str(out)], env={remote_cmd.KEYSHEET_PASSPHRASE_ENV: "sheet pass"}
    )
    assert shown.exit_code == 0, shown.output
    assert "\x1b" not in shown.output
    assert "mgmt_key_9b_[/b]" in shown.output


@pytest.mark.parametrize(("typed", "proceeds"), [("seal-card", False), ("SEAL-CARD", True)])
def test_the_phrase_must_be_typed_exactly(wired, monkeypatch, typed, proceeds):
    monkeypatch.setattr(remote_cmd, "sys", _FakeSys())
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run(["remote", "consumer-lock", "--show-once"], input=f"{typed}\n")
    assert "Type SEAL-CARD" in result.output
    if proceeds:
        assert result.exit_code == 0, result.output
        assert NEW_9B in result.stderr
    else:
        assert result.exit_code != 0
        assert "url" not in wired


@pytest.mark.parametrize("flags", [["--json"], ["--yes", "--json"]])
def test_a_terminal_does_not_stand_in_for_the_flag_in_json_mode(wired, monkeypatch, flags):
    monkeypatch.setattr(remote_cmd, "sys", _FakeSys())
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run([*flags, "remote", "consumer-lock", "--show-once"])
    assert result.exit_code == 1
    assert "--i-understand-this-is-irreversible" in json.loads(result.stdout)["message"]
    assert "url" not in wired


def test_keep_delivers_key_version_1(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    kcv = {
        "ssd_kvn1": keysheet.kcv_aes(bytes.fromhex(NEW_KVN1)).hex().upper(),
        "mgmt_key_9b_aes128": keysheet.kcv_aes(bytes.fromhex(NEW_9B)).hex().upper(),
    }
    kept = sheet(ssd_kvn1=NEW_KVN1, kcv=kcv)
    out = tmp_path / "card.cnxks"
    channel = wired["arm"]([delivered(kept, ok=True)])
    result = run(["--json", *LOCK, "--ssd-key1", "keep", "--show-once", "--sheet-out", str(out)])
    assert result.exit_code == 0, result.output
    params = channel.sent[0]["params"]
    assert (params["ssd_key1"], params["mgmt_key"]) == ("keep", "generate")
    payload = json.loads(result.stdout)
    assert payload["key_sheet"]["keys"] == ["ssd_kvn1", "mgmt_key_9b_aes128"]
    assert payload["key_sheet"]["kcv_match"] is True
    assert NEW_KVN1 in result.stderr
    assert NEW_KVN1 not in result.stdout

    shown = run(["remote", "key-sheet", str(out)])
    assert shown.exit_code == 0, shown.output
    assert "PIV_SCP03_ENC" in shown.output


# --------------------------------------------------------------------------- #
# The card manager's level fallback                                           #
# --------------------------------------------------------------------------- #
def ea(level):
    return apdu(0x84, 0x82, level, 0x00, bytes(16), le=False)


def iu(kvn):
    return apdu(0x80, 0x50, kvn, 0x00, bytes(8))


def open_domain(aid, kvn, refused=()):
    """The service's open: SELECT, then 0x33, then 0x13 if the card refused 0x33."""
    out = [(select(aid), "9000")]
    for level in (0x33, 0x13):
        out.append((iu(kvn), "9000"))
        if level in refused:
            out.append((ea(level), "6982"))
            continue
        out.append((ea(level), "9000"))
        break
    return out


def rotate(aid, kvn, refused=()):
    """One key replacement as the service runs it: open, PUT KEY, re-open, old key, re-open."""
    out = open_domain(aid, kvn, refused)
    out.append((apdu(0x84, 0xD8, kvn, 0x81, bytes(60)), "9000"))
    out += open_domain(aid, kvn, refused)
    out += [(select(aid), "9000"), (iu(kvn), "9000")]
    out += open_domain(aid, kvn, refused)
    return out


def replay(policy, sequence):
    for command, sw in sequence:
        policy.check(command)
        policy.observe(command, int(sw[:2], 16), int(sw[2:], 16))


def r2_to_r4(isd_refused=()):
    return (
        rotate(pol.PIV_SSD_AID, 1)
        + rotate(pol.PIV_SSD_AID, 2)
        + rotate(pol.ISD_AID, 1, isd_refused)
    )


def test_the_key_replacements_pass():
    replay(pol.RelayPolicy("consumer-lock"), r2_to_r4())


def test_a_card_manager_refusing_level_33_is_opened_at_13():
    p = pol.RelayPolicy("consumer-lock")
    replay(p, r2_to_r4(isd_refused=(0x33,)))
    assert p.external_authenticates[pol.ISD] == 6
    assert not p.open_initialize_updates.get(pol.ISD)


def test_after_a_refused_level_only_13_may_follow():
    p = pol.RelayPolicy("consumer-lock")
    replay(p, [(select(pol.ISD_AID), "9000"), (iu(1), "9000"), (ea(0x33), "6982"), (iu(1), "9000")])
    with pytest.raises(RemotePolicyError, match="only 13 may follow"):
        p.check(ea(0x33))


def test_a_failed_retry_at_13_stops():
    p = pol.RelayPolicy("consumer-lock")
    replay(p, [(select(pol.ISD_AID), "9000"), (iu(1), "9000"), (ea(0x33), "6982"), (iu(1), "9000")])
    p.check(ea(0x13))
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE failed"):
        p.observe(ea(0x13), 0x69, 0x82)


@pytest.mark.parametrize(
    ("aid", "level", "sw"),
    [
        (pol.ISD_AID, 0x33, (0x63, 0x00)),  # a cryptogram failure, not a level refusal
        (pol.ISD_AID, 0x13, (0x69, 0x82)),  # 0x13 has no fallback below it
        (pol.PIV_SSD_AID, 0x33, (0x69, 0x82)),  # the PIV security domain already opened at 0x33
    ],
)
def test_other_failed_authentications_still_stop(aid, level, sw):
    p = pol.RelayPolicy("consumer-lock")
    replay(p, [(select(aid), "9000"), (iu(1), "9000")])
    p.check(ea(level))
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE failed"):
        p.observe(ea(level), *sw)


def test_level_refusals_are_admitted_once_per_open():
    p = pol.RelayPolicy("consumer-lock")
    for _ in range(3):
        replay(p, open_domain(pol.ISD_AID, 1, refused=(0x33,)))
    replay(p, [(select(pol.ISD_AID), "9000"), (iu(1), "9000")])
    p.check(ea(0x33))
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE failed"):
        p.observe(ea(0x33), 0x69, 0x82)


def test_other_operations_have_no_level_fallback():
    p = pol.RelayPolicy("reset")
    replay(p, [(select(pol.ISD_AID), "9000"), (iu(1), "9000")])
    p.check(ea(0x33))
    with pytest.raises(RemotePolicyError, match="EXTERNAL AUTHENTICATE failed"):
        p.observe(ea(0x33), 0x69, 0x82)


# --------------------------------------------------------------------------- #
# The time cap                                                                #
# --------------------------------------------------------------------------- #
def test_the_service_deadline_fires_before_the_relay_cap():
    service_budget, service_handshake = 300.0, 20.0
    assert pol.rules_for("consumer-lock").max_seconds >= service_budget + service_handshake + 60
    assert pol.rules_for("consumer-lock", dry_run=True).max_seconds == 300.0


# --------------------------------------------------------------------------- #
# A stop on this side: the service's result is still read                     #
# --------------------------------------------------------------------------- #
class RecordingCard:
    def __init__(self, responses=None, fail_on=None):
        self.responses = {k.upper(): v for k, v in (responses or {}).items()}
        self.fail_on = fail_on
        self.sent: list[str] = []

    def transmit(self, command):
        key = bytes(command).hex().upper()
        self.sent.append(key)
        if key == self.fail_on:
            raise TransportError("the reader went away")
        data, sw = self.responses.get(key, "|9000").split("|")
        sw_bytes = bytes.fromhex(sw)
        return list(bytes.fromhex(data)), sw_bytes[0], sw_bytes[1]

    def get_atr(self):
        return bytes.fromhex(ATR)

    def disconnect(self):
        pass


DELETE_IN_SSD = apdu(0x84, 0xE4, 0x00, 0x80, bytes(10)).hex().upper()
PARTIAL = {"type": "result", "ok": False, "stage": "partial:ssd_kvn1", "recovery": "retry"}


def test_a_refusal_answers_the_service_and_reads_its_result():
    channel = ScriptedChannel(
        [
            {"type": "apdu", "hex": SELECT_SSD},
            {"type": "apdu", "hex": DELETE_IN_SSD},
            {"type": "log", "msg": "consumer-lock FAILED at stage ssd_kvn1"},
            {"type": "apdu", "hex": SELECT_SSD},
            PARTIAL,
        ]
    )
    card = RecordingCard()
    report = relay.RelayReport(op="consumer-lock", result={})
    with pytest.raises(RemotePolicyError) as caught:
        relay.run_operation(channel, card, "consumer-lock", report=report)
    assert caught.value.result == {k: v for k, v in PARTIAL.items() if k != "type"}
    assert card.sent == [SELECT_SSD]
    refusals = [f for f in channel.sent if f.get("error")]
    assert len(refusals) == 2
    assert "INS E4" in refusals[0]["error"]
    assert report.log_lines == ["consumer-lock FAILED at stage ssd_kvn1"]
    assert caught.value.to_dict()["result"]["recovery"] == "retry"


def test_a_card_error_is_reported_to_the_service_and_its_result_read():
    channel = ScriptedChannel([{"type": "apdu", "hex": SELECT_SSD}, PARTIAL])
    card = RecordingCard(fail_on=SELECT_SSD)
    with pytest.raises(RemoteError, match="stopped answering") as caught:
        relay.run_operation(channel, card, "consumer-lock")
    assert caught.value.result is not None
    assert caught.value.result["stage"] == "partial:ssd_kvn1"


def test_writes_handed_to_the_card_are_recorded():
    channel = ScriptedChannel(
        [
            {"type": "apdu", "hex": SELECT_ISD},
            {"type": "apdu", "hex": PUT_KEY_CMD.hex()},
            {"type": "apdu", "hex": VERIFY_PIN},
        ]
    )
    report = relay.RelayReport(op="consumer-lock", result={})
    with pytest.raises(RemotePolicyError):
        relay.run_operation(channel, RecordingCard(), "consumer-lock", report=report)
    assert report.card_written is True
    assert report.card_manager_key_written is True


def test_the_wait_for_the_result_is_bounded_in_frames():
    logs = [{"type": "log", "msg": f"line {n}"} for n in range(relay.DRAIN_FRAMES + 10)]
    channel = ScriptedChannel([{"type": "apdu", "hex": VERIFY_PIN}, *logs, PARTIAL])
    with pytest.raises(RemotePolicyError) as caught:
        relay.run_operation(channel, RecordingCard(), "consumer-lock")
    assert caught.value.result is None
    assert len(channel.script) == 11  # ten logs and the result left unread


def test_the_wait_for_the_result_is_bounded_in_time():
    now = [0.0]

    class SlowChannel(ScriptedChannel):
        def recv(self, timeout=None):
            self.timeouts.append(timeout)
            now[0] += 20.0
            return super().recv(timeout)

    channel = SlowChannel(
        [{"type": "apdu", "hex": VERIFY_PIN}, *[{"type": "log", "msg": "busy"}] * 5, PARTIAL]
    )
    channel.timeouts = []
    with pytest.raises(RemotePolicyError) as caught:
        relay.run_operation(channel, RecordingCard(), "consumer-lock", clock=lambda: now[0])
    assert caught.value.result is None
    drain_timeouts = channel.timeouts[1:]
    assert drain_timeouts and all(t <= relay.DRAIN_SECONDS for t in drain_timeouts)
    assert len(drain_timeouts) == 2


def test_other_operations_stop_without_reading_on():
    result = {"type": "result", "ok": False}
    channel = ScriptedChannel([{"type": "apdu", "hex": VERIFY_PIN}, result])
    with pytest.raises(RemotePolicyError) as caught:
        relay.run_operation(channel, RecordingCard(), "inspect")
    assert caught.value.result is None
    assert channel.script == [result]
    assert [f["type"] for f in channel.sent] == ["hello"]


def failing_on(conn, command, monkeypatch):
    real = conn.transmit

    def transmit(apdu_bytes):
        if bytes(apdu_bytes).hex().upper() == command:
            raise TransportError("the reader went away")
        return real(apdu_bytes)

    monkeypatch.setattr(conn, "transmit", transmit)


def partial_result(**extra):
    return delivered(
        sheet(),
        ok=False,
        error="RemoteTransportError: client APDU error",
        stage="partial:ssd_kvn1",
        recovery="retry",
        **extra,
    )


def test_a_card_error_after_a_write_still_saves_the_keys(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    failing_on(wired["conn"], PUT_KEY, monkeypatch)
    channel = wired["arm"](
        [
            *SCRIPT,
            {"type": "log", "msg": "consumer-lock FAILED at stage ssd_kvn1"},
            partial_result(),
        ]
    )
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 12, result.output
    assert "stopped answering" in result.output
    assert channel.sent[-1] == {"type": "apdu_resp", "error": channel.sent[-1]["error"]}
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()
    assert "recovery note: retry" in result.output
    assert NEW_9B not in result.output


def test_a_refusal_after_a_9b_write_still_saves_the_keys(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    wired["arm"](
        [
            {"type": "apdu", "hex": SELECT_PIV},
            {"type": "apdu", "hex": CRD_9B},
            {"type": "apdu", "hex": VERIFY_PIN},
            partial_result(),
        ]
    )
    result = run(["--json", *LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 15, result.output
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()
    assert "recovery note: retry" in result.stderr
    error = json.loads(result.stdout)
    assert error["error"] == "remote_policy"
    assert error["result"]["stage"] == "partial:ssd_kvn1"
    assert error["result"]["key_sheet"] == "decrypted locally"


def test_the_time_cap_still_saves_the_keys(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    ticks = [0.0, 0.0, 500.0]

    def clock():
        return ticks.pop(0) if len(ticks) > 1 else ticks[0]

    real = relay.run_operation
    monkeypatch.setattr(relay, "run_operation", lambda *a, **k: real(*a, clock=clock, **k))
    wired["arm"]([*SCRIPT, partial_result()])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 12, result.output
    assert "exceeded 420 seconds" in result.output
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()
    assert "recovery note: retry" in result.output


def test_no_result_after_a_write_warns_the_card_may_be_partly_changed(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    failing_on(wired["conn"], PUT_KEY, monkeypatch)
    wired["arm"](SCRIPT)
    result = run([*LOCK, "--ssd-key1", "keep", "--sheet-out", str(out)])
    assert result.exit_code == 12, result.output
    text = " ".join(result.output.split())
    assert "the card may be partly changed" in text
    assert (
        "The 9B management key and key version 1 of the PIV security domain may hold a "
        "random value that was never delivered" in text
    )
    assert "Cryptnox can still rebuild the card with a reset" in text
    assert not out.exists()


def test_a_card_manager_write_says_the_card_may_not_be_rebuilt(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    failing_on(wired["conn"], PUT_KEY, monkeypatch)
    wired["arm"]([{"type": "apdu", "hex": SELECT_ISD}, {"type": "apdu", "hex": PUT_KEY}])
    result = run(
        [*LOCK, "--mgmt-key", "provided", "--show-once"],
        env={remote_cmd.PROVIDED_MGMT_KEY_ENV: NEW_9B},
    )
    assert result.exit_code == 12, result.output
    text = " ".join(result.output.split())
    assert "The 9B management key may hold the value you supplied" in text
    assert "Cryptnox may no longer be able to rebuild the card" in text


def test_no_write_no_partial_change_warning(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    failing_on(wired["conn"], SELECT_SSD, monkeypatch)
    wired["arm"](SCRIPT)
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 12, result.output
    assert "partly changed" not in result.output


# --------------------------------------------------------------------------- #
# Interrupts during the lock                                                  #
# --------------------------------------------------------------------------- #
def interrupt(times, frame, seen=None):
    """A script entry that delivers SIGINT ``times`` times, then plays ``frame``."""

    def entry(sent):
        handler = signal.getsignal(signal.SIGINT)
        if seen is not None:
            seen["sigint"] = handler
            seen["sighup"] = signal.getsignal(signal.SIGHUP) if hasattr(signal, "SIGHUP") else None
        for _ in range(times):
            handler(signal.SIGINT, None)
        return frame(sent) if callable(frame) else frame

    return entry


def test_one_interrupt_does_not_stop_the_lock(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    before = signal.getsignal(signal.SIGINT)
    seen: dict = {}
    wired["arm"]([interrupt(1, SCRIPT[0], seen), SCRIPT[1], SCRIPT[2], delivered(sheet(), ok=True)])
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 0, result.output
    assert "interrupt again to stop" in " ".join(result.stderr.split())
    assert seen["sigint"] is not before
    if hasattr(signal, "SIGHUP"):
        assert seen["sighup"] is signal.SIG_IGN
    assert signal.getsignal(signal.SIGINT) is before


def test_a_second_interrupt_stops_after_the_current_command_and_keeps_the_result(
    wired, tmp_path, monkeypatch
):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"
    before = signal.getsignal(signal.SIGINT)
    channel = wired["arm"]([SCRIPT[0], interrupt(2, SCRIPT[1]), partial_result()])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 12, result.output
    assert "stopped on request" in result.output
    assert channel.sent[-1]["type"] == "apdu_resp"
    assert "stopped on request" in channel.sent[-1]["error"]
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()
    assert signal.getsignal(signal.SIGINT) is before


def test_a_termination_request_stops_after_the_current_command(wired, tmp_path, monkeypatch):
    monkeypatch.setenv(remote_cmd.KEYSHEET_PASSPHRASE_ENV, "sheet pass")
    out = tmp_path / "card.cnxks"

    def terminate(sent):
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        return SCRIPT[1]

    wired["arm"]([SCRIPT[0], terminate, partial_result()])
    result = run([*LOCK, "--sheet-out", str(out)])
    assert result.exit_code == 12, result.output
    assert keysheet.open_file(out.read_bytes(), "sheet pass") == sheet()


def test_a_dry_run_leaves_interrupts_alone(wired):
    seen: dict = {}

    def look(sent):
        seen["sigint"] = signal.getsignal(signal.SIGINT)
        return {"type": "result", "ok": True, "dry_run": True}

    before = signal.getsignal(signal.SIGINT)
    wired["arm"]([look])
    result = run(["--dry-run", "remote", "consumer-lock"])
    assert result.exit_code == 0, result.output
    assert seen["sigint"] is before


def test_the_warning_says_not_to_interrupt(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)
    wired["arm"]([delivered(sheet(), ok=True)])
    result = run([*LOCK, "--show-once"])
    assert "Do not interrupt the command or remove the card" in " ".join(result.output.split())


# --------------------------------------------------------------------------- #
# Diagnostic output that fails during the lock                                #
# --------------------------------------------------------------------------- #
def test_a_failing_transcript_does_not_stop_the_lock():
    channel = ScriptedChannel(
        [
            {"type": "apdu", "hex": SELECT_SSD},
            {"type": "apdu", "hex": PUT_KEY},
            {"type": "apdu", "hex": INIT_UPDATE},
            {"type": "result", "ok": True},
        ]
    )
    lines: list[str] = []

    def transcript(line):
        if line.startswith("relay < ") and len(lines) == 3:
            raise OSError(28, "No space left on device")
        lines.append(line)

    report = relay.run_operation(channel, RecordingCard(), "consumer-lock", transcript=transcript)
    assert report.ok
    assert report.apdus_relayed == 3
    assert len(lines) == 3  # switched off after the failure
    assert len(report.warnings) == 1
    assert "No space left on device" in report.warnings[0]


def test_a_closed_output_stream_does_not_stop_the_lock():
    channel = ScriptedChannel(
        [
            {"type": "log", "msg": "starting"},
            {"type": "apdu", "hex": SELECT_SSD},
            {"type": "log", "msg": "still going"},
            {"type": "result", "ok": True},
        ]
    )

    def on_log(message):
        raise SystemExit(1)

    report = relay.run_operation(channel, RecordingCard(), "consumer-lock", on_log=on_log)
    assert report.ok
    assert report.log_lines == ["starting", "still going"]
    assert len(report.warnings) == 1


def test_a_failing_transcript_is_warned_about_after_the_lock(wired, monkeypatch):
    monkeypatch.setattr(remote_cmd, "_stderr_is_terminal", lambda: True)

    last: list[str] = [""]

    def broken(self, line):
        if line.startswith("relay < ") and last[0].startswith("relay > 84D8"):
            raise OSError(5, "Input/output error")
        last[0] = line

    monkeypatch.setattr(AppContext, "apdu_trace", broken)
    wired["arm"]([*SCRIPT, delivered(sheet(), ok=True)])
    result = run([*LOCK, "--show-once"])
    assert result.exit_code == 0, result.output
    assert "switched off and the operation carried on" in " ".join(result.output.split())
