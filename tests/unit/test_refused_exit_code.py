"""A command the card refuses ends with exit code 6, and still prints its result.

``piv pin verify`` with a wrong PIN used to print ``verified: false`` and exit 0; so did
a refused PIN or PUK change, a refused ``set-pin``, a refused certificate import and a
refused object write. A script that checked only the exit code took the refusal for a
success, and the next step ran with a PIN the card had not accepted (seen on a card:
the retries of the PIN were spent that way).

The result is still printed, on stdout, before the exit: it carries the status word and
the retries left, which the error object of an exception would not.
"""

from __future__ import annotations

import contextlib
import datetime
import json

import _cardfakes
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.cli.commands.piv.perso import certificates, data_objects, verifiers
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.apdu import Response

STATUS_WORD_EXIT = 6

SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
ATR = "3BD518FF81B1FE451FC38073C821106F"


def _pad(value: str) -> str:
    return (value.encode() + b"\xff" * (8 - len(value))).hex().upper()


VERIFY = "0020008008" + _pad("123456")
CHANGE_PIN = "0024008010" + _pad("123456") + _pad("654321")
UNBLOCK_PIN = "002C008010" + _pad("12345678") + _pad("654321")
CHANGE_PUK = "0024008110" + _pad("12345678") + _pad("87654321")

OK = Response(b"", 0x90, 0x00)


def _refusal(sw: int) -> Response:
    return Response(b"", sw >> 8, sw & 0xFF)


def _wire(monkeypatch, mock_connection, command: str, sw: str) -> None:
    exchanges = {
        SELECT_PIV: f"{APT}|9000",
        command: f"|{sw}",
        _cardfakes.PIV_GET_STATUS: f"{_cardfakes.PIV_STATUS_CONTACT}|9000",
    }
    conn = mock_connection(ATR, exchanges, [])
    _cardfakes.wire_session(monkeypatch, conn, reader_name=_cardfakes.CONTACT_READER)


# ------------------------------------------------------------- cardholder commands #
CARDHOLDER = [
    pytest.param(VERIFY, ["piv", "pin", "verify", "--pin", "123456"], "verified", id="pin-verify"),
    pytest.param(
        CHANGE_PIN,
        ["piv", "pin", "change", "--old-pin", "123456", "--new-pin", "654321"],
        "changed",
        id="pin-change",
    ),
    pytest.param(
        UNBLOCK_PIN,
        ["piv", "pin", "unblock", "--puk", "12345678", "--new-pin", "654321"],
        "changed",
        id="pin-unblock",
    ),
    pytest.param(
        CHANGE_PUK,
        ["piv", "puk", "change", "--old-puk", "12345678", "--new-puk", "87654321"],
        "changed",
        id="puk-change",
    ),
]


@pytest.mark.parametrize(("command", "argv", "field"), CARDHOLDER)
def test_a_refused_secret_exits_6_and_still_reports(
    monkeypatch, mock_connection, command, argv, field
):
    _wire(monkeypatch, mock_connection, command, "63C5")
    res = _cardfakes.run(["--json", *argv])
    assert res.exit_code == STATUS_WORD_EXIT, res.output
    payload = json.loads(res.stdout)
    # The result object, not an error object: same fields as before the exit code changed.
    assert payload[field] is False
    assert payload["sw"] == "63C5"
    assert payload["retries_remaining"] == 5
    assert "error" not in payload


@pytest.mark.parametrize(("command", "argv", "field"), CARDHOLDER)
def test_an_accepted_secret_still_exits_0(monkeypatch, mock_connection, command, argv, field):
    _wire(monkeypatch, mock_connection, command, "9000")
    res = _cardfakes.run(["--json", *argv])
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)[field] is True


def test_a_refused_pin_says_so_in_text_too(monkeypatch, mock_connection):
    _wire(monkeypatch, mock_connection, VERIFY, "63C2")
    res = _cardfakes.run(["piv", "pin", "verify", "--pin", "123456"])
    assert res.exit_code == STATUS_WORD_EXIT
    assert "PIN not verified" in res.output and "63C2" in res.output


def test_a_blocked_pin_exits_6_with_the_recovery_path(monkeypatch, mock_connection):
    _wire(monkeypatch, mock_connection, CHANGE_PIN, "6983")  # a block over contact
    res = _cardfakes.run(
        ["--json", "piv", "pin", "change", "--old-pin", "123456", "--new-pin", "654321"]
    )
    assert res.exit_code == STATUS_WORD_EXIT
    payload = json.loads(res.stdout)
    assert payload["blocked"] is True and "pin unblock" in payload["recovery"]


def test_pin_status_never_exits_6(monkeypatch, mock_connection):
    # A status question is answered, whatever the answer: a blocked PIN is not a refusal.
    exchanges = {
        SELECT_PIV: f"{APT}|9000",
        "00200080": "|6983",
        "00200081": "|63C6",
        _cardfakes.PIV_GET_STATUS: f"{_cardfakes.PIV_STATUS_CONTACT}|9000",
    }
    conn = mock_connection(ATR, exchanges, [])
    _cardfakes.wire_session(monkeypatch, conn, reader_name=_cardfakes.CONTACT_READER)
    res = _cardfakes.run(["--json", "piv", "pin", "status"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["pin"]["blocked"] is True


# ------------------------------------------------------------ admin-channel writes #
@contextlib.contextmanager
def _fake_session(self):
    yield object()


def _admin(reply: Response):
    class _Admin:
        def __init__(self, session):
            pass

        def select(self):
            pass

        def open(self, keys):
            pass

        def send(self, apdu, context=None):
            return reply

    return _Admin


@pytest.mark.parametrize(
    ("command", "env", "label"),
    [
        ("set-pin", {"CRYPTNOX_PIV_NEW_PIN": "123456"}, "PIN"),
        ("set-puk", {"CRYPTNOX_PIV_NEW_PUK": "12345678"}, "PUK"),
    ],
)
def test_a_refused_set_pin_or_puk_exits_6(monkeypatch, command, env, label):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(
        verifiers, "_set_verifier", lambda adm, keys, ref, padded, label: _refusal(0x6A80)
    )
    res = _cardfakes.run(["--json", "piv", "perso", command, "--default-keys"], env=env)
    assert res.exit_code == STATUS_WORD_EXIT, res.output
    payload = json.loads(res.stdout)
    assert payload["set"] is False and payload["sw"] == "6A80"
    human = _cardfakes.run(["piv", "perso", command, "--default-keys"], env=env)
    assert human.exit_code == STATUS_WORD_EXIT
    assert f"{label} not set" in human.output


def test_a_refused_object_write_exits_6(monkeypatch, tmp_path):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(data_objects, "PivAdmin", _admin(_refusal(0x6A82)))
    blob = tmp_path / "discovery.bin"
    blob.write_bytes(b"\x7e\x00")
    argv = ["piv", "perso", "write-object", "--object", "discovery", "--file", str(blob)]
    res = _cardfakes.run(["--json", *argv, "--default-keys"])
    assert res.exit_code == STATUS_WORD_EXIT, res.output
    payload = json.loads(res.stdout)
    assert payload == {"object": "discovery", "written": False, "sw": "6A82"}
    human = _cardfakes.run([*argv, "--default-keys"])
    assert human.exit_code == STATUS_WORD_EXIT and "Write failed" in human.output


def test_an_accepted_object_write_still_exits_0(monkeypatch, tmp_path):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(data_objects, "PivAdmin", _admin(OK))
    blob = tmp_path / "chuid.bin"
    blob.write_bytes(b"\x01\x02")
    res = _cardfakes.run(
        [
            "--json",
            "piv",
            "perso",
            "write-object",
            "--object",
            "chuid",
            "--file",
            str(blob),
            "--default-keys",
        ]
    )
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["written"] is True


def test_one_refused_standard_object_exits_6_and_lists_both(monkeypatch):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(
        data_objects,
        "_write_standard",
        lambda adm, keys, names: [
            {"object": "chuid", "ok": True, "sw": "9000"},
            {"object": "ccc", "ok": False, "sw": "6982"},
        ],
    )
    res = _cardfakes.run(["--json", "piv", "perso", "write-standard-objects", "--default-keys"])
    assert res.exit_code == STATUS_WORD_EXIT, res.output
    objects = json.loads(res.stdout)["objects"]
    assert [o["ok"] for o in objects] == [True, False]


def _certificate(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "exit code test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "cert.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


@pytest.mark.parametrize(
    ("reply", "code", "imported"), [(_refusal(0x6A82), 6, False), (OK, 0, True)]
)
def test_a_refused_certificate_import_exits_6(monkeypatch, tmp_path, reply, code, imported):
    monkeypatch.setattr(AppContext, "open_session", _fake_session)
    monkeypatch.setattr(certificates, "PivAdmin", lambda session: object())
    monkeypatch.setattr(certificates, "_import_cert_der", lambda adm, keys, ref, der, label: reply)
    res = _cardfakes.run(
        [
            "--json",
            "piv",
            "perso",
            "import-cert",
            "--slot",
            "9C",
            "--cert",
            _certificate(tmp_path),
            "--default-keys",
        ]
    )
    assert res.exit_code == code, res.output
    assert json.loads(res.stdout)["imported"] is imported
