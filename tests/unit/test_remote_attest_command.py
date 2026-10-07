"""The ``remote attest`` command: wiring, overwrite gate, post-verification. No socket, no card."""

import contextlib
import datetime
import json
import sys

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.applets.piv import objects as piv_obj
from cryptnox_id_cli.cli.commands import remote as remote_cmd
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.remote import attest_verify as av
from cryptnox_id_cli.remote import channel as rchannel

ATR = "3BFA1300FF910131FE000031C173C84000009000D2"
UID = "4301012345670042"
SELECT_ISD = "00A4040008A00000015100000000"
CPLC_CMD = "80CA9F7F00"
CPLC_RESP = (
    "9F7F2A4790D6004700000000004301012345670042000000000000000002507231323334350000000000000000"
)
NOW = datetime.datetime(2026, 9, 22, tzinfo=datetime.timezone.utc)


# --------------------------------------------------------------------------- #
# A tiny PKI and a card whose attestation container we control                 #
# --------------------------------------------------------------------------- #
def _name(cn, serial=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if serial:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial))
    return x509.Name(attrs)


def _der_int(value):
    body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return bytes([0x02, len(body)]) + body


def _cert(subject, issuer_name, issuer_key, key, *, ca=False, extensions=()):
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=365))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    for ext in extensions:
        b = b.add_extension(ext, critical=False)
    return b.sign(issuer_key, hashes.SHA256())


@pytest.fixture(scope="module")
def pki():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(_name("TEST ROOT"), _name("TEST ROOT"), root_key, root_key, ca=True)
    slot_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(
        _name("CRYPTNOX PIV ATTESTATION", UID),
        root.subject,
        root_key,
        slot_key,
        extensions=[
            x509.UnrecognizedExtension(av.OID_PIV_SLOT, _der_int(0x9C)),
            x509.UnrecognizedExtension(av.OID_TRUST_MODEL, _der_int(2)),
        ],
    )
    return {
        "root_der": root.public_bytes(serialization.Encoding.DER),
        "leaf_der": leaf.public_bytes(serialization.Encoding.DER),
        "leaf_pem": leaf.public_bytes(serialization.Encoding.PEM).decode(),
    }


def _piv_exchanges(container_der: bytes | None) -> dict[str, str]:
    """A PIV applet whose attestation container holds ``container_der`` (or nothing)."""
    select_piv = "00A404000BA00000030800001000010000"
    apt = (
        "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
        "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
        "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
    )
    ex = {select_piv: f"{apt}|9000"}
    obj = piv_obj.object_by_name("attestation-cert")
    assert obj is not None
    get_att = piv_obj.get_data_apdu(obj.oid).to_bytes().hex().upper()
    if container_der is not None:
        ex[get_att] = _wrapped(piv_obj.wrap_certificate(container_der))
    else:
        ex[get_att] = "|6A82"
    sign_obj = piv_obj.object_by_name("sign-cert")
    assert sign_obj is not None
    ex[piv_obj.get_data_apdu(sign_obj.oid).to_bytes().hex().upper()] = "|6A82"
    return ex


def _len(value: bytes) -> bytes:
    from cryptnox_id_cli.util import tlv

    return tlv.encode_length(len(value))


def _wrapped(value: bytes) -> str:
    return (bytes([0x53]) + _len(value) + value).hex().upper() + "|9000"


class ScriptedChannel:
    def __init__(self, script):
        self.script = list(script)
        self.sent: list[dict] = []

    def send(self, message: str) -> None:
        self.sent.append(json.loads(message))

    def recv(self, timeout=None) -> str:
        return json.dumps(self.script.pop(0))

    def close(self) -> None:
        pass


class _FakeSys:
    class _Stdin:
        def isatty(self):
            return True

        def __getattr__(self, name):
            return getattr(sys.stdin, name)

    stdin = _Stdin()

    def __getattr__(self, name):
        return getattr(sys, name)


@pytest.fixture
def wired(monkeypatch, mock_connection, pki):
    """Card with an EMPTY attestation container before, the leaf in it after."""
    base = {SELECT_ISD: "6F108408A000000151000000A5049F6501FF|9000", CPLC_CMD: f"{CPLC_RESP}|9000"}
    before = mock_connection(ATR, {**base, **_piv_exchanges(None)}, [])
    after_ex = {**base, **_piv_exchanges(pki["leaf_der"])}
    holder: dict = {"conn": before, "opened": 0, "after": after_ex}

    original = before.transmit

    def transmit(apdu):
        # Once the service has run (the channel was opened), the card holds the leaf.
        if holder["opened"]:
            key = bytes(apdu).hex().upper()
            spec = holder["after"].get(key)
            if spec is not None:
                data_hex, sw_hex = spec.split("|")
                sw = bytes.fromhex(sw_hex)
                return (list(bytes.fromhex(data_hex)) if data_hex else []), sw[0], sw[1]
        return original(apdu)

    before.transmit = transmit
    monkeypatch.setattr(remote_cmd, "pick_reader", lambda pref: "Fake Reader 00 00")
    monkeypatch.setattr(remote_cmd, "connect", lambda name: before)
    monkeypatch.setattr(av.trust, "load_anchors", lambda extra_dir=None: ([pki["root_der"]], []))
    monkeypatch.delenv(rchannel.URL_ENV, raising=False)

    @contextlib.contextmanager
    def fake_open(url, **kwargs):
        holder["opened"] += 1
        yield holder["channel"]

    monkeypatch.setattr(rchannel, "open_channel", fake_open)

    def arm(script):
        holder["channel"] = ScriptedChannel(script)
        return holder["channel"]

    holder["arm"] = arm
    return holder


def run(args, **kwargs):
    return CliRunner().invoke(root, args, **kwargs)


def ok_result(pki, **extra):
    return {
        "type": "result",
        "ok": True,
        "slot": "9C",
        "algorithm": "ECCP256",
        "chain_verified": True,
        "written_to_card": True,
        "readback_matches": True,
        "attestation_cert_pem": pki["leaf_pem"],
        **extra,
    }


# --------------------------------------------------------------------------- #
# Wiring and parameters                                                       #
# --------------------------------------------------------------------------- #
def test_attest_sends_slot_and_algorithm_and_omits_ca_obj_by_default(wired, pki):
    channel = wired["arm"]([ok_result(pki)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    assert channel.sent[0] == {
        "type": "hello",
        "op": "attest",
        "params": {"slot": "9C", "algorithm": "ECCP256"},
    }


def test_ca_obj_is_sent_only_when_given(wired, pki):
    channel = wired["arm"]([ok_result(pki)])
    run(["--json", "remote", "attest", "--ca-obj", "0301"])
    assert channel.sent[0]["params"]["ca_obj"] == "0301"


def test_slot_is_validated():
    result = run(["remote", "attest", "--slot", "9B"])
    assert result.exit_code == 2
    result = run(["remote", "attest", "--slot", "zz"])
    assert result.exit_code == 2


def test_dry_run_refuses(monkeypatch):
    monkeypatch.setattr(remote_cmd, "pick_reader", lambda *a: (_ for _ in ()).throw(AssertionError))
    result = run(["--dry-run", "remote", "attest"])
    assert result.exit_code != 0
    assert "nothing was sent to the card" in result.output


# --------------------------------------------------------------------------- #
# Post-verification                                                           #
# --------------------------------------------------------------------------- #
def test_genuine_result_verifies_and_binds(wired, pki):
    wired["arm"]([ok_result(pki)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    v = payload["verification"]
    assert v["verified"] is True
    assert v["chain_verified"] is True
    assert v["serial_number_matches_card"] is True
    assert v["slot_matches"] is True
    assert v["trust_model_matches"] is True
    assert v["public_key_matches_card"] is True
    assert payload["verified_locally"]["attestation_verified"] is True
    assert payload["verified_locally"]["attestation_container_written"] is True


def test_wrong_slot_in_the_certificate_is_reported(wired, pki):
    wired["arm"]([ok_result(pki)])
    result = run(["--json", "remote", "attest", "--slot", "9A"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["verification"]["slot_matches"] is False
    assert payload["verified_locally"]["attestation_verified"] is False


def test_missing_certificate_is_reported_not_faked(wired, pki):
    wired["arm"]([ok_result(pki, attestation_cert_pem="")])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["verification"] is None
    assert payload["verified_locally"]["attestation_returned"] is False


def test_unreadable_certificate_is_an_error(wired, pki):
    wired["arm"]([ok_result(pki, attestation_cert_pem="-----BEGIN CERTIFICATE-----\nnope\n")])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 1
    assert "unreadable certificate" in json.loads(result.stdout)["message"]


def test_out_writes_the_pem(wired, pki, tmp_path):
    wired["arm"]([ok_result(pki)])
    out = tmp_path / "att.pem"
    result = run(["--json", "remote", "attest", "--out", str(out)])
    assert result.exit_code == 0
    assert out.read_text() == pki["leaf_pem"]


def test_human_output_names_the_claim_it_cannot_witness(wired, pki):
    wired["arm"]([ok_result(pki)])
    result = run(["remote", "attest"])
    assert result.exit_code == 0, result.output
    assert "cannot witness" in result.output
    assert "verified" in result.output


# --------------------------------------------------------------------------- #
# Overwrite gate                                                              #
# --------------------------------------------------------------------------- #
@pytest.fixture
def occupied(wired, pki):
    """The attestation container already holds a certificate before the run."""
    wired["conn"]._exchanges.update(_piv_exchanges(pki["leaf_der"]))
    return wired


def test_occupied_container_fails_closed_non_interactively(occupied, pki):
    occupied["arm"]([ok_result(pki)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 1
    assert "pass --yes" in json.loads(result.stdout)["message"]
    assert occupied["opened"] == 0


def test_occupied_container_proceeds_with_yes(occupied, pki):
    occupied["arm"]([ok_result(pki)])
    result = run(["--yes", "--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    assert occupied["opened"] == 1


def test_occupied_container_asks_interactively(occupied, pki, monkeypatch):
    monkeypatch.setattr(remote_cmd, "sys", _FakeSys())
    occupied["arm"]([ok_result(pki)])
    result = run(["remote", "attest"], input="n\n")
    assert result.exit_code != 0
    assert occupied["opened"] == 0
    occupied["arm"]([ok_result(pki)])
    result = run(["remote", "attest"], input="y\n")
    assert result.exit_code == 0, result.output
