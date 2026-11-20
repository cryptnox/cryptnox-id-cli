# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""The ``remote attest`` command: wiring, overwrite gate, post-verification. No socket, no card."""

import contextlib
import datetime
import json
import sys
from pathlib import Path

import pytest
from _cardfakes import wire_session
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.applets.piv import objects as piv_obj
from cryptnox_id_cli.cli.commands.remote import attest as remote_attest
from cryptnox_id_cli.cli.context import AppContext
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
    wire_session(monkeypatch, before, reader_name="Fake Reader 00 00")
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


HARDENED = {"scp": "SCP03", "level": "0x33", "mode": "hardened", "responses_authenticated": True}
LEGACY_SCP02 = {"scp": "SCP02", "level": "0x03", "mode": "legacy", "responses_authenticated": False}


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
        "channel": HARDENED,
        "public_key_authenticated": True,
        **extra,
    }


# --------------------------------------------------------------------------- #
# Wiring and parameters                                                       #
# --------------------------------------------------------------------------- #
def test_attest_sends_slot_and_algorithm_only(wired, pki):
    channel = wired["arm"]([ok_result(pki)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    assert channel.sent[0] == {
        "type": "hello",
        "op": "attest",
        "params": {"slot": "9C", "algorithm": "ECCP256"},
    }


def test_ca_obj_is_gone(wired, pki):
    # The signing key is the service's own setting; the option no longer exists.
    result = run(["remote", "attest", "--ca-obj", "0301"])
    assert result.exit_code == 2
    assert wired["opened"] == 0
    assert "--ca-obj" not in run(["remote", "attest", "--help"]).output


# --------------------------------------------------------------------------- #
# What the service says it signed, against the certificate it returned        #
# --------------------------------------------------------------------------- #
def _identifiers(pki):
    import hashlib

    leaf = x509.load_der_x509_certificate(pki["leaf_der"])
    spki = leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "cert_serial": f"{leaf.serial_number:x}",
        "cert_sha256": hashlib.sha256(pki["leaf_der"]).hexdigest(),
        "pub_sha256": hashlib.sha256(spki).hexdigest(),
    }


def test_reported_identifiers_are_recomputed_from_the_certificate(wired, pki):
    wired["arm"]([ok_result(pki, **_identifiers(pki))])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    checks = json.loads(result.stdout)["verified_locally"]
    assert checks["certificate_serial_matches"] is True
    assert checks["certificate_sha256_matches"] is True
    assert checks["public_key_sha256_matches"] is True
    assert "do not match" not in result.stderr


def test_an_identifier_that_does_not_match_is_reported_and_warned_about(wired, pki):
    ids = _identifiers(pki)
    ids["cert_sha256"] = "00" * 32
    ids["pub_sha256"] = ids["pub_sha256"].upper()  # case must not matter
    wired["arm"]([ok_result(pki, **ids)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 17, result.output
    checks = json.loads(result.stdout)["verified_locally"]
    assert checks["certificate_sha256_matches"] is False
    assert checks["certificate_serial_matches"] is True
    assert checks["public_key_sha256_matches"] is True
    assert "do not match the certificate it returned" in result.stderr


def test_identifiers_the_service_does_not_report_are_left_unchecked(wired, pki):
    wired["arm"]([ok_result(pki, cert_serial="not-hex")])
    result = run(["--json", "remote", "attest"])
    checks = json.loads(result.stdout)["verified_locally"]
    assert checks["certificate_serial_matches"] is False
    assert checks["certificate_sha256_matches"] is None
    assert checks["public_key_sha256_matches"] is None


def test_slot_is_validated():
    result = run(["remote", "attest", "--slot", "9B"])
    assert result.exit_code == 2
    result = run(["remote", "attest", "--slot", "zz"])
    assert result.exit_code == 2


def test_dry_run_refuses(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("reader must not be opened under --dry-run")

    monkeypatch.setattr(AppContext, "open_session", boom)
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
    assert result.exit_code == 17  # printed, then refused: the tool's own check failed
    payload = json.loads(result.stdout)
    assert payload["verification"]["slot_matches"] is False
    assert payload["verified_locally"]["attestation_verified"] is False


def test_missing_certificate_is_reported_not_faked(wired, pki):
    wired["arm"]([ok_result(pki, attestation_cert_pem="")])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 17
    payload = json.loads(result.stdout)
    assert payload["verification"] is None
    assert "local verification failed: attestation_returned, attestation_verified" in result.stderr
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
    monkeypatch.setattr(remote_attest, "sys", _FakeSys())
    occupied["arm"]([ok_result(pki)])
    result = run(["remote", "attest"], input="n\n")
    assert result.exit_code != 0
    assert occupied["opened"] == 0
    occupied["arm"]([ok_result(pki)])
    result = run(["remote", "attest"], input="y\n")
    assert result.exit_code == 0, result.output


# --------------------------------------------------------------------------- #
# A finalized applet: the key in the slot is overwritten                      #
# --------------------------------------------------------------------------- #
GET_STATUS = "00CB3F00055C032F475300"
STATUS_SECURED = "531880010F8101008201008301008401008501008601008701FF"
STATUS_OPEN = "53188001078101008201008301008401008501008601008701FF"
# What the service answers on a finalized applet: when the confirmation is missing, when
# the slot has no key object, and what a build from before 2026-11 answered.
NEEDS_CONFIRMATION = {
    "type": "result",
    "ok": False,
    "op": "attest",
    "applet_finalized": True,
    "confirmation_required": "replace_key",
    "error": "attest refused: the PIV applet is finalized. Attesting generates a new key in "
    "slot 9C and the key now in that slot is overwritten. The request did not confirm that "
    "(params.replace_key), so nothing was changed. A client that cannot confirm it needs an "
    "update",
}
NO_KEY_OBJECT = {
    "type": "result",
    "ok": False,
    "op": "attest",
    "applet_finalized": True,
    "error": "attest refused: the finalized PIV applet has no ECCP256 key object in slot 9C "
    "(GENERATE SW=6A80), and nothing can be added to a finalized applet. Nothing was changed",
}
OLDER_SERVICE = {"type": "result", "ok": False, "error": "create 9B mgmt key failed SW=6986"}


@pytest.fixture
def finalized(wired):
    """The applet reports itself finalized (SECURED): nothing can be added to it."""
    wired["conn"]._exchanges[GET_STATUS] = f"{STATUS_SECURED}|9000"
    return wired


def test_finalized_applet_warns_that_the_key_is_overwritten_and_stops_without_yes(finalized, pki):
    finalized["arm"]([ok_result(pki)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 1
    assert "overwrites the key in slot 9C" in json.loads(result.stdout)["message"]
    assert "THE KEY NOW IN SLOT 9C IS OVERWRITTEN" in result.stderr
    assert finalized["opened"] == 0  # nothing was sent, no operation spent


def test_finalized_applet_sends_the_confirmation_only_after_yes(finalized, pki):
    channel = finalized["arm"]([ok_result(pki, applet_finalized=True, key_replaced=True)])
    result = run(["--yes", "--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    assert channel.sent[0]["params"] == {
        "slot": "9C",
        "algorithm": "ECCP256",
        "replace_key": True,
    }
    assert "THE KEY NOW IN SLOT 9C IS OVERWRITTEN" in result.stderr  # said even with --yes


def test_finalized_applet_asks_about_the_key_interactively(finalized, pki, monkeypatch):
    monkeypatch.setattr(remote_attest, "sys", _FakeSys())
    finalized["arm"]([ok_result(pki)])
    result = run(["remote", "attest"], input="n\n")
    assert result.exit_code != 0
    assert "Overwrite the key in slot 9C?" in result.output
    assert finalized["opened"] == 0
    channel = finalized["arm"]([ok_result(pki)])
    result = run(["remote", "attest"], input="y\n")
    assert result.exit_code == 0, result.output
    assert channel.sent[0]["params"]["replace_key"] is True


def test_an_applet_that_is_not_finalized_gets_no_warning_and_sends_no_confirmation(wired, pki):
    wired["conn"]._exchanges[GET_STATUS] = f"{STATUS_OPEN}|9000"
    channel = wired["arm"]([ok_result(pki)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    assert "finalized" not in result.stderr
    assert "replace_key" not in channel.sent[0]["params"]


def _not_stored(pki):
    return ok_result(
        pki,
        applet_finalized=True,
        key_replaced=True,
        attestation_stored=False,
        written_to_card=False,
        readback_matches=False,
    )


def test_a_certificate_the_card_could_not_store_is_printed(finalized, pki):
    # A finalized applet without an attestation container: the certificate comes back in
    # the service's answer only.
    finalized["after"].update(_piv_exchanges(None))
    finalized["arm"]([_not_stored(pki)])
    result = run(["--yes", "remote", "attest"])
    assert result.exit_code == 0, result.output  # unchecked is not a failure
    assert "not stored on the card" in result.output
    assert "not fully checked" in result.output
    assert "MISMATCH" not in result.output
    assert "It is printed below; keep it." in result.output
    assert "-----BEGIN CERTIFICATE-----" in result.output


def test_a_certificate_the_card_could_not_store_goes_to_the_out_file(finalized, pki, tmp_path):
    finalized["after"].update(_piv_exchanges(None))
    finalized["arm"]([_not_stored(pki)])
    out = tmp_path / "attestation.pem"
    result = run(["--yes", "--json", "remote", "attest", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text() == pki["leaf_pem"]
    assert f"It was written to {out}." in result.stderr.replace("\n", "")
    payload = json.loads(result.stdout)
    assert payload["result"]["attestation_stored"] is False
    assert payload["out"] == str(out)
    assert payload["verified_locally"]["attestation_container_written"] is None
    assert payload["verified_locally"]["attestation_verified"] is None
    assert payload["verified_locally"]["certificate_written_to_out"] is True
    # Chain, card serial, slot and trust model hold. The fourth binding compares the
    # certified key with the certificate stored on the card, and there is none: unchecked,
    # so the overall verdict stays false, as `AttestVerification.verified` defines it.
    verification = payload["verification"]
    assert verification["chain_verified"] is True
    assert verification["serial_number_matches_card"] is True
    assert verification["public_key_matches_card"] is None
    assert verification["verified"] is False


@pytest.mark.parametrize(
    ("answer", "says"),
    [
        (NEEDS_CONFIRMATION, "overwrites the key now in the slot"),
        (NO_KEY_OBJECT, "no key object for this algorithm"),
        (OLDER_SERVICE, "this build of the service cannot attest a key on a finalized applet"),
    ],
)
def test_a_refusal_on_a_finalized_applet_is_explained(finalized, answer, says):
    finalized["arm"]([answer])
    result = run(["--yes", "--json", "remote", "attest"])
    assert result.exit_code == 16, result.output
    error = json.loads(result.stdout)
    assert error["reason"] == "applet_finalized"
    assert says in error["message"]
    assert error["result"]["error"] == answer["error"]


# --------------------------------------------------------------------------- #
# What the service says about the channel it used                             #
# --------------------------------------------------------------------------- #
def test_unauthenticated_public_key_is_warned_about(wired, pki):
    wired["arm"]([ok_result(pki, public_key_authenticated=False, channel=LEGACY_SCP02)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    assert "could have substituted it" in result.stderr
    payload = json.loads(result.stdout)
    assert payload["result"]["public_key_authenticated"] is False
    # The local bindings are checked exactly as before; the warning is about origin.
    assert payload["verified_locally"]["attestation_verified"] is True
    wired["arm"]([ok_result(pki, public_key_authenticated=False, channel=LEGACY_SCP02)])
    result = run(["--yes", "remote", "attest"])  # the first run left the leaf on the card
    assert "public key authenticated by the card's channel (service's claim): NO" in result.output
    assert "Admin channel: SCP02 level 0x03, legacy" in result.output


def test_authenticated_public_key_is_shown_without_a_warning(wired, pki):
    wired["arm"]([ok_result(pki)])
    result = run(["remote", "attest"])
    assert result.exit_code == 0, result.output
    assert "(service's claim): yes" in result.output
    assert "Admin channel: SCP03 level 0x33, hardened" in result.output
    assert "warning" not in result.output


def test_a_service_that_says_nothing_about_the_channel_is_treated_as_legacy(wired, pki):
    answer = ok_result(pki)
    del answer["channel"], answer["public_key_authenticated"]
    wired["arm"]([answer])
    result = run(["remote", "attest"])
    assert result.exit_code == 0, result.output
    assert "(service's claim): not reported" in result.output
    assert "Admin channel: not reported by the service (treated as legacy)" in result.output
    assert "did not say whether the public key" in result.output


def test_legacy_level_on_an_scp03_card_is_warned_about(wired, pki):
    chan = {"scp": "SCP03", "level": "0x03", "mode": "legacy", "responses_authenticated": False}
    wired["arm"]([ok_result(pki, public_key_authenticated=False, channel=chan)])
    result = run(["--json", "remote", "attest"])
    assert result.exit_code == 0, result.output
    assert "drove this SCP03 card at the legacy channel level" in result.stderr


def test_contactless_reader_is_warned_about_before_connecting(wired, pki, monkeypatch):
    wire_session(monkeypatch, wired["conn"], reader_name="OMNIKEY 5422CL")
    wired["arm"]([ok_result(pki)])
    result = run(["remote", "attest"])
    assert result.exit_code == 0, result.output
    before = result.output.split("remote attest via")[0]
    assert "looks like a contactless reader" in before
    assert "refuses this operation over contactless" in before


# --------------------------------------------------------------------------- #
# --out: checked before an operation is spent, and a failed write loses nothing #
# --------------------------------------------------------------------------- #
def test_an_unwritable_out_path_is_refused_before_anything_is_sent(wired, pki, tmp_path):
    wired["arm"]([ok_result(pki)])
    out = tmp_path / "no" / "such" / "dir" / "attestation.pem"
    result = run(["--json", "remote", "attest", "--out", str(out)])
    assert result.exit_code == 1
    assert "does not exist or is not writable" in json.loads(result.stdout)["message"]
    assert wired["opened"] == 0


def test_a_write_that_fails_after_the_operation_keeps_the_certificate(
    finalized, pki, tmp_path, monkeypatch
):
    finalized["after"].update(_piv_exchanges(None))
    finalized["arm"]([_not_stored(pki)])
    out = tmp_path / "attestation.pem"

    def boom(self, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_bytes", boom)
    result = run(["--yes", "remote", "attest", "--out", str(out)])
    assert result.exit_code == 17, result.output  # the file the caller asked for is missing
    assert "could not be written" in result.output
    assert "-----BEGIN CERTIFICATE-----" in result.output  # printed instead
    assert "certificate_written_to_out: MISMATCH" in result.output
