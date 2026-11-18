# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Genuineness / attestation applet: SELECT/GET CERT/ATTEST client, signature
verification, chain ordering + anchoring, and the read-only state detector.

The trust material is a synthetic EC PKI (root -> sub-CA -> device leaf) built in
the fixture, so the tests are self-contained and deterministic — no transcribed
card data. The device leaf signs ``ATTEST_LABEL || nonce`` exactly as the real
applet does, exercising the true proof-of-possession path."""

from __future__ import annotations

import datetime
import json

import pytest
from _cardfakes import run, run_both_modes, wire_session
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptnox_id_cli.applets.genuine import constants as gc
from cryptnox_id_cli.applets.genuine.genuine import GenuinenessApplet
from cryptnox_id_cli.applets.genuine.verify import (
    _order_intermediates,
    verify_attestation_signature,
    verify_genuineness,
)
from cryptnox_id_cli.cli.commands.genuine import _load_dir_anchors
from cryptnox_id_cli.state.detector import StateDetector
from cryptnox_id_cli.state.model import CardState, DesfireState, GenuinenessState
from cryptnox_id_cli.transport.errors import AppletNotFoundError
from cryptnox_id_cli.transport.pcsc import CardSession

_SELECT_C4 = "00A4040008A00000100002470100"  # SELECT genuineness, case-4 (Le=00)
_SELECT_C3 = "00A4040008A000001000024701"  # SELECT genuineness, case-3 (no Le)
_GET_INFO = "8001000000"
_GET_CERT_LEAF = "80020000000000"  # extended Le
_NONCE = bytes(range(0x20, 0x40))
_ATTEST = ("8004000020" + _NONCE.hex()).upper()

_NB = datetime.datetime(2020, 1, 1)
_NA = datetime.datetime(2045, 1, 1)


def _ca(subject: str, issuer_name, issuer_key, *, self_signed: bool):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    signer_key = key if self_signed else issuer_key
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name if self_signed else issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(signer_key, hashes.SHA256())
    )
    return key, name, cert


def _chain(root_cn: str, sub_cn: str, leaf_cn: str) -> dict[str, bytes]:
    """A synthetic chain: ROOT -> SUB-CA -> device LEAF, plus a valid ATTEST sig."""
    root_key, root_name, root = _ca(root_cn, None, None, self_signed=True)
    sub_key, sub_name, sub = _ca(sub_cn, root_name, root_key, self_signed=False)

    dev_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf_cn)]))
        .issuer_name(sub_name)
        .public_key(dev_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(sub_key, hashes.SHA256())
    )
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    sig = dev_key.sign(gc.ATTEST_LABEL + _NONCE, ec.ECDSA(hashes.SHA256()))
    return {
        "leaf": der(leaf),
        "sub": der(sub),
        "root": der(root),
        "sig": sig,
    }


@pytest.fixture
def pki():
    return _chain("TEST ROOT CA", "TEST SUB CA", "Device DEV-TEST-01")


class _DictConn:
    def __init__(self, exchanges: dict[str, str]) -> None:
        self._x = {k.upper(): v for k, v in exchanges.items()}
        self.sent: list[str] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        key = bytes(apdu).hex().upper()
        self.sent.append(key)
        spec = self._x.get(key)
        if spec is None:
            return [], 0x6A, 0x82
        data_hex, sw_hex = spec.split("|")
        data = list(bytes.fromhex(data_hex)) if data_hex else []
        sw = bytes.fromhex(sw_hex)
        return data, sw[0], sw[1]

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B8580018073C821100E")

    def disconnect(self) -> None:
        pass


def _applet(exchanges: dict[str, str]) -> tuple[GenuinenessApplet, _DictConn]:
    conn = _DictConn(exchanges)
    return GenuinenessApplet(CardSession(conn)), conn


# ----------------------------------------------------------------- applet --- #
def test_select_present_then_reads(pki):
    leaf_hex = pki["leaf"].hex()
    gen, _ = _applet(
        {_SELECT_C4: "|9000", _GET_INFO: "01000711|9000", _GET_CERT_LEAF: f"{leaf_hex}|9000"}
    )
    gen.select()
    assert gen.get_info().hex == "01000711"
    assert gen.get_cert(gc.CERT_LEAF) == pki["leaf"]


def test_select_absent_raises_and_try_select_false():
    gen, _ = _applet({})  # unmapped SELECT -> 6A82
    with pytest.raises(AppletNotFoundError):
        gen.select()
    assert GenuinenessApplet(CardSession(_DictConn({}))).try_select() is False


def test_select_6d00_is_treated_as_absent():
    # 6D00: another applet (e.g. U2F left selected by a preceding FIDO probe) rejects the
    # SELECT's INS. The genuineness AID is not selectable there, indistinguishable from
    # absent - must be NOT_PRESENT, not a StatusWordError bubbling up as UNKNOWN.
    gen, _ = _applet({_SELECT_C4: "|6D00"})
    with pytest.raises(AppletNotFoundError):
        gen.select()
    assert GenuinenessApplet(CardSession(_DictConn({_SELECT_C4: "|6D00"}))).try_select() is False


def test_select_retries_case3_on_6700():
    gen, conn = _applet({_SELECT_C4: "|6700", _SELECT_C3: "|9000"})
    gen.select()
    assert conn.sent == [_SELECT_C4, _SELECT_C3]


def test_attest_returns_signature(pki):
    gen, _ = _applet({_SELECT_C4: "|9000", _ATTEST: f"{pki['sig'].hex()}|9000"})
    gen.select()
    assert gen.attest(_NONCE) == pki["sig"]


# ----------------------------------------------------------------- verify --- #
def test_attestation_signature_verifies(pki):
    assert verify_attestation_signature(pki["leaf"], _NONCE, pki["sig"]) is True


def test_attestation_signature_rejects_wrong_nonce(pki):
    assert verify_attestation_signature(pki["leaf"], bytes(32), pki["sig"]) is False


def test_order_intermediates_builds_leaf_to_root_and_drops_root(pki):
    # Pool has the sub-CA (an intermediate) and the self-issued root (must be dropped).
    ordered = _order_intermediates(pki["leaf"], [pki["root"], pki["sub"]])
    assert ordered == [pki["sub"]]


def test_verify_genuineness_full_chain_genuine(pki):
    r = verify_genuineness(
        leaf_der=pki["leaf"],
        nonce=_NONCE,
        signature=pki["sig"],
        card_issuer_der=pki["sub"],  # issuer read off the card
        roots=[pki["root"]],  # pinned anchor
        intermediates=[],
    )
    assert r.attested is True
    assert r.chain is not None and r.chain.verified is True
    assert r.genuine is True


def test_verify_genuineness_pop_ok_but_unanchored(pki):
    r = verify_genuineness(
        leaf_der=pki["leaf"],
        nonce=_NONCE,
        signature=pki["sig"],
        card_issuer_der=pki["sub"],
        roots=[],  # no pinned anchor
        intermediates=[],
    )
    assert r.attested is True  # proof of possession holds
    assert r.genuine is False  # but chain cannot be anchored
    assert any("root" in n.lower() for n in r.notes)


def test_verify_genuineness_not_personalized():
    r = verify_genuineness(
        leaf_der=None,
        nonce=_NONCE,
        signature=None,
        card_issuer_der=None,
        roots=[],
        intermediates=[],
    )
    assert r.attested is False and r.chain is None and r.genuine is False


# --------------------------------------------------------------- detector --- #
def test_detector_personalized(pki):
    leaf_hex = pki["leaf"].hex()
    conn = _DictConn(
        {_SELECT_C4: "|9000", _GET_INFO: "01000711|9000", _GET_CERT_LEAF: f"{leaf_hex}|9000"}
    )
    st = StateDetector(
        CardSession(conn), probe_fido=False, probe_desfire=False, probe_genuine=True
    ).detect()
    assert st.genuine == GenuinenessState.PERSONALIZED
    assert "DEV-TEST-01" in (st.genuine_leaf_subject or "")
    assert st.genuine_info == "01000711"


def test_detector_not_present_on_contact():
    det = StateDetector(CardSession(_DictConn({})))
    st = CardState(desfire=DesfireState.UNKNOWN)
    det._detect_genuineness(st)
    assert st.genuine == GenuinenessState.NOT_PRESENT


def test_detector_contact_only_when_desfire_reachable():
    # Contactless interface: DESFire answers; the contact-only genuineness applet does not.
    det = StateDetector(CardSession(_DictConn({})))
    st = CardState(desfire=DesfireState.REACHABLE)
    det._detect_genuineness(st)
    assert st.genuine == GenuinenessState.NEEDS_CONTACT_READER
    assert any("contact-only" in n.lower() for n in st.notes)


_SELECT_DEFAULT_C2 = "00A4040000"  # empty SELECT (default applet / card manager)
_SELECT_DEFAULT_C1 = "00A40400"
_SELECT_FIDO = "00A4040008A0000006472F000100"


class _JcreConn(_DictConn):
    """Model the JCRE selection rule the detector must survive: a SELECT for an AID
    that matches no applet is handed to the *currently selected* applet as an ordinary
    command, and that applet answers with an arbitrary SW. Only after an empty SELECT
    (back to the card manager) does an unknown AID get the authoritative 6A82.

    ``foreign_sw`` is the SW the wrongly-selected applet answers with - deliberately
    not 6D00, so the regression cannot be satisfied by SW mapping alone."""

    def __init__(self, *, fido_present: bool, genuine_present: bool, foreign_sw=(0x69, 0x85)):
        super().__init__({})
        self.fido_present = fido_present
        self.genuine_present = genuine_present
        self.foreign_sw = foreign_sw
        self.foreign_selected = False  # a non-card-manager applet holds the interface

    def transmit(self, apdu):
        key = bytes(apdu).hex().upper()
        self.sent.append(key)
        if key in (_SELECT_DEFAULT_C2, _SELECT_DEFAULT_C1):
            self.foreign_selected = False
            return [], 0x90, 0x00
        if key == _SELECT_FIDO and self.fido_present:
            self.foreign_selected = True
            return [], 0x90, 0x00
        if key in (_SELECT_C4, _SELECT_C3):
            if self.genuine_present:  # a matching AID is always selected by the JCRE
                self.foreign_selected = False
                return [], 0x90, 0x00
            if self.foreign_selected:
                return [], self.foreign_sw[0], self.foreign_sw[1]
            return [], 0x6A, 0x82
        if self.foreign_selected:  # any other probe APDU also lands on the wrong applet
            return [], self.foreign_sw[0], self.foreign_sw[1]
        return [], 0x6A, 0x82


def test_detector_resets_selection_left_by_a_previous_probe():
    """Regression: with an applet left selected answering SW 6985, the genuineness
    verdict was UNKNOWN ('select error') instead of NOT_PRESENT. The detector must
    re-select the card manager before probing, not depend on the stray applet's SW."""
    conn = _JcreConn(fido_present=True, genuine_present=False)
    conn.foreign_selected = True  # a previous probe (FIDO) left its applet selected
    det = StateDetector(CardSession(conn))
    st = CardState(desfire=DesfireState.UNKNOWN)
    det._detect_genuineness(st)
    assert st.genuine == GenuinenessState.NOT_PRESENT
    assert not any("select error" in n.lower() for n in st.notes)
    reset = conn.sent.index(_SELECT_DEFAULT_C2)
    assert any(k in (_SELECT_C4, _SELECT_C3) for k in conn.sent[reset:])


def test_detector_genuineness_verdict_is_probe_order_independent():
    """The verdict must not depend on whether the FIDO probe ran (and selected U2F)."""
    verdicts = []
    for probe_fido in (True, False):
        st = StateDetector(
            CardSession(_JcreConn(fido_present=True, genuine_present=False)),
            probe_fido=probe_fido,
            probe_desfire=False,
        ).detect()
        verdicts.append(st.genuine)
    assert verdicts == [GenuinenessState.NOT_PRESENT, GenuinenessState.NOT_PRESENT]


def test_detector_finds_present_applet_after_fido_probe():
    """A present genuineness applet is selected by the JCRE regardless of prior state."""
    st = StateDetector(
        CardSession(_JcreConn(fido_present=True, genuine_present=True)),
        probe_fido=True,
        probe_desfire=False,
    ).detect()
    # GET INFO / GET CERT land on the (mock) applet and fail -> PRESENT, not personalized.
    assert st.genuine == GenuinenessState.PRESENT


_GET_CERT_ISSUER = "80020100000000"
MARKUP_NAMES = ("TEST [b]ROOT[/b]", "SUB a[/x]b", "Device [b]S[/b]")


def _pem(der: bytes) -> bytes:
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)


def _without_basic_constraints() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NO BASIC CONSTRAINTS")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_anchor_dir_keeps_cas_and_classifies_them(tmp_path, pki):
    (tmp_path / "a-root.PEM").write_bytes(_pem(pki["root"]))
    (tmp_path / "b-sub.crt").write_bytes(pki["sub"])  # DER under a PEM-style suffix
    (tmp_path / "c-leaf.pem").write_bytes(_pem(pki["leaf"]))  # not a CA
    (tmp_path / "d-nobc.cer").write_bytes(_without_basic_constraints())
    (tmp_path / "e-junk.cer").write_bytes(b"not a certificate")
    (tmp_path / "f-notes.txt").write_bytes(_pem(pki["root"]))  # wrong suffix
    (tmp_path / "g-dir.pem").mkdir()

    assert _load_dir_anchors(str(tmp_path)) == ([pki["root"]], [pki["sub"]])


def test_one_pem_file_may_carry_a_whole_bundle(tmp_path, pki):
    (tmp_path / "bundle.pem").write_bytes(_pem(pki["sub"]) + _pem(pki["root"]))

    assert _load_dir_anchors(str(tmp_path)) == ([pki["root"]], [pki["sub"]])


def test_empty_anchor_dir_adds_nothing(tmp_path):
    assert _load_dir_anchors(str(tmp_path)) == ([], [])


def _card(monkeypatch, pki, *, leaf=True, info="01000711|9000", sig=None):
    exchanges = {_SELECT_C4: "|9000", _GET_INFO: info}
    if leaf:
        exchanges[_GET_CERT_LEAF] = f"{pki['leaf'].hex()}|9000"
        exchanges[_GET_CERT_ISSUER] = f"{pki['sub'].hex()}|9000"
        exchanges[_ATTEST] = f"{(sig or pki['sig']).hex()}|9000"
    conn = _DictConn(exchanges)
    wire_session(monkeypatch, conn, reader_name="ACS ACR39U ICC Reader 0")
    return conn


def _anchor_dir(tmp_path, pki) -> str:
    (tmp_path / "root.pem").write_bytes(_pem(pki["root"]))
    return str(tmp_path)


def _both(args):
    as_json, human = run_both_modes(args)
    assert as_json.exit_code == 0, as_json.output
    assert human.exit_code == 0, human.output
    return json.loads(as_json.stdout), " ".join(human.output.split())


def test_info_reports_leaf_and_issuer(monkeypatch, pki):
    _card(monkeypatch, pki)
    payload, text = _both(["genuine", "info"])

    assert payload["personalized"] is True
    assert payload["info"] == "01000711"
    assert payload["leaf"]["subject"] == "CN=Device DEV-TEST-01"
    assert payload["issuer"]["subject"] == "CN=TEST SUB CA"
    assert "Info: 01000711" in text
    assert "Device leaf: CN=Device DEV-TEST-01 issuer: CN=TEST SUB CA" in text


def test_info_on_a_blank_applet_says_not_personalized(monkeypatch, pki):
    _card(monkeypatch, pki, leaf=False, info="|6D00")
    payload, text = _both(["genuine", "info"])

    assert payload == {
        "present": True,
        "personalized": False,
        "info": None,
        "leaf": None,
        "issuer": None,
    }
    assert "Info:" not in text
    assert "No device leaf certificate (applet not personalized)." in text


def test_verify_proves_a_card_chained_to_a_pinned_anchor(monkeypatch, pki, tmp_path):
    conn = _card(monkeypatch, pki)
    args = ["genuine", "verify", "--nonce", _NONCE.hex(), "--anchors", _anchor_dir(tmp_path, pki)]
    payload, text = _both(args)

    assert payload["genuine"] is True
    assert payload["chain"]["chain"] == [
        "CN=Device DEV-TEST-01",
        "CN=TEST SUB CA",
        "CN=TEST ROOT CA",
    ]
    assert conn.sent.count(_ATTEST) == 2  # the caller's nonce, once per mode
    assert "Genuineness: GENUINE" in text
    assert "proof of possession (ATTEST): valid" in text
    assert "device leaf: CN=Device DEV-TEST-01" in text
    assert "certificate chain: verified" in text
    assert "CN=Device DEV-TEST-01 -> CN=TEST SUB CA -> CN=TEST ROOT CA" in text


def test_verify_without_the_anchor_is_not_proven(monkeypatch, pki):
    _card(monkeypatch, pki)
    payload, text = _both(["genuine", "verify", "--nonce", _NONCE.hex()])

    assert payload["proof_of_possession"] is True
    assert payload["genuine"] is False
    assert payload["chain"]["reasons"] == ["not anchored: no pinned root issues 'CN=TEST SUB CA'"]
    assert "Genuineness: NOT proven" in text
    assert "certificate chain: not verified" in text
    assert "- not anchored: no pinned root issues 'CN=TEST SUB CA'" in text


def test_verify_rejects_a_signature_that_does_not_match(monkeypatch, pki, tmp_path):
    _card(monkeypatch, pki, sig=b"\x30\x00")
    args = ["genuine", "verify", "--nonce", _NONCE.hex(), "--anchors", _anchor_dir(tmp_path, pki)]
    payload, text = _both(args)

    assert payload["proof_of_possession"] is False
    assert payload["chain"]["verified"] is True
    assert payload["genuine"] is False
    assert "proof of possession (ATTEST): invalid" in text


def test_verify_on_a_blank_applet_sends_no_attest(monkeypatch, pki):
    conn = _card(monkeypatch, pki, leaf=False)
    payload, text = _both(["genuine", "verify"])

    assert payload["genuine"] is False
    assert payload["chain"] is None
    assert not any(c.startswith("8004") for c in conn.sent)
    assert "Genuineness: NOT proven" in text
    assert "device leaf:" not in text and "certificate chain" not in text
    assert "* Genuineness applet present but carries no device leaf certificate." in text


@pytest.mark.parametrize("nonce", ["zz", "abc"])
def test_verify_refuses_a_nonce_that_is_not_hex(nonce):
    result = run(["genuine", "verify", "--nonce", nonce])

    assert result.exit_code == 2
    assert "nonce must be hex" in result.output


@pytest.fixture
def markup_pki():
    return _chain(*MARKUP_NAMES)


def test_json_carries_bracketed_names_unchanged(monkeypatch, markup_pki):
    _card(monkeypatch, markup_pki)
    as_json, _ = run_both_modes(["genuine", "info"])
    payload = json.loads(as_json.stdout)
    assert payload["leaf"]["subject"] == "CN=Device [b]S[/b]"
    assert payload["leaf"]["issuer"] == "CN=SUB a[/x]b"


@pytest.mark.xfail(strict=True, reason="certificate names are printed as console markup")
def test_info_prints_bracketed_names_as_written(monkeypatch, markup_pki):
    _card(monkeypatch, markup_pki)
    _, text = _both(["genuine", "info"])
    assert "Device leaf: CN=Device [b]S[/b] issuer: CN=SUB a[/x]b" in text


@pytest.mark.xfail(strict=True, reason="certificate names are printed as console markup")
def test_verify_prints_bracketed_names_as_written(monkeypatch, markup_pki, tmp_path):
    _card(monkeypatch, markup_pki)
    anchors = _anchor_dir(tmp_path, markup_pki)
    _, text = _both(["genuine", "verify", "--nonce", _NONCE.hex(), "--anchors", anchors])
    assert "device leaf: CN=Device [b]S[/b]" in text
    assert "CN=Device [b]S[/b] -> CN=SUB a[/x]b -> CN=TEST [b]ROOT[/b]" in text


@pytest.mark.xfail(strict=True, reason="certificate names are printed as console markup")
def test_verify_prints_a_reason_naming_a_bracketed_issuer_as_written(monkeypatch, markup_pki):
    _card(monkeypatch, markup_pki)
    _, text = _both(["genuine", "verify", "--nonce", _NONCE.hex()])
    assert "- not anchored: no pinned root issues 'CN=SUB a[/x]b'" in text
