"""`_generate_key_on_card`: which path it takes, and what it sends on each.

The seam is shared by `piv perso generate-key` and `piv quickstart`, so both inherit
whatever this helper does. Two properties matter most and are asserted directly: a
card that returns the full template must behave exactly as before (no extra APDU, no
environment read, no console line), and a card that truncates must SELECT, authenticate
the management key, and repeat the generation - in that order, with nothing in between
the two halves of the authentication.
"""

from __future__ import annotations

import contextlib

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptnox_id_cli.applets.piv import mgmt_auth as ma
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.util import tlv

RSA2048 = 0x07
KEY256 = bytes(range(32))
WITNESS = bytes.fromhex("A7E57B882467107902739D50387B3651")


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def template(rsa_key) -> bytes:
    numbers = rsa_key.public_key().public_numbers()
    body = tlv.build(perso_mod.TAG_RSA_MODULUS, numbers.n.to_bytes(256, "big")) + tlv.build(
        perso_mod.TAG_RSA_EXPONENT, numbers.e.to_bytes(3, "big")
    )
    return tlv.build(perso_mod.TAG_PUBKEY_TEMPLATE, body)


class FakeSession:
    """The plain side of the card: SELECT, the 9B exchange, and plain GENERATE."""

    reader_name = "Fake Contact Reader 00 00"

    def __init__(self, template: bytes, *, key: bytes = KEY256, mechanism: int = 0x0C) -> None:
        self.template = template
        self.key = key
        self.mechanism = mechanism
        self.sent: list[str] = []
        #: overrides, keyed by INS, applied before the default behaviour
        self.generate_response: Response | None = None
        self.witness_sw: int | None = None
        self.mutual_sw: int | None = None

    @property
    def atr(self) -> bytes:
        return bytes.fromhex("3BFA1300008131FE454A434F5033")

    def transmit(self, apdu, *, context: str | None = None) -> Response:
        self.sent.append(apdu.to_bytes().hex().upper())
        if apdu.ins == 0xA4:
            return Response(b"", 0x90, 0x00)
        if apdu.ins == 0x87:
            return self._general_authenticate(apdu)
        if apdu.ins == perso_mod.INS_GENERATE_ASYMMETRIC:
            if self.generate_response is not None:
                return self.generate_response
            return Response(self.template, 0x90, 0x00)
        return Response(b"", 0x6A, 0x82)

    def _general_authenticate(self, apdu) -> Response:
        if apdu.p1 != self.mechanism:
            return Response(b"", 0x6A, 0x86)
        fields = {c.tag: c.value for c in tlv.parse(apdu.data)[0].children}
        if set(fields) == {ma.TAG_WITNESS}:
            if self.witness_sw is not None:
                return Response(b"", self.witness_sw >> 8, self.witness_sw & 0xFF)
            body = tlv.build_constructed(
                ma.TAG_DYNAMIC_AUTH,
                tlv.build(ma.TAG_WITNESS, ma.aes_ecb_encrypt(self.key, WITNESS)),
            )
            return Response(body, 0x90, 0x00)
        if self.mutual_sw is not None:
            return Response(b"", self.mutual_sw >> 8, self.mutual_sw & 0xFF)
        body = tlv.build_constructed(
            ma.TAG_DYNAMIC_AUTH,
            tlv.build(ma.TAG_RESPONSE, ma.aes_ecb_encrypt(self.key, fields[ma.TAG_CHALLENGE])),
        )
        return Response(body, 0x90, 0x00)


class FakeAdmin:
    """The admin-channel side: records the session lifecycle, answers GENERATE."""

    def __init__(self, session: FakeSession, secured_response: Response) -> None:
        self.card = session
        self.secured_response = secured_response
        self.events: list[str] = []

    def select(self) -> None:
        self.events.append("select")
        self.card.transmit(_select_apdu())

    def open(self, keys) -> None:
        self.events.append("open")

    def forget_channel(self) -> None:
        self.events.append("forget_channel")

    def send(self, apdu, *, context: str | None = None) -> Response:
        self.events.append(f"send:{apdu.ins:02X}")
        return self.secured_response


def _select_apdu():
    from cryptnox_id_cli.applets.piv import constants as pivc
    from cryptnox_id_cli.transport.apdu import APDU

    return APDU(0x00, pivc.INS_SELECT, 0x04, 0x00, data=pivc.PIV_AID, le=256)


def _app(**kw) -> AppContext:
    return AppContext(**kw)


def _generate(adm, app, **kw):
    return piv_cmd._generate_key_on_card(app, adm, object(), 0x9A, RSA2048, label="9A", **kw)


@pytest.fixture(autouse=True)
def _no_inherited_env(monkeypatch):
    monkeypatch.delenv("PIV_MGMT_KEY", raising=False)
    monkeypatch.delenv("CARD_PIV_MGMT_KEY", raising=False)


# ------------------------------------------------------- field-card behaviour --
def test_a_card_that_returns_the_full_template_is_untouched(template, rsa_key, capsys):
    session = FakeSession(template)
    adm = FakeAdmin(session, Response(template, 0x90, 0x00))
    generated = _generate(adm, _app())

    assert generated.path == "admin-channel"
    assert generated.management_key_auth is None
    assert generated.public_key.public_numbers() == rsa_key.public_key().public_numbers()
    assert adm.events == ["select", "open", "send:47"]
    assert [cmd[:8] for cmd in session.sent] == ["00A40400"], "only the admin SELECT was sent"
    assert "management key" not in capsys.readouterr().out


def test_ecc_never_takes_the_fallback(template):
    # A 256-byte success on an ECC mechanism cannot be truncation; it is a parse error.
    session = FakeSession(template)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    with pytest.raises(piv_cmd.CryptnoxError, match="cannot parse"):
        piv_cmd._generate_key_on_card(_app(), adm, object(), 0x9A, 0x11, label="9A")
    assert adm.events == ["select", "open", "send:47"]


# ------------------------------------------------------------- happy fallback --
def test_the_fallback_selects_authenticates_and_regenerates(template, rsa_key, monkeypatch):
    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    session = FakeSession(template)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    generated = _generate(adm, _app())

    assert generated.path == "management-key"
    assert generated.management_key_auth == {"mechanism": "AES-256", "source": "$PIV_MGMT_KEY"}
    assert generated.public_key.public_numbers() == rsa_key.public_key().public_numbers()
    assert adm.events == ["select", "open", "send:47", "select", "forget_channel"]
    # SELECT, witness request, mutual response, plain GENERATE - in that order, with
    # nothing between the two halves of the authentication.
    assert [cmd[:8] for cmd in session.sent] == [
        "00A40400",  # the admin channel's own SELECT
        "00A40400",  # the fallback's SELECT, which resets the card's channel
        "00870C9B",
        "00870C9B",
        "0047009A",
    ]


def test_the_operator_is_told_the_first_key_was_already_replaced(template, monkeypatch, capsys):
    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    adm = FakeAdmin(FakeSession(template), Response(template[:256], 0x90, 0x00))
    _generate(adm, _app())
    warning = capsys.readouterr().out
    assert "256 of 270" in warning
    assert "already replaced the key in slot 9A" in warning


def test_default_keys_supplies_the_published_development_value(template):
    from cryptnox_id_cli.secrets.resolver import DEFAULT_GP_KEY

    session = FakeSession(template, key=DEFAULT_GP_KEY * 2)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    generated = _generate(adm, _app(), default_keys=True)
    assert generated.management_key_auth == {"mechanism": "AES-256", "source": "--default-keys"}


# ----------------------------------------------------------------- refusals ---
def test_no_key_material_says_how_to_supply_it(template):
    from cryptnox_id_cli.secrets.resolver import SecretInputError

    session = FakeSession(template)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    with pytest.raises(SecretInputError) as excinfo:
        _generate(adm, _app())
    assert "PIV_MGMT_KEY" in str(excinfo.value)
    assert "--default-keys" in str(excinfo.value)
    assert not any(cmd.startswith("0087") for cmd in session.sent)


def test_an_empty_9b_names_the_command_that_loads_a_value(template, monkeypatch):
    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    session = FakeSession(template)
    session.witness_sw = 0x6983
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _generate(adm, _app())
    assert excinfo.value.stage == "empty"
    assert excinfo.value.exit_code == 7
    assert "set-mgmt-key" in str(excinfo.value)
    assert not any(cmd.startswith("0047") for cmd in session.sent)


def test_a_wrong_management_key_is_reported_as_such(template, monkeypatch):
    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    session = FakeSession(template)
    session.mutual_sw = 0x6982
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    with pytest.raises(ma.MgmtKeyError) as excinfo:
        _generate(adm, _app())
    assert excinfo.value.stage == "key_mismatch"


def test_a_refused_plain_generate_surfaces_the_status_word(template, monkeypatch):
    from cryptnox_id_cli.transport.errors import StatusWordError

    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    session = FakeSession(template)
    session.generate_response = Response(b"", 0x6A, 0x80)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    with pytest.raises(StatusWordError, match="management-key path"):
        _generate(adm, _app())


def test_6982_on_the_plain_generate_names_the_admin_key_binding(template, monkeypatch):
    from cryptnox_id_cli.transport.errors import StatusWordError

    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    session = FakeSession(template)
    session.generate_response = Response(b"", 0x69, 0x82)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    with pytest.raises(StatusWordError, match="different admin key"):
        _generate(adm, _app())


def test_a_still_truncated_plain_response_stops_instead_of_looping(template, monkeypatch):
    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    session = FakeSession(template)
    session.generate_response = Response(template[:256], 0x90, 0x00)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))
    with pytest.raises(piv_cmd.CryptnoxError, match="no further fallback"):
        _generate(adm, _app())


def test_an_unparseable_template_is_a_cli_error_not_a_traceback():
    adm = FakeAdmin(FakeSession(b""), Response(bytes.fromhex("7F4903810100"), 0x90, 0x00))
    with pytest.raises(piv_cmd.CryptnoxError) as excinfo:
        _generate(adm, _app())
    assert excinfo.value.to_dict()["error"] == "error"
    assert "6 bytes over the admin-channel path" in str(excinfo.value)


# ------------------------------------------------------------ command level ---
def test_the_json_payload_reports_the_path_and_the_management_key(template, monkeypatch):
    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    session = FakeSession(template)
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))

    @contextlib.contextmanager
    def fake_session(self):
        yield session

    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(piv_cmd, "_select", lambda s: object())
    monkeypatch.setattr(piv_cmd, "_read_cert_der", lambda piv, name: None)
    monkeypatch.setattr(piv_cmd, "PivAdmin", lambda s: adm)
    for var in ("PIV_SCP03_ENC", "PIV_SCP03_MAC", "PIV_SCP03_DEK"):
        monkeypatch.setenv(var, "40" * 16)  # the admin channel is stubbed out anyway

    result = CliRunner().invoke(
        root,
        ["--json", "piv", "perso", "generate-key", "--slot", "9A", "--algorithm", "RSA2048"],
    )
    assert result.exit_code == 0, result.output
    import json

    payload = json.loads(result.stdout)
    assert payload["generate_path"] == "management-key"
    assert payload["management_key_auth"] == {"mechanism": "AES-256", "source": "$PIV_MGMT_KEY"}


def test_the_exit_code_for_a_management_key_failure_is_seven(template, monkeypatch):
    session = FakeSession(template)
    session.witness_sw = 0x6983
    adm = FakeAdmin(session, Response(template[:256], 0x90, 0x00))

    @contextlib.contextmanager
    def fake_session(self):
        yield session

    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(piv_cmd, "_select", lambda s: object())
    monkeypatch.setattr(piv_cmd, "_read_cert_der", lambda piv, name: None)
    monkeypatch.setattr(piv_cmd, "PivAdmin", lambda s: adm)
    for var in ("PIV_SCP03_ENC", "PIV_SCP03_MAC", "PIV_SCP03_DEK"):
        monkeypatch.setenv(var, "40" * 16)  # the admin channel is stubbed out anyway

    result = CliRunner().invoke(
        root,
        ["--json", "piv", "perso", "generate-key", "--slot", "9A", "--algorithm", "RSA2048"],
    )
    assert result.exit_code == 7
    import json

    error = json.loads(result.stdout or result.output)
    assert error["error"] == "mgmt_key"
    assert error["stage"] == "empty"


# ---------------------------------------------------- quickstart, end to end ---
class FakeCard(FakeSession):
    """FakeSession plus the card state the steps after the fallback depend on.

    SELECT closes the secure channel and drops the key-holder role, a completed 9B
    exchange grants the role, and every command is answered the way the card answers
    it in that state: GENERATE is cut at 256 bytes inside the channel and complete
    behind the role, PUT DATA needs the channel.
    """

    REFUSED = Response(b"", 0x69, 0x82)

    def __init__(self, template: bytes) -> None:
        super().__init__(template)
        self.channel_open = False
        self.key_holder = False

    def transmit(self, apdu, *, context: str | None = None) -> Response:
        self.sent.append(apdu.to_bytes().hex().upper())
        if apdu.ins == 0xA4:
            self.channel_open = self.key_holder = False
            return Response(b"", 0x90, 0x00)
        if apdu.ins == 0x87:
            resp = self._general_authenticate(apdu)
            fields = {c.tag for c in tlv.parse(apdu.data)[0].children}
            self.key_holder = resp.ok and ma.TAG_CHALLENGE in fields
            return resp
        if apdu.ins == perso_mod.INS_GENERATE_ASYMMETRIC:
            if self.channel_open:
                return Response(self.template[:256], 0x90, 0x00)
            return Response(self.template, 0x90, 0x00) if self.key_holder else self.REFUSED
        if apdu.ins == perso_mod.INS_PUT_DATA:
            return Response(b"", 0x90, 0x00) if self.channel_open else self.REFUSED
        return Response(b"", 0x6A, 0x82)


class _PlainChannel:
    """Stands in for the channel's wrapping; FakeCard tracks the channel itself."""

    def wrap(self, apdu):
        return apdu

    def unwrap(self, resp):
        return resp


def test_quickstart_reopens_the_admin_channel_after_the_fallback(template, rsa_key, monkeypatch):
    # The fallback leaves the card with no secure channel and the host with none
    # either, so the certificate write that follows has to open its own.
    import json

    from cryptography.hazmat.primitives.asymmetric import padding, utils

    from cryptnox_id_cli.applets.piv import keyimport
    from cryptnox_id_cli.applets.piv.admin import PivAdmin

    card = FakeCard(template)

    @contextlib.contextmanager
    def fake_session(self):
        yield card

    def open_channel(self, keys, **kw) -> None:
        self.scp = _PlainChannel()
        self.scp_version = 0x03
        self.card.channel_open = True

    def sign_off_card(session, ref, mech, pin, build):
        digest_alg = utils.Prehashed(keyimport.digest_for_mechanism(mech))
        return build(lambda digest: rsa_key.sign(digest, padding.PKCS1v15(), digest_alg))

    facts = piv_cmd.CardFacts(
        pin_configured=True,
        puk_configured=True,
        key_object_present=True,
        cert_present=False,
        chuid_present=True,
        ccc_present=True,
    )
    monkeypatch.setattr(AppContext, "open_session", fake_session)
    monkeypatch.setattr(PivAdmin, "open", open_channel)
    monkeypatch.setattr(piv_cmd, "_collect_quickstart_facts", lambda s, ref, mech: (facts, "x"))
    monkeypatch.setattr(piv_cmd, "_select", lambda s: object())
    monkeypatch.setattr(piv_cmd, "_pin_truth", lambda piv, pin: ("match", None))
    monkeypatch.setattr(piv_cmd, "_sign_with_session", sign_off_card)
    monkeypatch.setenv("PIV_MGMT_KEY", KEY256.hex())
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    for var in ("PIV_SCP03_ENC", "PIV_SCP03_MAC", "PIV_SCP03_DEK"):
        monkeypatch.setenv(var, "40" * 16)  # open_channel ignores the keys

    result = CliRunner().invoke(
        root,
        ["--json", "--yes", "piv", "quickstart", "--profile", "ms-logon"]
        + ["--slot", "9A", "--algorithm", "RSA2048"],
    )
    assert result.exit_code == 0, result.output

    steps = {s["step"]: s for s in json.loads(result.stdout)["steps"]}
    assert steps["generate-key"]["detail"]["generate_path"] == "management-key"
    assert steps["certificate"]["status"] == "ok"
    assert steps["smoke-test"]["status"] == "ok"

    in_channel, plain = (i for i, cmd in enumerate(card.sent) if cmd[:8] == "0047009A")
    assert card.sent[plain - 1][:8] == "00870C9B", "generated behind the 9B role"
    after = [cmd[:8] for cmd in card.sent[plain + 1 :]]
    assert after[0] == "00A40400", "the certificate step starts from a fresh SELECT"
    assert all(cmd[2:8] == "DB3FFF" for cmd in after[1:]), after
    assert len(after) > 1
