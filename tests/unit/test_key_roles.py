"""Key roles: the 6985 explanation on signing, `piv perso create-key-object`, the
profile 9A warning and quickstart's refusal of a certificate step that cannot sign.

The key-listing rows follow the D600 capture in ``test_piv_inventory.py``: tag 8E is
the mechanism, 8F the role (01 AUTHENTICATE, 04 SIGN).
"""

from __future__ import annotations

import json

import pytest
from _cardfakes import run, wire_session

from cryptnox_id_cli.applets.piv import preperso as pp
from cryptnox_id_cli.applets.piv import profiles as prof
from cryptnox_id_cli.cli.commands import piv as piv_cmd
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.transport.pcsc import CardSession

ECCP256, ECCP384, RSA2048 = 0x11, 0x14, 0x07
AUTH, SIGN, KEY_ESTABLISH = pp.ROLE_AUTHENTICATE, pp.ROLE_SIGN, pp.ROLE_KEY_ESTABLISH
STATUS_SECURED = bytes.fromhex("531880010F8101008201008301008401008501008601008701FF")


def _key_row(ref: int, mech: int, role: int) -> bytes:
    body = f"8B01{ref:02X}8C01018D010091019B8E01{mech:02X}8F01{role:02X}900110"
    return bytes.fromhex("5315" + body)


class Card:
    """Answers SELECT, VERIFY, the key listing, and GENERAL AUTHENTICATE with ``sign_sw``."""

    def __init__(
        self, keys, *, sign_sw: int = 0x6985, restricted: bool = False, secured: bool = False
    ) -> None:
        self.keys = [_key_row(*k) for k in keys]
        self.sign_sw = sign_sw
        self.restricted = restricted
        self.secured = secured
        self.sent: list[bytes] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        raw = bytes(apdu)
        self.sent.append(raw)
        ins, p1, p2 = raw[1], raw[2], raw[3]
        if ins in (0xA4, 0x20):
            return [], 0x90, 0x00
        if ins == 0x87:
            return [], self.sign_sw >> 8, self.sign_sw & 0xFF
        if ins == 0xCB and p1 == 0x3F and raw[-3:-1] == b"\x47\x53" and self.secured:
            return list(STATUS_SECURED), 0x90, 0x00
        if ins == 0xCB and p1 == 0x3F and raw[-3:-1] == b"\x47\x4b":
            if self.restricted:
                return [], 0x69, 0x86
            if p2 < len(self.keys):
                return list(self.keys[p2]), 0x90, 0x00
        return [], 0x6A, 0x82

    def get_atr(self) -> bytes:
        return b"\x3b\x00"

    def disconnect(self) -> None:
        pass


def _session(card: Card) -> CardSession:
    return CardSession(card)


# --------------------------------------------------------------- 6985 hint --- #
def test_refusal_names_the_role_and_suggests_a_free_algorithm():
    text = piv_cmd._sign_refusal(_session(Card([(0x9A, ECCP256, AUTH)])), 0x9A, ECCP256, 0x6985)
    assert "has the role AUTHENTICATE" in text
    assert "sign with slot 9C" in text
    assert "create-key-object --slot 9A --algorithm RSA2048 --role SIGN+AUTHENTICATE" in text


def test_refusal_skips_algorithms_the_slot_already_has():
    card = Card([(0x9A, ECCP256, AUTH), (0x9A, RSA2048, AUTH)])
    text = piv_cmd._sign_refusal(_session(card), 0x9A, ECCP256, 0x6985)
    assert "--algorithm ECCP384" in text


def test_refusal_on_9c_does_not_send_the_user_to_9c():
    text = piv_cmd._sign_refusal(_session(Card([(0x9C, ECCP256, AUTH)])), 0x9C, ECCP256, 0x6985)
    assert "9C instead" not in text and "sign with slot 9C" not in text
    assert text.endswith("--algorithm RSA2048.")


def test_refusal_without_the_listing_says_the_role_cannot_be_read():
    text = piv_cmd._sign_refusal(_session(Card([], restricted=True)), 0x9A, ECCP256, 0x6985)
    assert "withholds its key listing" in text and "piv inventory" not in text
    assert "Slot 9C signs" in text
    text = piv_cmd._sign_refusal(_session(Card([], restricted=True)), 0x9C, ECCP256, 0x6985)
    assert "Slot 9C signs" not in text


@pytest.mark.parametrize(
    ("role", "mech", "signs"),
    [
        (SIGN, ECCP256, True),
        (SIGN | AUTH, RSA2048, True),
        (AUTH, ECCP256, False),
        (KEY_ESTABLISH, RSA2048, True),
        (KEY_ESTABLISH, 0x05, True),
        (KEY_ESTABLISH, 0x16, True),
        (KEY_ESTABLISH, ECCP256, False),
        (SIGN, 0x08, True),
    ],
)
def test_key_signs_follows_the_applet(role, mech, signs):
    assert pp.key_signs(role, mech) is signs


def test_refusal_points_at_a_sibling_that_signs_instead_of_a_new_object():
    card = Card([(0x9A, ECCP256, AUTH), (0x9A, RSA2048, SIGN | AUTH)])
    text = piv_cmd._sign_refusal(_session(card), 0x9A, ECCP256, 0x6985)
    assert "pass --algorithm RSA2048, and that key's public key" in text
    assert "create-key-object" not in text


def test_refusal_on_a_finalized_applet_offers_no_new_object():
    card = Card([(0x9A, ECCP256, AUTH)], secured=True)
    text = piv_cmd._sign_refusal(_session(card), 0x9A, ECCP256, 0x6985)
    assert "create-key-object" not in text
    assert text.endswith("Sign with slot 9C.")


def test_refusal_with_every_alternative_taken():
    taken = [(0x9A, m, AUTH) for m in (ECCP256, ECCP384, RSA2048)]
    text = piv_cmd._sign_refusal(_session(Card(taken)), 0x9A, ECCP256, 0x6985)
    assert text.endswith("Sign with slot 9C.")
    taken = [(0x9C, m, AUTH) for m in (ECCP256, ECCP384, RSA2048)]
    text = piv_cmd._sign_refusal(_session(Card(taken)), 0x9C, ECCP256, 0x6985)
    assert text.endswith("cannot be changed.")


def test_refusal_for_an_ecc_key_establishment_key():
    card = Card([(0x9D, ECCP256, KEY_ESTABLISH)])
    text = piv_cmd._sign_refusal(_session(card), 0x9D, ECCP256, 0x6A86)
    assert "has the role KEY-ESTABLISH, which cannot sign" in text


def test_withheld_listing_and_6a86_points_at_the_algorithm():
    text = piv_cmd._sign_refusal(_session(Card([], restricted=True)), 0x9C, ECCP384, 0x6A86)
    assert "no ECCP384 key that can sign" in text and "--algorithm" in text
    assert "role does not include SIGN" not in text


def test_a_symmetric_key_is_never_offered_as_the_signing_sibling():
    card = Card([(0x9E, ECCP256, AUTH), (0x9E, 0x08, SIGN)])
    text = piv_cmd._sign_refusal(_session(card), 0x9E, ECCP256, 0x6985)
    assert "AES" not in text and "also holds" not in text


def test_refusal_for_an_object_the_listing_lacks_is_generic():
    assert (
        piv_cmd._sign_refusal(_session(Card([(0x9C, ECCP256, SIGN)])), 0x9A, ECCP256, 0x6985)
        is None
    )


def test_an_empty_hint_keeps_the_table_text():
    from cryptnox_id_cli.transport.errors import StatusWordError

    assert "Conditions of use not satisfied" in str(StatusWordError(0x69, 0x85, hint=""))
    assert str(StatusWordError(0x69, 0x85, hint="why")) == "why (SW=6985)"


def test_a_signing_key_leaves_the_generic_message():
    assert (
        piv_cmd._sign_refusal(_session(Card([(0x9A, ECCP256, SIGN)])), 0x9A, ECCP256, 0x6985)
        is None
    )


def test_6a86_from_an_ecc_key_establishment_key_is_explained(monkeypatch):
    wire_session(monkeypatch, Card([(0x9D, ECCP256, KEY_ESTABLISH)], sign_sw=0x6A86))
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    result = run(["--json", "piv", "perso", "smoke-test", "--slot", "9D"])
    assert result.exit_code != 0
    assert "KEY-ESTABLISH" in json.loads(result.stdout)["message"]


def test_other_refusals_keep_the_table_text_and_read_no_listing(monkeypatch):
    card = Card([(0x9A, ECCP256, AUTH)], sign_sw=0x6982)
    wire_session(monkeypatch, card)
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    result = run(["--json", "piv", "perso", "smoke-test", "--slot", "9A"])
    assert json.loads(result.stdout)["sw"] == "6982"
    assert "role" not in json.loads(result.stdout)["message"]
    assert not any(frame[1] == 0xCB for frame in card.sent)


def test_smoke_test_reports_the_role(monkeypatch):
    wire_session(monkeypatch, Card([(0x9A, ECCP256, AUTH)]))
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    result = run(["--json", "piv", "perso", "smoke-test", "--slot", "9A"])
    assert result.exit_code != 0
    error = json.loads(result.stdout)
    assert error["sw"] == "6985"
    assert "has the role AUTHENTICATE" in error["message"]
    assert "lifecycle" not in error["message"]


# ------------------------------------------------------ create-key-object --- #
class ProbeCard(Card):
    """The (slot, mechanism) probe answers ``probe_sw``."""

    def __init__(self, probe_sw: int, *, secured: bool = False) -> None:
        super().__init__([], sign_sw=probe_sw, secured=secured)


@pytest.fixture
def created(monkeypatch):
    ops: list[bytes] = []
    monkeypatch.setattr(piv_cmd, "_send_create_key", lambda adm, keys, op, slot: ops.append(op))
    return ops


def _create(*extra: str):
    return run(
        [
            "--json",
            "--yes",
            "piv",
            "perso",
            "create-key-object",
            "--slot",
            "9a",
            "--algorithm",
            "RSA2048",
            "--role",
            "sign+authenticate",
            "--default-keys",
            *extra,
        ]
    )


def test_create_sends_the_requested_object(monkeypatch, created):
    wire_session(monkeypatch, ProbeCard(0x6A86))
    result = _create()
    assert result.exit_code == 0, result.output
    assert created == [pp.create_key(0x9A, pp.MODE_PIN, pp.MODE_NEVER, RSA2048, 0x05, 0x10)]
    out = json.loads(result.stdout)
    assert (out["slot"], out["algorithm"], out["created"]) == ("9A", "RSA2048", True)
    assert out["roles"] == ["AUTHENTICATE", "SIGN"]


def test_create_dry_run_sends_nothing(monkeypatch, created):
    wire_session(monkeypatch, ProbeCard(0x6A86))
    result = _create("--dry-run")
    assert result.exit_code == 0, result.output
    assert created == []
    assert json.loads(result.stdout)["created"] is False


def test_create_refuses_an_existing_object(monkeypatch, created):
    wire_session(monkeypatch, ProbeCard(0x6982))
    result = _create()
    assert result.exit_code != 0
    assert "already has a key object for RSA2048" in result.output
    assert created == []


def test_create_refuses_a_finalized_applet_before_the_probe(monkeypatch, created):
    card = ProbeCard(0x6A86, secured=True)
    wire_session(monkeypatch, card)
    result = _create()
    assert result.exit_code != 0
    assert "finalized" in result.output
    assert created == [] and not any(frame[1] == 0x87 for frame in card.sent)


@pytest.mark.parametrize("answer", ["n\n", "\n"])
def test_create_asks_and_a_no_or_enter_writes_nothing(monkeypatch, created, answer):
    wire_session(monkeypatch, ProbeCard(0x6A86))
    result = run(
        ["piv", "perso", "create-key-object", "--slot", "9A", "--algorithm", "RSA2048"]
        + ["--role", "SIGN", "--default-keys"],
        input=answer,
    )
    assert result.exit_code != 0
    assert "Create the key object?" in result.output
    assert created == []


def test_create_passes_modes_and_rsa_crt_through(monkeypatch, created):
    wire_session(monkeypatch, ProbeCard(0x6A86))
    result = _create("--contact", "ALWAYS", "--contactless", "PIN", "--rsa-crt")
    assert result.exit_code == 0, result.output
    assert created == [
        pp.create_key(0x9A, pp.MODE_ALWAYS, pp.MODE_PIN, RSA2048, 0x05, 0x10 | pp.ATTR_RSA_CRT)
    ]


@pytest.mark.parametrize(
    "args",
    [
        ["--slot", "9A", "--algorithm", "ECCP384", "--role", "SIGN+KEY_ESTABLISH"],
        ["--slot", "9D", "--algorithm", "RSA2048", "--role", "SIGN+KEY_ESTABLISH"],
        ["--slot", "9A", "--algorithm", "ECCP256", "--role", "SIGN+NOPE"],
        ["--slot", "9A", "--algorithm", "ECCP256", "--role", "SIGN", "--rsa-crt"],
        ["--slot", "9B", "--algorithm", "ECCP256", "--role", "SIGN"],
    ],
)
def test_create_rejects_bad_options_before_the_card(monkeypatch, args):
    def no_session(self):
        raise AssertionError("bad options reached the card")

    monkeypatch.setattr(piv_cmd.AppContext, "open_session", no_session)
    result = run(["piv", "perso", "create-key-object", *args, "--default-keys"])
    assert result.exit_code == 2


class _Admin:
    def __init__(self, sw: int) -> None:
        self.sw = sw

    def select(self) -> None:
        pass

    def open(self, keys) -> None:
        pass

    def send(self, apdu, *, context=None):
        from cryptnox_id_cli.transport.apdu import Response

        return Response(b"", self.sw >> 8, self.sw & 0xFF)


@pytest.mark.parametrize(("sw", "text"), [(0x6E27, "already has"), (0x6986, "finalized")])
def test_send_create_key_explains_refusals(sw, text):
    with pytest.raises(CryptnoxError, match=text):
        piv_cmd._send_create_key(_Admin(sw), object(), b"\x00", "9A")


# ------------------------------------------------------------- templates --- #
def test_template_prefers_the_profile_entry_for_the_mechanism():
    ms_logon = prof.builtin("ms-logon")
    assert piv_cmd._key_template(0x9A, RSA2048, ms_logon)[2] == SIGN | AUTH
    assert piv_cmd._key_template(0x9A, RSA2048)[2] == AUTH
    assert piv_cmd._key_template(0x9C, ECCP256)[2] == SIGN
    assert piv_cmd._key_template(0x82, ECCP256)[2] == pp.ROLE_KEY_ESTABLISH


def test_profile_without_9a_gets_no_warning():
    import dataclasses

    default = prof.builtin("cryptnox-default")
    no_9a = dataclasses.replace(default, keys=[k for k in default.keys if k.ref != 0x9A])
    assert no_9a.piv_auth_warning() is None


def test_profile_warning_only_for_a_9a_that_cannot_sign():
    assert "can authenticate but not sign" in prof.builtin("cryptnox-default").piv_auth_warning()
    assert prof.builtin("ssh").piv_auth_warning() is None
    assert prof.builtin("ms-logon").piv_auth_warning() is None


def test_load_config_warns_before_a_real_write():
    result = run(
        ["factory", "piv", "preperso", "load-config", "--profile", "cryptnox-default"],
        input="n\n",
    )
    assert result.exit_code != 0
    assert "can authenticate but not sign" in result.output


def test_load_config_dry_run_warns_about_9a():
    result = run(
        ["factory", "piv", "preperso", "load-config", "--profile", "cryptnox-default", "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    assert "can authenticate but not sign" in result.output


# ------------------------------------------------------------- quickstart --- #
def _facts(**kw) -> piv_cmd.CardFacts:
    base = {
        "pin_configured": True,
        "puk_configured": True,
        "structure_present": True,
        "key_object_present": True,
        "cert_present": False,
        "chuid_present": True,
        "ccc_present": True,
        **kw,
    }
    return piv_cmd.CardFacts(**base)


def _opts(**kw) -> piv_cmd.QuickstartOptions:
    base = {
        "slot": 0x9A,
        "mechanism": ECCP256,
        "cert_mode": "self-signed",
        "include_preperso": True,
        **kw,
    }
    return piv_cmd.QuickstartOptions(**base)


def test_quickstart_refuses_a_certificate_on_a_key_that_cannot_sign():
    with pytest.raises(CryptnoxError, match="create-key-object"):
        piv_cmd._plan_quickstart(_facts(key_object_can_sign=False), _opts())


def test_quickstart_refusal_names_a_sibling_that_signs():
    facts = _facts(key_object_can_sign=False, signing_siblings=("RSA2048",))
    with pytest.raises(CryptnoxError, match="pass --algorithm RSA2048") as exc:
        piv_cmd._plan_quickstart(facts, _opts())
    assert "create-key-object" not in str(exc.value)


def test_quickstart_refusal_on_a_finalized_applet_offers_no_new_object():
    facts = _facts(key_object_can_sign=False, applet_secured=True)
    with pytest.raises(CryptnoxError) as exc:
        piv_cmd._plan_quickstart(facts, _opts())
    assert "create-key-object" not in str(exc.value)


def test_quickstart_refusal_on_9c_does_not_offer_9c():
    with pytest.raises(CryptnoxError) as exc:
        piv_cmd._plan_quickstart(_facts(key_object_can_sign=False), _opts(slot=0x9C))
    assert "Use slot 9C" not in str(exc.value)


def test_quickstart_on_a_finalized_applet_plans_no_new_object():
    facts = _facts(key_object_present=False, applet_secured=True)
    with pytest.raises(CryptnoxError, match="finalized"):
        piv_cmd._plan_quickstart(facts, _opts(cert_mode="none"))


def test_quickstart_refuses_a_missing_object_the_profile_would_create_unsigning():
    with pytest.raises(CryptnoxError, match="would create"):
        piv_cmd._plan_quickstart(_facts(key_object_present=False), _opts(new_object_can_sign=False))


def test_quickstart_refuses_a_profile_that_would_create_a_key_that_cannot_sign():
    with pytest.raises(CryptnoxError, match="profile 'cryptnox-default'"):
        piv_cmd._plan_quickstart(
            _facts(structure_present=False, key_object_present=False),
            _opts(new_object_can_sign=False),
        )


@pytest.mark.parametrize(
    ("facts", "opts"),
    [
        (_facts(key_object_can_sign=False), _opts(cert_mode="none")),
        (_facts(key_object_can_sign=None), _opts()),
        (_facts(key_object_can_sign=False, cert_present=True), _opts()),
        (_facts(key_object_present=False), _opts(new_object_can_sign=True)),
    ],
)
def test_quickstart_plans_when_the_certificate_can_be_made(facts, opts):
    assert piv_cmd._plan_quickstart(facts, opts)


# ------------------------------------------------------ quickstart wiring --- #
def _quickstart(monkeypatch, facts, *args):
    import contextlib

    @contextlib.contextmanager
    def no_card(self):
        yield object()

    monkeypatch.setattr(piv_cmd.AppContext, "open_session", no_card)
    monkeypatch.setattr(piv_cmd, "_collect_quickstart_facts", lambda s, ref, mech: (facts, "x"))
    return run(["--json", "--yes", "piv", "quickstart", *args])


@pytest.mark.parametrize("profile", ["cryptnox-default", "developer"])
def test_quickstart_refuses_a_profile_whose_9a_cannot_sign(monkeypatch, profile):
    blank = _facts(structure_present=False, key_object_present=False)
    result = _quickstart(
        monkeypatch, blank, "--profile", profile, "--slot", "9A", "--include-preperso", "--dry-run"
    )
    assert result.exit_code != 0
    assert f"profile '{profile}'" in json.loads(result.stdout)["message"]


def test_quickstart_plans_a_profile_whose_9a_signs(monkeypatch):
    blank = _facts(structure_present=False, key_object_present=False)
    result = _quickstart(
        monkeypatch, blank, "--profile", "ssh", "--slot", "9A", "--include-preperso", "--dry-run"
    )
    assert result.exit_code == 0, result.output


def test_quickstart_creates_the_object_with_the_profile_role(monkeypatch):
    seen = {}

    def spy(app, adm, keys, ref, mech, rsa_crt, slot, *, profile=None, confirmed=False):
        seen["role"] = piv_cmd._key_template(ref, mech, profile)[2]
        seen["rsa_crt"], seen["confirmed"] = rsa_crt, confirmed
        raise CryptnoxError("stop after the create step")

    facts = _facts(key_object_present=False)
    monkeypatch.setattr(piv_cmd, "_create_key_object", spy)
    monkeypatch.setattr(piv_cmd, "_select", lambda s: object())
    monkeypatch.setattr(piv_cmd, "_pin_truth", lambda piv, pin: ("match", None))
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    result = _quickstart(
        monkeypatch,
        facts,
        "--profile",
        "ms-logon",
        "--slot",
        "9A",
        "--algorithm",
        "RSA2048",
        "--include-preperso",
        "--default-keys",
    )
    assert seen.get("role") == SIGN | AUTH, result.output
    assert seen["rsa_crt"] is True and seen["confirmed"] is True


def test_quickstart_warns_about_the_profile_before_laying_down_the_structure(monkeypatch):
    def stop(self):
        raise CryptnoxError("stop before the card")

    monkeypatch.setattr(piv_cmd.PivAdmin, "select", stop)
    monkeypatch.setenv("CRYPTNOX_PIV_NEW_PIN", "123456")
    monkeypatch.setenv("CRYPTNOX_PIV_NEW_PUK", "12345678")
    blank = _facts(structure_present=False, key_object_present=False, pin_configured=False)
    result = _quickstart(
        monkeypatch,
        blank,
        "--slot",
        "9C",
        "--cert-mode",
        "none",
        "--include-preperso",
        "--default-keys",
    )
    assert "can authenticate but not sign" in result.stderr


@pytest.mark.parametrize(("secured", "offered"), [(False, True), (True, False)])
def test_quickstart_rsa_refusal_offers_create_only_when_possible(monkeypatch, secured, offered):
    facts = _facts(key_object_present=False, applet_secured=secured)
    result = _quickstart(monkeypatch, facts, "--slot", "9A", "--algorithm", "RSA2048", "--dry-run")
    assert result.exit_code == 2
    assert ("create-key-object" in result.output) is offered


# ------------------------------------------------------------- round three --- #
def test_an_empty_key_object_is_named_not_a_blocked_pin():
    text = piv_cmd._sign_refusal(_session(Card([(0x9A, RSA2048, SIGN)])), 0x9A, RSA2048, 0x6983)
    assert "holds no key yet" in text and "generate-key --slot 9A --algorithm RSA2048" in text


def test_6a86_with_a_readable_listing_names_the_missing_algorithm_and_a_signer():
    card = Card([(0x9C, ECCP256, SIGN)])
    text = piv_cmd._sign_refusal(_session(card), 0x9C, ECCP384, 0x6A86)
    assert text.startswith("slot 9C has no ECCP384 key object.")
    assert "pass --algorithm ECCP256" in text


def test_quickstart_points_at_create_key_object_with_the_profile_role():
    with pytest.raises(CryptnoxError) as exc:
        piv_cmd._plan_quickstart(
            _facts(key_object_present=False),
            _opts(include_preperso=False, cert_mode="none", new_object_roles="AUTHENTICATE"),
        )
    assert "create-key-object --slot 9A --algorithm ECCP256 --role AUTHENTICATE" in str(exc.value)
    assert "generate-key" not in str(exc.value)


def test_quickstart_refuses_an_unsigning_object_before_suggesting_it():
    with pytest.raises(CryptnoxError, match="would create"):
        piv_cmd._plan_quickstart(
            _facts(key_object_present=False),
            _opts(include_preperso=False, new_object_can_sign=False),
        )


def test_quickstart_finalized_refusal_comes_first():
    facts = _facts(key_object_present=False, applet_secured=True)
    with pytest.raises(CryptnoxError, match="finalized"):
        piv_cmd._plan_quickstart(facts, _opts(include_preperso=False))


def test_quickstart_replaces_the_certificate_of_a_key_that_cannot_sign():
    facts = _facts(other_cert="ECCP256", other_cert_replaceable=True, key_object_can_sign=True)
    steps = {s.step: s for s in piv_cmd._plan_quickstart(facts, _opts())}
    assert steps["generate-key"].run and steps["certificate"].run
    assert steps["certificate"].reason == "replaces the slot's ECCP256 certificate"


@pytest.mark.parametrize(
    ("other", "text"), [("RSA2048", "--algorithm RSA2048"), ("unrecognised", "cannot match")]
)
def test_quickstart_refuses_to_replace_a_certificate_it_cannot_account_for(other, text):
    facts = _facts(other_cert=other, key_object_can_sign=True)
    with pytest.raises(CryptnoxError, match=text):
        piv_cmd._plan_quickstart(facts, _opts())
    steps = {s.step: s for s in piv_cmd._plan_quickstart(facts, _opts(cert_mode="none"))}
    assert steps["generate-key"].run and not steps["certificate"].run


def test_quickstart_never_creates_an_object_and_skips_its_key():
    facts = _facts(key_object_present=False, other_cert="ECCP256", other_cert_replaceable=True)
    steps = {s.step: s for s in piv_cmd._plan_quickstart(facts, _opts(cert_mode="none"))}
    assert steps["create-key-object"].run and steps["generate-key"].run


def test_missing_structure_advice_names_the_chosen_profile():
    facts = _facts(structure_present=False, key_object_present=False)
    with pytest.raises(CryptnoxError, match="load-config --profile ssh"):
        piv_cmd._plan_quickstart(facts, _opts(include_preperso=False, profile_name="ssh"))


def test_unsigning_role_advice_offers_the_signing_role():
    with pytest.raises(CryptnoxError, match="use --role SIGN\\+AUTHENTICATE"):
        piv_cmd._plan_quickstart(
            _facts(key_object_present=False),
            _opts(
                include_preperso=False,
                cert_mode="none",
                new_object_can_sign=False,
                new_object_roles="AUTHENTICATE",
            ),
        )


def test_rsa_refusal_on_a_blank_card_lays_down_a_structure_first(monkeypatch):
    blank = _facts(structure_present=False, key_object_present=False)
    result = _quickstart(monkeypatch, blank, "--slot", "9A", "--algorithm", "RSA2048", "--dry-run")
    assert result.exit_code == 2
    assert "load-config" in result.output and "create-key-object" not in result.output


def test_dry_run_shows_the_profile_and_new_object_warnings(monkeypatch):
    blank = _facts(structure_present=False, key_object_present=False)
    result = _quickstart(
        monkeypatch,
        blank,
        "--slot",
        "9A",
        "--cert-mode",
        "none",
        "--include-preperso",
        "--algorithm",
        "ECCP384",
        "--dry-run",
    )
    assert result.exit_code == 0, result.output
    assert "can authenticate but not sign" in result.stderr
    assert "cannot sign; it is permanent" in result.stderr


class _RecordingAdmin(_Admin):
    def __init__(self, *, secured: bool = False) -> None:
        super().__init__(0x9000)
        self.card = _session(Card([], secured=secured))
        self.sent = 0

    def send(self, apdu, *, context=None):
        self.sent += 1
        return super().send(apdu, context=context)


@pytest.mark.parametrize(
    ("yes", "confirmed", "answer", "sent"),
    [
        (False, False, False, 0),
        (False, False, True, 1),
        (True, False, False, 1),
        (False, True, False, 1),
    ],
)
def test_create_key_object_fallback_confirms_a_9a_key_that_cannot_sign(
    monkeypatch, yes, confirmed, answer, sent
):
    import contextlib

    import click

    monkeypatch.setattr(click, "confirm", lambda *a, **k: answer)
    adm = _RecordingAdmin()
    app = piv_cmd.AppContext(yes=yes)
    with contextlib.suppress(click.Abort):
        piv_cmd._create_key_object(
            app, adm, object(), 0x9A, ECCP384, False, "9A", confirmed=confirmed
        )
    assert adm.sent == sent


def test_certificate_mechanism_reads_the_key_type():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    assert piv_cmd._certificate_mechanism(cert.public_bytes(serialization.Encoding.DER)) == ECCP256
    assert piv_cmd._certificate_mechanism(b"not a certificate") is None


@pytest.mark.parametrize(("algorithm", "warned"), [("RSA2048", False), ("ECCP256", True)])
def test_generate_key_warns_only_for_the_certified_key(monkeypatch, algorithm, warned):
    """9A's certificate is for its ECC key; generating the RSA key leaves that key alone."""
    import contextlib
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.asymmetric import ec

    @contextlib.contextmanager
    def no_card(self):
        yield object()

    monkeypatch.setattr(piv_cmd.AppContext, "open_session", no_card)
    monkeypatch.setattr(piv_cmd, "_select", lambda s: object())
    monkeypatch.setattr(piv_cmd, "_read_cert_der", lambda piv, name: b"cert")
    monkeypatch.setattr(piv_cmd, "_certificate_mechanism", lambda der: ECCP256)
    public = ec.generate_private_key(ec.SECP256R1()).public_key()
    monkeypatch.setattr(
        piv_cmd,
        "_generate_key_on_card",
        lambda *a, **k: SimpleNamespace(
            public_key=public, path="admin-channel", management_key_auth=False
        ),
    )
    result = run(
        ["piv", "perso", "generate-key", "--slot", "9A", "--algorithm", algorithm]
        + ["--default-keys"],
        input="n\n",
    )
    assert ("DESTROYS" in result.output) is warned
    assert (result.exit_code != 0) is warned
    assert ("which this leaves alone" in result.output) is not warned


def test_quickstart_advice_carries_the_profile_role(monkeypatch):
    facts = _facts(key_object_present=False)
    result = _quickstart(monkeypatch, facts, "--slot", "9A", "--cert-mode", "none", "--dry-run")
    assert result.exit_code != 0
    assert "--role AUTHENTICATE" in json.loads(result.stdout)["message"]


def test_smoke_test_on_an_empty_key_object(monkeypatch):
    wire_session(monkeypatch, Card([(0x9C, ECCP256, SIGN)], sign_sw=0x6983))
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "123456")
    result = run(["--json", "piv", "perso", "smoke-test", "--slot", "9C"])
    message = json.loads(result.stdout)["message"]
    assert "holds no key yet" in message and "blocked" not in message


def test_create_key_object_fallback_refuses_a_finalized_applet_before_asking(monkeypatch):
    import click

    def no_prompt(*a, **k):
        raise AssertionError("asked before checking the applet state")

    monkeypatch.setattr(click, "confirm", no_prompt)
    adm = _RecordingAdmin(secured=True)
    with pytest.raises(CryptnoxError, match="finalized"):
        piv_cmd._create_key_object(piv_cmd.AppContext(), adm, object(), 0x9A, ECCP384, False, "9A")
    assert adm.sent == 0


# -------------------------------------------------------------- round four --- #
def test_6983_on_a_key_that_cannot_sign_names_the_role_first():
    card = Card([(0x9A, ECCP256, AUTH)])
    text = piv_cmd._sign_refusal(_session(card), 0x9A, ECCP256, 0x6983)
    assert "has the role AUTHENTICATE" in text and "holds no key yet" not in text


@pytest.mark.parametrize(
    ("rsa_crt", "suffix"), [(False, "SIGN+AUTHENTICATE`"), (True, "--rsa-crt`")]
)
def test_fallback_advice_is_a_complete_command(monkeypatch, capsys, rsa_crt, suffix):
    import click

    monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
    with pytest.raises(click.Abort):
        piv_cmd._create_key_object(
            piv_cmd.AppContext(), _RecordingAdmin(), object(), 0x9A, RSA2048, rsa_crt, "9A"
        )
    out = " ".join(capsys.readouterr().out.split())
    assert "create-key-object --slot 9A --algorithm RSA2048 --role SIGN+AUTHENTICATE" in out
    assert suffix in out


def test_an_unloadable_certificate_key_is_unrecognised(monkeypatch):
    from types import SimpleNamespace

    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm

    def unsupported():
        raise UnsupportedAlgorithm("curve not supported")

    monkeypatch.setattr(
        x509, "load_der_x509_certificate", lambda der: SimpleNamespace(public_key=unsupported)
    )
    assert piv_cmd._certificate_mechanism(b"der") is None


@pytest.mark.parametrize(
    ("facts", "warning"),
    [
        (
            _facts(other_cert="ECCP256", other_cert_replaceable=True),
            "replaces the ECCP256 certificate",
        ),
        (_facts(listing_withheld=True), "withholds its key listing"),
    ],
)
def test_dry_run_warns_about_what_the_certificate_step_cannot_check(monkeypatch, facts, warning):
    result = _quickstart(monkeypatch, facts, "--slot", "9C", "--dry-run")
    assert result.exit_code == 0, result.output
    assert warning in " ".join(result.stderr.split())


def test_template_falls_back_within_the_key_family():
    ms_logon = prof.builtin("ms-logon")
    for mech in (0x05, 0x16):
        _, _, role, attrs = piv_cmd._key_template(0x9A, mech, ms_logon)
        assert role == SIGN | AUTH and attrs & pp.ATTR_RSA_CRT


def test_create_key_object_warns_about_a_9a_role_that_cannot_sign(monkeypatch, created):
    wire_session(monkeypatch, ProbeCard(0x6A86))
    result = run(
        ["--yes", "piv", "perso", "create-key-object", "--slot", "9A", "--algorithm", "ECCP384"]
        + ["--role", "AUTHENTICATE", "--default-keys"]
    )
    assert result.exit_code == 0, result.output
    assert "cannot sign" in result.output
