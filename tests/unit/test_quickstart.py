"""Quickstart planner: which steps run for each starting card state."""

import pytest

from cryptnox_id_cli.cli.commands.piv import (
    CardFacts,
    PlannedStep,
    QuickstartOptions,
    _apply_pin_truth,
    _pin_truth,
    _plan_quickstart,
)
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError

OPTS = QuickstartOptions(slot=0x9C, mechanism=0x11, cert_mode="self-signed", include_preperso=False)


def _facts(**overrides) -> CardFacts:
    base = {
        "pin_configured": False,
        "puk_configured": False,
        "structure_present": True,
        "key_object_present": True,
        "cert_present": False,
        "chuid_present": False,
        "ccc_present": False,
    }
    base.update(overrides)
    return CardFacts(**base)


def _runs(steps) -> list[str]:
    return [s.step for s in steps if s.run]


BLANK = {"structure_present": False, "key_object_present": False}


def test_structure_missing_without_flag_is_a_hard_error():
    with pytest.raises(CryptnoxError, match="factory piv preperso load-config"):
        _plan_quickstart(_facts(**BLANK), OPTS)


def test_structure_missing_with_flag_runs_everything():
    opts = QuickstartOptions(0x9C, 0x11, "self-signed", include_preperso=True)
    steps = _plan_quickstart(_facts(**BLANK), opts)
    assert _runs(steps) == [
        "preperso-load-config",
        "set-pin",
        "set-puk",
        "generate-key",
        "certificate",
        "write-chuid",
        "write-ccc",
        "smoke-test",
    ]
    assert {s.step: s.reason for s in steps}["create-key-object"] == "provided by the profile"


def test_structure_missing_and_profile_without_the_object_creates_it_after_load_config():
    opts = QuickstartOptions(
        0x9A, 0x07, "none", include_preperso=True, profile_provides_key_object=False
    )
    steps = _plan_quickstart(_facts(**BLANK), opts)
    assert _runs(steps)[:2] == ["preperso-load-config", "create-key-object"]


def test_object_missing_in_an_existing_structure_points_at_create_key_object():
    """The 6E27 loop: a structure can only grow, so load-config must never be re-run
    over it. Without the flag the error names the targeted fix."""
    with pytest.raises(CryptnoxError, match="--create-key-object") as info:
        _plan_quickstart(_facts(key_object_present=False), OPTS)
    assert "load-config" not in str(info.value).split("--create-key-object")[0]


def test_object_missing_in_an_existing_structure_creates_only_the_object():
    opts = QuickstartOptions(0x9A, 0x07, "none", include_preperso=True)
    steps = _plan_quickstart(_facts(key_object_present=False), opts)
    runs = _runs(steps)
    assert runs[0] == "create-key-object"
    assert "preperso-load-config" not in runs
    assert {s.step: s.reason for s in steps}["preperso-load-config"] == "structure present"


def test_preperso_skipped_when_structure_present():
    steps = _plan_quickstart(_facts(), OPTS)
    assert _runs(steps) == [
        "set-pin",
        "set-puk",
        "generate-key",
        "certificate",
        "write-chuid",
        "write-ccc",
        "smoke-test",
    ]
    assert steps[0].reason == "structure present"


def test_partially_personalized_runs_only_the_gaps():
    facts = _facts(pin_configured=True, chuid_present=True)
    steps = _plan_quickstart(facts, OPTS)
    assert _runs(steps) == ["set-puk", "generate-key", "certificate", "write-ccc", "smoke-test"]
    by_name = {s.step: s for s in steps}
    assert by_name["set-pin"].reason == "PIN already set"
    assert by_name["write-chuid"].reason == "already present"


def test_fully_personalized_runs_smoke_only():
    facts = _facts(
        pin_configured=True,
        puk_configured=True,
        cert_present=True,
        chuid_present=True,
        ccc_present=True,
    )
    steps = _plan_quickstart(facts, OPTS)
    assert _runs(steps) == ["smoke-test"]
    assert {s.step: s.reason for s in steps}["generate-key"] == (
        "certificate present - keeping the existing key"
    )


def test_existing_certificate_protects_the_key():
    steps = _plan_quickstart(_facts(cert_present=True), OPTS)
    runs = _runs(steps)
    assert "generate-key" not in runs and "certificate" not in runs


def test_cert_mode_none_skips_certificate_but_generates():
    opts = QuickstartOptions(0x9C, 0x11, "none", include_preperso=False)
    steps = _plan_quickstart(_facts(), opts)
    runs = _runs(steps)
    assert "certificate" not in runs and "generate-key" in runs
    assert {s.step: s.reason for s in steps}["certificate"] == "--cert-mode none"


# ----------------------------------------------------------- CLI wiring ---- #
def _invoke(args, monkeypatch=None, facts=None, state="PivPrePersonalized"):
    from click.testing import CliRunner

    from cryptnox_id_cli.cli.commands import piv as piv_cmd
    from cryptnox_id_cli.cli.context import AppContext

    if monkeypatch is not None:

        class _DummySession:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                pass

            def transmit(self, *a, **k):  # pragma: no cover - guard
                raise AssertionError("dry-run must not touch the card")

        monkeypatch.setattr(AppContext, "open_session", lambda self: _DummySession())
        monkeypatch.setattr(
            piv_cmd, "_collect_quickstart_facts", lambda session, ref, mech: (facts, state)
        )
    return CliRunner().invoke(piv_cmd.command, args, obj=AppContext(json=True))


def test_quickstart_dry_run_sends_nothing(monkeypatch):
    result = _invoke(["quickstart", "--dry-run"], monkeypatch, _facts())
    assert result.exit_code == 0, result.output
    assert "would-run" in result.output and "smoke-test" in result.output


def test_quickstart_dry_run_structure_missing_errors(monkeypatch):
    result = _invoke(["quickstart", "--dry-run"], monkeypatch, _facts(**BLANK))
    assert result.exit_code != 0
    assert isinstance(result.exception, CryptnoxError)


def _invoke_capturing_mechanism(args, monkeypatch, facts=None, state="PivPrePersonalized"):
    """Like _invoke, but records the (ref, mechanism) quickstart actually resolved, so a
    default can be asserted on directly rather than inferred from rendered output."""
    from click.testing import CliRunner

    from cryptnox_id_cli.cli.commands import piv as piv_cmd
    from cryptnox_id_cli.cli.context import AppContext

    seen: dict = {}

    class _DummySession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def transmit(self, *a, **k):  # pragma: no cover - guard
            raise AssertionError("dry-run must not touch the card")

    def _spy(session, ref, mech):
        seen["ref"], seen["mech"] = ref, mech
        return facts, state

    monkeypatch.setattr(AppContext, "open_session", lambda self: _DummySession())
    monkeypatch.setattr(piv_cmd, "_collect_quickstart_facts", _spy)
    result = CliRunner().invoke(piv_cmd.command, args, obj=AppContext(json=True))
    return result, seen


def test_quickstart_defaults_to_rsa_on_ms_logon_9a(monkeypatch):
    """The default stays ECC everywhere except the Windows shape (ms-logon + 9A): the
    Windows inbox minidriver does not enumerate EC keys, so an ECC card there is
    useless for its purpose. RSA-2048 is the default there, and the run says so."""
    from cryptnox_id_cli.applets.piv import perso as perso_mod

    result, seen = _invoke_capturing_mechanism(
        ["quickstart", "--profile", "ms-logon", "--slot", "9A", "--dry-run"],
        monkeypatch,
        _facts(),
    )
    assert result.exit_code == 0, result.output
    assert seen["mech"] == perso_mod.ALGORITHMS["RSA2048"]
    assert "RSA2048" in result.output


def test_quickstart_explicit_ecc_on_ms_logon_9a_stays_quiet(monkeypatch):
    """An operator who explicitly chose ECC on the Windows shape made a decision;
    honor it without the warning."""
    from cryptnox_id_cli.applets.piv import perso as perso_mod

    result, seen = _invoke_capturing_mechanism(
        [
            "quickstart",
            "--profile",
            "ms-logon",
            "--slot",
            "9A",
            "--algorithm",
            "ECCP256",
            "--dry-run",
        ],
        monkeypatch,
        _facts(),
    )
    assert result.exit_code == 0, result.output
    assert seen["mech"] == perso_mod.ALGORITHMS["ECCP256"]
    assert "RSA2048" not in result.output


def test_quickstart_keeps_the_ecc_default_everywhere_else(monkeypatch):
    """The RSA default is scoped to ms-logon + 9A; no other invocation changes behaviour."""
    from cryptnox_id_cli.applets.piv import perso as perso_mod

    _, seen = _invoke_capturing_mechanism(["quickstart", "--dry-run"], monkeypatch, _facts())
    assert seen["mech"] == perso_mod.ALGORITHMS["ECCP256"]

    # ms-logon but a different slot: 9C has no RSA key object, so it must stay ECC.
    _, seen = _invoke_capturing_mechanism(
        ["quickstart", "--profile", "ms-logon", "--slot", "9C", "--dry-run"],
        monkeypatch,
        _facts(),
    )
    assert seen["mech"] == perso_mod.ALGORITHMS["ECCP256"]


def test_quickstart_accepts_explicit_rsa_for_ms_logon_9a(monkeypatch):
    result, _ = _invoke_capturing_mechanism(
        [
            "quickstart",
            "--profile",
            "ms-logon",
            "--slot",
            "9A",
            "--algorithm",
            "RSA2048",
            "--dry-run",
        ],
        monkeypatch,
        _facts(),
    )
    assert result.exit_code == 0, result.output


def test_quickstart_rejects_rsa_outside_the_ms_logon_9a_shape():
    """Only ms-logon's 9A has an RSA key object, so anything else would fail on the card.
    Fail early and say which combination works rather than letting it get that far.
    The shape is profile AND slot: each single-condition variant must reject too, or a
    regression to checking only one of them would slip through."""
    # both wrong (default profile, 9C)
    result = _invoke(["quickstart", "--slot", "9C", "--algorithm", "RSA2048"])
    assert result.exit_code == 2
    assert "ms-logon" in result.output
    # right slot, wrong profile
    result = _invoke(["quickstart", "--slot", "9A", "--algorithm", "RSA2048"])
    assert result.exit_code == 2
    assert "ms-logon" in result.output
    # right profile, wrong slot (ms-logon has no RSA object on 9C)
    result = _invoke(
        ["quickstart", "--profile", "ms-logon", "--slot", "9C", "--algorithm", "RSA2048"]
    )
    assert result.exit_code == 2
    assert "ms-logon" in result.output


def test_quickstart_rsa_without_the_key_object_points_at_create_key_object(monkeypatch):
    from cryptnox_id_cli.applets.piv import perso as perso_mod

    result, seen = _invoke_capturing_mechanism(
        [
            "quickstart",
            "--profile",
            "ms-logon",
            "--slot",
            "9A",
            "--algorithm",
            "RSA2048",
            "--dry-run",
        ],
        monkeypatch,
        _facts(key_object_present=False),
    )
    assert result.exit_code != 0
    assert isinstance(result.exception, CryptnoxError)
    assert "--create-key-object" in str(result.exception)
    # Pin that it was the RSA (slot, mechanism) object that was looked up and found missing,
    # otherwise this test is indistinguishable from the plain ECC structure-missing one.
    assert seen["mech"] == perso_mod.ALGORITHMS["RSA2048"]


# ------------------------------------------------- facts from the key-object listing --- #
SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA000000308000010000100"
    "79074F05A000000308"
    "500B4F70656E46495053323031"
    "5F5049687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F"
    "5370656369616C5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
KEY_9A_ECC = "53158B019A8C01018D010091019B8E01118F0101900110"
VERIFIER_PIN = "53248B01808C013F8D01008E01068F010890010691010092010093010094010095010096015A"


def _ext(ident: int, index: int = 0) -> str:
    return f"00CB3F{index:02X}055C032F{ident:04X}00"


def _session(mock_connection, exchanges: dict[str, str]):
    from cryptnox_id_cli.transport.pcsc import CardSession

    return CardSession(mock_connection("3B00", {SELECT_PIV: f"{APT}|9000", **exchanges}, []))


def test_facts_distinguish_a_missing_object_from_a_missing_structure(mock_connection):
    """A 9A ECC object and a PIN verifier exist; RSA-2048 on 9A does not. That is
    'structure present, object missing', which must not be read as 'no structure'."""
    from cryptnox_id_cli.applets.piv import inventory as inv
    from cryptnox_id_cli.cli.commands.piv import _collect_quickstart_facts

    exchanges = {
        _ext(inv.ID_KEY): f"{KEY_9A_ECC}|9000",
        _ext(inv.ID_VERIFIER): f"{VERIFIER_PIN}|9000",
    }
    facts, _ = _collect_quickstart_facts(_session(mock_connection, exchanges), 0x9A, 0x07)
    assert facts.structure_present is True
    assert facts.key_object_present is False
    facts, _ = _collect_quickstart_facts(_session(mock_connection, exchanges), 0x9A, 0x11)
    assert facts.key_object_present is True


def test_facts_without_any_listed_object_mean_no_structure(mock_connection):
    from cryptnox_id_cli.cli.commands.piv import _collect_quickstart_facts

    facts, _ = _collect_quickstart_facts(_session(mock_connection, {}), 0x9C, 0x11)
    assert facts.structure_present is False
    assert facts.key_object_present is False


def test_facts_fall_back_to_the_probe_when_the_listing_is_withheld(mock_connection):
    """restrict-enumeration set: the applet answers 6986, and the one (slot, mechanism)
    probe decides again, as it did before the listing existed."""
    from cryptnox_id_cli.applets.piv import inventory as inv
    from cryptnox_id_cli.applets.piv import keyimport
    from cryptnox_id_cli.cli.commands.piv import _collect_quickstart_facts

    probe = keyimport.probe_apdu(0x9C, 0x11).to_bytes().hex().upper()
    withheld = {_ext(inv.ID_KEY): "|6986", _ext(inv.ID_VERIFIER): "|6986"}
    facts, _ = _collect_quickstart_facts(
        _session(mock_connection, {**withheld, probe: "|6982"}), 0x9C, 0x11
    )
    assert facts.key_object_present is True and facts.structure_present is True
    facts, _ = _collect_quickstart_facts(
        _session(mock_connection, {**withheld, probe: "|6A86"}), 0x9C, 0x11
    )
    assert facts.key_object_present is False and facts.structure_present is False


def test_quickstart_csr_requires_csr_out():
    result = _invoke(["quickstart", "--cert-mode", "csr"])
    assert result.exit_code == 2
    assert "--csr-out" in result.output


def test_quickstart_cert_mode_rejects_non_sign_capable_slots():
    result = _invoke(["quickstart", "--slot", "9D"])
    assert result.exit_code == 2
    assert "ms-logon" in result.output


def test_quickstart_slot_9a_accepted_for_ms_logon_cards(monkeypatch):
    # 9A is allowed (the ms-logon profile makes it SIGN-capable); dry-run plans normally.
    result = _invoke(
        ["quickstart", "--slot", "9A", "--profile", "ms-logon", "--dry-run"],
        monkeypatch,
        _facts(),
    )
    assert result.exit_code == 0, result.output
    assert "would-run" in result.output


def test_quickstart_unknown_profile_is_an_error():
    result = _invoke(["quickstart", "--profile", "nope"])
    assert result.exit_code != 0
    assert result.exception is not None  # ProfileError via the error funnel


# ------------------------------------------------- pre-flight PIN truth check --- #
# Found on hardware 2026-08-21: after a manual pre-personalization the PIN verifier
# exists with no value, the status probe (empty VERIFY) answers 63C6 as if the PIN
# were set, quickstart skipped set-pin, and the certificate step then failed with
# 6A88. The pre-flight check does one real VERIFY to establish the truth; it costs
# no extra retries because every quickstart path verifies the PIN at least once.


class _VerifyingPiv:
    def __init__(self, sw1, sw2):
        self._resp = Response(b"", sw1, sw2)

    def verify_pin(self, pin):
        return self._resp


def test_pin_truth_match():
    assert _pin_truth(_VerifyingPiv(0x90, 0x00), b"123456") == ("match", None)


def test_pin_truth_empty_verifier():
    assert _pin_truth(_VerifyingPiv(0x6A, 0x88), b"123456") == ("empty", None)


def test_pin_truth_mismatch_reports_remaining_tries():
    assert _pin_truth(_VerifyingPiv(0x63, 0xC5), b"999999") == ("mismatch", 5)


def test_pin_truth_unexpected_sw_raises():
    with pytest.raises(StatusWordError):
        _pin_truth(_VerifyingPiv(0x69, 0x85), b"123456")


def _skip_plan():
    return [
        PlannedStep("preperso-load-config", False, "structure present"),
        PlannedStep("set-pin", False, "PIN already set"),
        PlannedStep("set-puk", False, "PUK already set"),
        PlannedStep("generate-key", True),
        PlannedStep("smoke-test", True),
    ]


def test_apply_pin_truth_empty_flips_both_verifier_steps():
    steps = _apply_pin_truth(_skip_plan(), "empty")
    by = {s.step: s for s in steps}
    assert by["set-pin"].run and "no value" in (by["set-pin"].reason or "")
    assert by["set-puk"].run and "valueless" in (by["set-puk"].reason or "")
    assert by["generate-key"].run  # untouched
    assert not by["preperso-load-config"].run  # untouched


def test_apply_pin_truth_match_upgrades_the_reason_only():
    steps = _apply_pin_truth(_skip_plan(), "match")
    by = {s.step: s for s in steps}
    assert not by["set-pin"].run and by["set-pin"].reason == "PIN already set (verified)"
    assert not by["set-puk"].run  # PUK claim left alone when the PIN proved true


def test_apply_pin_truth_never_unflips_a_planned_step():
    planned = [PlannedStep("set-pin", True), PlannedStep("set-puk", True)]
    for verdict in ("match", "empty"):
        assert all(s.run for s in _apply_pin_truth(planned, verdict))


def test_quickstart_mismatch_aborts_before_any_write(monkeypatch):
    from click.testing import CliRunner

    from cryptnox_id_cli.cli.commands import piv as piv_cmd
    from cryptnox_id_cli.cli.context import AppContext

    class _DummySession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

    monkeypatch.setattr(AppContext, "open_session", lambda self: _DummySession())
    monkeypatch.setattr(
        piv_cmd,
        "_collect_quickstart_facts",
        lambda session, ref, mech: (_facts(pin_configured=True), "PivPartiallyPersonalized"),
    )
    monkeypatch.setattr(piv_cmd, "_pin_truth", lambda piv, pin: ("mismatch", 4))
    monkeypatch.setattr(piv_cmd, "_select", lambda session: object())
    monkeypatch.setattr(
        piv_cmd,
        "_set_verifier",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("write reached the card")),
    )
    monkeypatch.setenv("CRYPTNOX_PIV_PIN", "999999")
    result = CliRunner().invoke(
        piv_cmd.command,
        ["quickstart", "--default-keys"],
        obj=AppContext(json=True, yes=True),
    )
    assert result.exit_code != 0
    assert isinstance(result.exception, CryptnoxError)
    assert "does not match" in str(result.exception)
    assert "4 tries" in str(result.exception)
