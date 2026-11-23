"""Profiles for the PIV applet build with FIPS mode off. No card.

The applet enforces three bounds when a profile is loaded, and lifts them when it
is built with FIPS mode off: a PIN or PUK of at least 6, at most 15 retries, no PIN
over the contactless interface without secure messaging. A profile says which
build it is written for with ``fips_mode``; the built-in ones are for the
FIPS-mode build and must stay byte-identical.
"""

from __future__ import annotations

import json

import pytest
import yaml
from _cardfakes import run, wire_session

from cryptnox_id_cli.applets.piv import profiles
from cryptnox_id_cli.cli.commands import factory as factory_cmd
from cryptnox_id_cli.transport.apdu import Response

ATR = "3BD518FF81B1FE451FC38073C821106F"
SELECT_PIV = "00A404000BA00000030800001000010000"
APT = (
    "616F4F0BA00000030800001000010079074F05A000000308500B4F70656E464950533230315F5049"
    "687474703A2F2F6E766C707562732E6E6973742E676F762F6E697374707562732F5370656369616C"
    "5075626C69636174696F6E732F4E4953542E53502E3830302D37332D342E706466"
)
GET_STATUS = "00CB3F00055C032F475300"
STATUS_FIPS_OFF = "5318800107810100820100830100840100850100860100870100"
STATUS_FIPS = "53188001078101008201008301008401008501008601008701FF"

LOAD = ["factory", "piv", "preperso", "load-config"]


def off_profile(**pin) -> dict:
    """``cryptnox-default`` rewritten for the build with FIPS mode off."""
    data = profiles.builtin("cryptnox-default").to_dict()
    data["name"] = "short-pin"
    data["fips_mode"] = False
    data["pin"].update(pin or {"min": 4, "retries": 12})
    return data


def write(tmp_path, data: dict) -> str:
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# The model                                                                   #
# --------------------------------------------------------------------------- #
#: the one built-in profile written for the build with FIPS mode off
OFF_BUILTINS = {"ms-logon-nfc"}


def test_built_in_profiles_are_for_the_fips_mode_build_and_read_as_before():
    for name in sorted(set(profiles.builtin_names()) - OFF_BUILTINS):
        prof = profiles.builtin(name)
        assert prof.fips_mode is True
        assert "fips_mode" not in prof.to_dict()
        assert "fips_mode" not in prof.to_yaml()
        assert prof.fips_mode_note() is None
        assert prof.pin_bounds() == (6, 10)


def test_the_fips_mode_bounds_stand_and_point_at_the_other_build():
    data = off_profile(min=4, retries=12)
    data["fips_mode"] = True
    errors = profiles.from_dict(data).validate()
    assert any(
        e.startswith("PIN min_length 4 < minimum 6") and "fips_mode: false" in e for e in errors
    )
    assert any(
        e.startswith("PIN retries 12 out of range (max 10)") and "fips_mode: false" in e
        for e in errors
    )


def test_a_profile_for_the_build_with_fips_mode_off_may_use_its_bounds():
    prof = profiles.from_dict(off_profile(min=4, retries=15))
    assert prof.fips_mode is False
    assert prof.validate() == []
    assert prof.pin_bounds() == (4, 15)
    assert "FIPS mode off" in (prof.fips_mode_note() or "")


@pytest.mark.parametrize(
    ("pin", "fragment"),
    [
        ({"min": 3}, "PIN min_length 3 < minimum 4"),
        ({"retries": 16}, "PIN retries 16 out of range (max 15)"),
        ({"max": 17}, "PIN max_length 17 must be 8: "),
        ({"max": 16}, "PIN max_length 16 must be 8: "),
        ({"min": 4, "max": 7}, "PIN max_length 7 must be 8: "),
        ({"min": 9, "max": 8}, "PIN max_length < min_length"),
    ],
)
def test_the_other_build_has_bounds_too_and_no_hint_is_offered_past_them(pin, fragment):
    errors = profiles.from_dict(off_profile(**pin)).validate()
    assert any(e.startswith(fragment) for e in errors), errors


def test_below_both_builds_the_fips_mode_message_offers_no_hint():
    data = off_profile(min=3)
    data["fips_mode"] = True
    assert "PIN min_length 3 < minimum 6" in profiles.from_dict(data).validate()


def test_the_declaration_survives_a_yaml_round_trip():
    prof = profiles.from_dict(off_profile())
    text = prof.to_yaml()
    assert "fips_mode: false" in text
    again = profiles.from_yaml(text)
    assert again.fips_mode is False
    assert again.build_payload() == prof.build_payload()


@pytest.mark.parametrize("value", ["off", "no", 0, "false", None])
def test_the_declaration_must_be_a_boolean(value):
    data = off_profile()
    data["fips_mode"] = value
    with pytest.raises(profiles.ProfileError, match="fips_mode must be true or false"):
        profiles.from_dict(data)


def test_yaml_spellings_of_false_are_accepted():
    # YAML itself reads these as the boolean false; a quoted "off" stays a string.
    for spelling in ("false", "off", "no"):
        text = (
            profiles.from_dict(off_profile())
            .to_yaml()
            .replace("fips_mode: false", f"fips_mode: {spelling}")
        )
        assert profiles.from_yaml(text).fips_mode is False


def test_the_pin_verifier_carries_the_shorter_minimum_and_the_longer_counter():
    prof = profiles.from_dict(off_profile(min=4, retries=12))
    verifier = dict(prof.build_ops())["verifier PIN (80)"]
    assert bytes.fromhex("8E0104") in verifier  # minimum length 4
    assert bytes.fromhex("90010C") in verifier  # 12 retries over the contact interface
    # The PUK was not touched and keeps the FIPS-mode shape.
    assert bytes.fromhex("8E0108") in dict(prof.build_ops())["verifier PUK (81)"]


# --------------------------------------------------------------------------- #
# load-config                                                                 #
# --------------------------------------------------------------------------- #
class _FakeAdmin:
    """The admin channel double: every PUT DATA ADMIN is accepted and recorded."""

    opened = 0
    sent: list[str] = []

    def __init__(self, session) -> None:
        self.session = session

    def select(self) -> None:
        pass

    def open(self, keys, **kwargs) -> None:
        _FakeAdmin.opened += 1

    def send(self, apdu, *, context=None) -> Response:
        _FakeAdmin.sent.append(context or "")
        return Response(b"", 0x90, 0x00)


@pytest.fixture
def card(monkeypatch, mock_connection):
    def wire(status: str | None):
        exchanges = {SELECT_PIV: f"{APT}|9000"}
        if status is not None:
            exchanges[GET_STATUS] = f"{status}|9000"
        wire_session(monkeypatch, mock_connection(ATR, exchanges, []))
        _FakeAdmin.opened = 0
        _FakeAdmin.sent = []
        monkeypatch.setattr(factory_cmd, "PivAdmin", _FakeAdmin)

    return wire


def test_dry_run_says_which_build_the_profile_is_for(tmp_path, card):
    card(None)  # a card that does not report its build: the preview stands on its own
    path = write(tmp_path, off_profile())
    result = run(["--json", *LOAD, "--file", path, "--dry-run"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["fips_mode"] is False
    assert "written for the PIV applet build with FIPS mode off" in result.stderr

    built_in = run(["--json", *LOAD, "--profile", "cryptnox-default", "--dry-run"])
    assert json.loads(built_in.stdout)["fips_mode"] is True
    assert "FIPS mode off" not in built_in.stderr


def test_a_fips_mode_card_is_refused_before_anything_is_written(tmp_path, card):
    card(STATUS_FIPS)
    path = write(tmp_path, off_profile())
    result = run(["--json", "--yes", *LOAD, "--file", path, "--default-keys"])
    assert result.exit_code == 8
    error = json.loads(result.stdout)
    assert error["error"] == "profile_error"
    assert "this card carries the FIPS-mode build" in error["message"]
    assert "remote reset --fips-off" in error["message"]
    assert _FakeAdmin.opened == 0 and _FakeAdmin.sent == []


def test_a_dry_run_on_a_fips_mode_card_refuses_like_the_real_run(tmp_path, card):
    card(STATUS_FIPS)
    path = write(tmp_path, off_profile())
    result = run(["--json", *LOAD, "--file", path, "--dry-run"])
    assert result.exit_code == 8
    assert "this card carries the FIPS-mode build" in json.loads(result.stdout)["message"]
    assert _FakeAdmin.opened == 0


def test_a_dry_run_on_a_card_with_fips_mode_off_previews(tmp_path, card):
    card(STATUS_FIPS_OFF)
    path = write(tmp_path, off_profile())
    result = run(["--json", *LOAD, "--file", path, "--dry-run"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["dry_run"] is True
    assert _FakeAdmin.opened == 0


def test_a_card_with_fips_mode_off_takes_the_profile(tmp_path, card):
    card(STATUS_FIPS_OFF)
    path = write(tmp_path, off_profile())
    result = run(["--json", "--yes", *LOAD, "--file", path, "--default-keys"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["applied"] is True
    assert any("verifier PIN (80)" in label for label in _FakeAdmin.sent)
    assert _FakeAdmin.opened == len(_FakeAdmin.sent)  # one channel per operation


def test_a_card_that_does_not_report_its_build_is_left_to_the_applet(tmp_path, card):
    card(None)
    path = write(tmp_path, off_profile())
    result = run(["--json", "--yes", *LOAD, "--file", path, "--default-keys"])
    assert result.exit_code == 0, result.output
    assert _FakeAdmin.sent


def test_a_fips_mode_profile_goes_to_either_build_without_the_question(card):
    for status in (STATUS_FIPS, STATUS_FIPS_OFF):
        card(status)
        result = run(["--json", "--yes", *LOAD, "--profile", "cryptnox-default", "--default-keys"])
        assert result.exit_code == 0, result.output


def test_a_profile_past_the_fips_mode_bounds_without_the_declaration_is_a_profile_error(
    tmp_path,
):
    data = off_profile()
    del data["fips_mode"]
    result = run(["--json", *LOAD, "--file", write(tmp_path, data), "--dry-run"])
    assert result.exit_code == 8
    assert "fips_mode: false" in json.loads(result.stdout)["message"]


def test_inspect_defaults_lists_both_sets_of_bounds():
    result = run(["--json", "factory", "piv", "preperso", "inspect-defaults"])
    limits = json.loads(result.stdout)["pin_limits"]
    assert limits["min_length"] == 6 and limits["profile_retry_cap"] == 10
    assert limits["fips_mode_off"] == {"min_length": 4, "profile_retry_cap": 15}
    text = " ".join(run(["factory", "piv", "preperso", "inspect-defaults"]).output.split())
    assert "with FIPS mode off (profile key fips_mode: false): min length 4" in text
