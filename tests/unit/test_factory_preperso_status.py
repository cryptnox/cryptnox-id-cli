# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``factory piv preperso status``, ``init-config``, ``export-config`` and the load-config
dry run, against the SCP03 double with nothing in ``factory.py`` patched."""

from __future__ import annotations

import json

import pytest
import yaml
from _cardfakes import ResponseAdapter, run, run_both_modes, wire_session
from test_factory_preperso_commands import PivAdminCard

from cryptnox_id_cli.applets.piv import profiles
from cryptnox_id_cli.applets.piv.ssd import ISD_AID
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.transport.apdu import Response
from cryptnox_id_cli.transport.errors import TransportError

STATUS = ["factory", "piv", "preperso", "status"]
E0_KVN1_AES = bytes.fromhex("E012C00401018810C00402018810C00403018810")


class StatusCard(PivAdminCard):
    """Adds the 9B witness request and a selectable card manager with a key table."""

    def __init__(self, *, mgmt_sw=0x6985, isd=None, key_info_sw=0x9000, isd_raises=False, **kw):
        super().__init__(**kw)
        self.mgmt_sw, self.isd, self.key_info_sw = mgmt_sw, isd, key_info_sw
        self.isd_raises = isd_raises

    def transmit(self, apdu):
        raw = bytes(apdu)
        if raw[:2] == b"\x00\x87" and raw[3] == 0x9B:
            return Response(b"", self.mgmt_sw >> 8, self.mgmt_sw & 0xFF)
        if raw[:4] == b"\x00\xa4\x04\x00" and raw[5 : 5 + raw[4]] == ISD_AID:
            if self.isd_raises:
                raise TransportError("reader went away")
            return Response(b"", 0x90, 0x00) if self.isd is not None else Response(b"", 0x6A, 0x82)
        if raw[:4] == b"\x80\xca\x00\xe0":
            ok = self.key_info_sw == 0x9000
            return Response(self.isd if ok else b"", self.key_info_sw >> 8, self.key_info_sw & 0xFF)
        return super().transmit(raw)


def _status(monkeypatch, **kw):
    wire_session(monkeypatch, ResponseAdapter(StatusCard(**kw)))
    return run_both_modes(STATUS)


@pytest.mark.parametrize(
    ("mgmt_sw", "present", "value_set", "line"),
    [
        (0x6A86, False, None, "absent"),
        (0x6983, True, False, "AES-256, no value"),
        (0x6982, True, None, "AES-256, not accessible on this interface"),
        (0x6985, True, True, "AES-256, value set"),
    ],
    ids=["absent", "no-value", "not-here", "value-set"],
)
def test_status_reads_the_management_key_from_the_witness_request(
    monkeypatch, mgmt_sw, present, value_set, line
):
    as_json, human = _status(monkeypatch, mgmt_sw=mgmt_sw)
    assert as_json.exit_code == 0, as_json.output
    mgmt = json.loads(as_json.stdout)["management_key"]
    assert (mgmt["present"], mgmt["value_set"]) == (present, value_set)
    assert f"Management key (9B): {line}" in human.output


def test_status_on_a_pre_personalized_card_allows_both_steps(monkeypatch):
    as_json, human = _status(monkeypatch)
    payload = json.loads(as_json.stdout)
    assert payload["state"] == "PivPrePersonalized"
    assert payload["finalize_allowed"] and payload["load_config_allowed"]
    assert "Pre-perso load-config: allowed (no structure yet)" in human.output
    assert "Finalize: allowed" in human.output


def test_status_on_a_finalized_card_refuses_both_steps(monkeypatch):
    as_json, human = _status(monkeypatch, secured=True)
    payload = json.loads(as_json.stdout)
    assert payload["secured"] is True
    assert not payload["finalize_allowed"] and not payload["load_config_allowed"]
    assert "not allowed, structure is finalized" in human.output
    assert "not allowed, already finalized" in human.output


def test_status_without_a_piv_applet(monkeypatch):
    as_json, human = _status(monkeypatch, present=False)
    payload = json.loads(as_json.stdout)
    assert payload["management_key"] is None and not payload["finalize_allowed"]
    assert "Management key (9B): not determined" in human.output
    assert "Finalize: not allowed in state PivNotPresent" in human.output


@pytest.mark.parametrize(
    ("kw", "line", "scp"),
    [
        ({}, "not determined (no security domain selectable)", None),
        ({"isd_raises": True}, "not determined (no security domain selectable)", None),
        (
            {"isd": E0_KVN1_AES},
            "SCP03 via A000000151000000; key version(s) 1 (3 x AES 16 B)",
            "SCP03",
        ),
        (
            {"isd": b"", "key_info_sw": 0x6A88},
            "A000000151000000, key table withheld (SW=6A88)",
            None,
        ),
    ],
    ids=["none", "transport-error", "key-table", "withheld"],
)
def test_status_describes_the_admin_secure_channel(monkeypatch, kw, line, scp):
    as_json, human = _status(monkeypatch, **kw)
    assert as_json.exit_code == 0, as_json.output
    payload = json.loads(as_json.stdout)
    assert payload["scp_version"] == scp
    assert payload["scp03_available"] is ("isd" in kw)
    assert f"Admin secure channel: {line}" in " ".join(human.output.split())


def test_init_config_writes_a_loadable_profile(tmp_path):
    out = tmp_path / "profile.yaml"
    as_json, human = run_both_modes(
        ["factory", "piv", "preperso", "init-config", "--out", str(out)]
    )
    assert json.loads(as_json.stdout) == {"profile": "cryptnox-default", "out": str(out)}
    loaded = profiles.from_yaml(out.read_text(encoding="utf-8"))
    loaded.ensure_valid()
    assert loaded.build_payload() == profiles.builtin("cryptnox-default").build_payload()
    assert "Wrote profile 'cryptnox-default'" in human.output


def test_export_config_writes_an_observed_snapshot(monkeypatch, tmp_path):
    wire_session(monkeypatch, ResponseAdapter(StatusCard()))
    out = tmp_path / "snapshot.yaml"
    args = ["factory", "piv", "preperso", "export-config", "--out", str(out)]
    as_json, human = run_both_modes(args)
    assert as_json.exit_code == 0, as_json.output
    snapshot = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert snapshot["state"] == "PivPrePersonalized"
    assert "NOT a loadable profile" in snapshot["_note"]
    assert json.loads(as_json.stdout)["out"] == str(out)
    assert "Wrote observed state snapshot" in human.output


@pytest.mark.parametrize(
    "args",
    [[], ["--profile", "ssh", "--file", __file__]],
    ids=["neither", "both"],
)
def test_load_config_wants_exactly_one_source(args):
    result = run(["factory", "piv", "preperso", "load-config", *args])
    assert result.exit_code == 2
    assert "specify exactly one of --file or --profile" in result.output


@pytest.mark.parametrize("profile", ["ssh", "ms-logon-nfc"], ids=["fips", "fips-off"])
def test_load_config_dry_run_previews_without_a_reader(monkeypatch, profile):
    def no_reader(self):
        raise TransportError("no reader found")

    monkeypatch.setattr(AppContext, "open_session", no_reader)
    args = ["--json", "factory", "piv", "preperso", "load-config", "--dry-run"]
    result = run([*args, "--profile", profile])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True and payload["profile"] == profile
    assert payload["bulk_hex"] == profiles.builtin(profile).build_payload().hex().upper()
