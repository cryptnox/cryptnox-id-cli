# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""``apdu select``, ``send`` and ``transcript`` through the session seam."""

from __future__ import annotations

import json

from _cardfakes import RecordingConn, ResponseAdapter, run, run_both_modes, wire_session

PIV_AID = "A000000308000010000100"
SELECT_PIV = "00A404000BA00000030800001000010000"


def test_select_sends_a_case_4_select_and_shows_the_answer(monkeypatch):
    conn = ResponseAdapter(
        RecordingConn(([], 0x6A, 0x82)), answers={SELECT_PIV: (b"\x61\x00", 0x90, 0x00)}
    )
    wire_session(monkeypatch, conn)
    as_json, human = run_both_modes(["apdu", "select", "--aid", PIV_AID])
    payload = json.loads(as_json.stdout)
    assert (payload["sw"], payload["data"]) == ("9000", "6100")
    assert conn.log == [SELECT_PIV, SELECT_PIV]
    assert "SW:   9000" in human.output and "Data: 6100" in human.output


def test_dry_run_select_and_send_send_nothing(monkeypatch):
    conn = RecordingConn()
    wire_session(monkeypatch, conn)
    select = run(["--json", "--dry-run", "apdu", "select", "--aid", PIV_AID])
    send = run(["--dry-run", "apdu", "send", "--hex", "80CA9F7F00"])
    assert select.exit_code == 0 and send.exit_code == 0, select.output + send.output
    assert SELECT_PIV in select.stdout
    assert "would send 80CA9F7F00" in send.output
    assert conn.frames == []


def test_transcript_replays_each_entry_and_tables_the_answers(monkeypatch, tmp_path):
    conn = ResponseAdapter(
        RecordingConn(([], 0x6A, 0x82)),
        answers={SELECT_PIV: (b"", 0x90, 0x00), "80CA9F7F00": (b"\x9f\x7f", 0x90, 0x00)},
    )
    wire_session(monkeypatch, conn)
    script = tmp_path / "t.json"
    script.write_text(json.dumps([SELECT_PIV, {"apdu": "80CA9F7F00"}, "00B0000000"]))
    as_json, human = run_both_modes(["apdu", "transcript", "--file", str(script)])
    results = json.loads(as_json.stdout)["results"]
    assert [r["sw"] for r in results] == ["9000", "9000", "6A82"]
    assert results[1]["data"] == "9F7F"
    rows = [
        line
        for line in human.output.splitlines()
        if "│" in line and line.split("│")[1].strip().isdigit()
    ]
    assert len(rows) == 3
    assert rows[2].split("│")[4].strip() == "-"
