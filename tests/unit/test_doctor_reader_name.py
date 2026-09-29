"""``doctor`` must tell the session which reader it is on.

``is_contactless_interface`` takes two independent signals: the reader name and the ATR.
A card that does not synthesise the PC/SC contactless ATR leaves the reader name as the
only evidence, so a session built without it gets diagnosed on the ATR alone and the
DESFire advice inverts - telling an operator already on a PICC interface to go and find
a contactless reader.

The detector-level tests in ``test_state_detector.py`` cannot catch that: they build
``CardSession`` themselves and pass ``reader_name`` explicitly, and the contactless case
there uses the composed ``3B 80 80 01 ...`` ATR, which satisfies the ATR signal on its
own. These drive the real command instead, patching PC/SC at the boundary.
"""

import json

from click.testing import CliRunner

from cryptnox_id_cli.cli.commands import doctor as doctor_cmd
from cryptnox_id_cli.cli.main import main as root
from cryptnox_id_cli.transport.pcsc import ReaderInfo

#: A contactless interface whose card answers with its own wired-style ATR (the D600's),
#: so the ATR signal stays silent and only the reader name says "contactless".
PICC_READER = "ACS ACR1552 1S CL Reader PICC 0"
CONTACT_READER = "ACS ACR39U ICC Reader 0"
WIRED_ATR = "3BD518FF8191FE1FC38073C821100A"


def _wire(monkeypatch, mock_connection, reader_name):
    """Substitute the three PC/SC names ``doctor`` imported, and nothing inside doctor.

    An empty exchange table answers everything 6A82, which is what makes the DESFire
    probe report "not selected" - the same shape test_state_detector.py relies on.
    """
    infos = [ReaderInfo(0, reader_name, True, bytes.fromhex(WIRED_ATR))]
    monkeypatch.setattr(doctor_cmd, "reader_states", lambda: infos)
    monkeypatch.setattr(doctor_cmd, "pick_reader", lambda preference: reader_name)
    monkeypatch.setattr(doctor_cmd, "connect", lambda name: mock_connection(WIRED_ATR, {}, []))


def _desfire_detail(result):
    payload = json.loads(result.output)
    return next(c for c in payload["checks"] if c["check"].startswith("DESFire"))["detail"]


def test_contactless_reader_is_not_told_to_get_a_contactless_reader(monkeypatch, mock_connection):
    _wire(monkeypatch, mock_connection, PICC_READER)
    detail = _desfire_detail(CliRunner().invoke(root, ["--json", "doctor"]))
    assert "re-present the card" in detail
    assert "needs a contactless reader" not in detail


def test_contact_reader_still_gets_the_contactless_advice(monkeypatch, mock_connection):
    """The other half of the fix: on a genuine contact interface the advice is correct
    and must not change."""
    _wire(monkeypatch, mock_connection, CONTACT_READER)
    detail = _desfire_detail(CliRunner().invoke(root, ["--json", "doctor"]))
    assert "needs a contactless reader" in detail


def test_session_carries_the_resolved_reader_name(monkeypatch, mock_connection):
    """The underlying contract, independent of how the detector currently reads it."""
    captured = {}
    _wire(monkeypatch, mock_connection, PICC_READER)
    real_make_session = doctor_cmd.AppContext.make_session

    def spy(self, conn, **kw):
        captured.update(kw)
        return real_make_session(self, conn, **kw)

    monkeypatch.setattr(doctor_cmd.AppContext, "make_session", spy)
    CliRunner().invoke(root, ["--json", "doctor"])
    assert captured.get("reader_name") == PICC_READER
