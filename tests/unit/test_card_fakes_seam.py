"""The seam the card doubles hang on, and the boundary that keeps it honest.

Substituting the card happens in one of two places, and which one depends on how the
command module reached PC/SC:

* ``AppContext.open_session`` for the 63 call sites that go through it, and
* the command module's own namespace for the two that do ``from ... import connect``.

A command added later that imports the same way would slip past a fixture patched only
at ``open_session`` and reach a real reader in CI, so the boundary is asserted here
rather than left as a convention.
"""

import ast
import pathlib

import pytest
from _cardfakes import ResponseAdapter, run, wire_session
from test_scp03 import GP_KEY, FakeScp03Card

from cryptnox_id_cli.transport.scp03 import Scp03Keys

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "cryptnox_id_cli"

#: Modules allowed to bind PC/SC entry points into their own namespace. Everything else
#: must go through AppContext.open_session, or a fixture cannot substitute the card.
PCSC_IMPORTERS = {
    "cli/context.py",
    "cli/commands/doctor.py",
    "cli/commands/readers.py",
}
PCSC_NAMES = {"connect", "pick_reader", "reader_states", "PCSCConnection"}


def _modules_importing_pcsc_names() -> set[str]:
    found = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").endswith("transport.pcsc")
                and {a.name for a in node.names} & PCSC_NAMES
            ):
                found.add(path.relative_to(SRC).as_posix())
    return found


def test_only_known_modules_bind_pcsc_entry_points():
    assert _modules_importing_pcsc_names() == PCSC_IMPORTERS, (
        "A module started importing PC/SC entry points directly. Either route it through "
        "AppContext.open_session, or add it here and teach the fixtures to patch it - "
        "otherwise its tests will reach a real reader."
    )


def test_smartcard_is_imported_only_inside_the_transport_wrapper():
    """pyscard stays behind transport/pcsc.py, so substituting there is sufficient."""
    offenders = set()
    for path in SRC.rglob("*.py"):
        if path.relative_to(SRC).as_posix() == "transport/pcsc.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            mod = ""
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
            elif isinstance(node, ast.Import):
                mod = node.names[0].name
            if mod == "smartcard" or mod.startswith("smartcard."):
                offenders.add(path.relative_to(SRC).as_posix())
    assert offenders == set()


@pytest.fixture
def scp03_card(monkeypatch):
    """A real SCP03 responder behind connect(), reached through open_session.

    The point of the adapter: os.urandom is NOT patched. The host challenge is fresh on
    every run and the card derives its cryptogram from the one it receives, which is
    exactly what a recorded transcript cannot do.
    """
    card = FakeScp03Card(Scp03Keys.same(GP_KEY), bytes.fromhex("1122334455667788"))
    conn = ResponseAdapter(
        card,
        # The SCP double models the secure channel, not applet selection.
        answers={"00A404000BA00000030800001000010000": ([0x6F, 0x00], 0x90, 0x00)},
    )
    wire_session(monkeypatch, conn, reader_name="Fake Reader 00 00")
    return conn


def test_admin_authenticate_completes_a_real_mutual_authentication(scp03_card):
    result = run(["--json", "piv", "admin", "authenticate", "--default-keys"])
    assert result.exit_code == 0, result.output
    assert '"authenticated": true' in result.output
    assert "SCP03" in result.output


def test_the_channel_really_was_negotiated_not_stubbed(scp03_card):
    """Guards against a double that just answers 9000: the wire must show the handshake."""
    run(["--json", "piv", "admin", "authenticate", "--default-keys"])
    log = scp03_card.log
    assert any(c.startswith("8050") for c in log), "no INITIALIZE UPDATE"
    assert any(c.startswith("8482") for c in log), "no EXTERNAL AUTHENTICATE"
    # The self-test rides the open channel: CLA 0x04 marks a C-MAC/C-ENC wrapped command.
    assert any(c.startswith("04") for c in log), "nothing was sent over the open channel"


def test_a_fresh_host_challenge_is_used_each_run(scp03_card, monkeypatch):
    """The handshake is computed, not replayed, so two runs differ on the wire."""
    run(["--json", "piv", "admin", "authenticate", "--default-keys"])
    first = next(c for c in scp03_card.log if c.startswith("8050"))
    scp03_card.log.clear()
    run(["--json", "piv", "admin", "authenticate", "--default-keys"])
    second = next(c for c in scp03_card.log if c.startswith("8050"))
    assert first != second
