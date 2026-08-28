"""Shared test fixtures: a mock card transport driven by recorded transcripts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptnox_id_cli.transport.errors import CardAccessDeniedError
from cryptnox_id_cli.transport.pcsc import CardSession


class MockConnection:
    """A RawConnection backed by a recorded transcript (secrets already scrubbed).

    ``exchanges`` maps an uppercase command-APDU hex to ``"<dataHex>|<swHex>"``.
    Unknown commands return 6A82. AIDs in ``deny`` raise CardAccessDeniedError to
    simulate the Windows FIDO block.
    """

    def __init__(self, atr: str, exchanges: dict[str, str], deny: list[str]) -> None:
        self._atr = bytes.fromhex(atr)
        self._exchanges = {k.upper(): v for k, v in exchanges.items()}
        self._deny = {d.upper() for d in deny}

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        key = bytes(apdu).hex().upper()
        if key in self._deny:
            raise CardAccessDeniedError("simulated SCARD_E_NO_ACCESS", hresult=0x80100027)
        spec = self._exchanges.get(key)
        if spec is None:
            return [], 0x6A, 0x82
        data_hex, sw_hex = spec.split("|")
        data = list(bytes.fromhex(data_hex)) if data_hex else []
        sw = bytes.fromhex(sw_hex)
        return data, sw[0], sw[1]

    def get_atr(self) -> bytes:
        return self._atr

    def disconnect(self) -> None:
        pass


def load_transcript(name: str) -> dict:
    path = Path(__file__).parent / "transcripts" / name
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def mock_connection() -> type[MockConnection]:
    """The MockConnection class, reachable without importing `tests.conftest` -
    that import only resolves when the repo root happens to be on sys.path
    (python -m pytest), not under the bare `pytest` entry point CI uses."""
    return MockConnection


@pytest.fixture
def acs_transcript() -> dict:
    return load_transcript("acs_card.json")


@pytest.fixture
def acs_session(acs_transcript: dict) -> CardSession:
    conn = MockConnection(
        acs_transcript["atr"], acs_transcript["exchanges"], acs_transcript.get("deny", [])
    )
    return CardSession(conn)
