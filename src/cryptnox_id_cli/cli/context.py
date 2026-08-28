"""The per-invocation application context shared by all commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TextIO

from cryptnox_id_cli import CLI_NAME
from cryptnox_id_cli.output.render import Output
from cryptnox_id_cli.secrets.redaction import Redactor
from cryptnox_id_cli.transport.pcsc import CardSession, RawConnection, connect, pick_reader


@dataclass
class AppContext:
    reader: str | None = None
    json: bool = False
    verbose: bool = False
    apdu_log_path: str | None = None
    dry_run: bool = False
    yes: bool = False
    timeout: int = 15
    no_color: bool = False
    elevated_result_out: str | None = None

    resolved_reader: str | None = field(default=None, init=False)
    out: Output = field(init=False)
    redactor: Redactor = field(init=False)
    _log_fh: TextIO | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.out = Output(
            json=self.json,
            no_color=self.no_color,
            verbose=self.verbose,
            result_path=self.elevated_result_out,
        )
        self.redactor = Redactor()

    def _trace(self, line: str) -> None:
        if self.verbose:
            self.out.err.print(f"[dim]apdu {line}[/dim]")

    def _ensure_log(self) -> TextIO | None:
        if self.apdu_log_path and self._log_fh is None:
            self._log_fh = open(self.apdu_log_path, "a", encoding="utf-8")  # noqa: SIM115
            self._log_fh.write(f"# {CLI_NAME} APDU transcript (secrets redacted)\n")
        return self._log_fh

    def make_session(self, conn: RawConnection, *, reader_name: str | None = None) -> CardSession:
        """Wrap an already-open connection in a CardSession with our redactor/log."""
        return CardSession(
            conn,
            redactor=self.redactor,
            apdu_log=self._ensure_log(),
            trace=self._trace,
            reader_name=reader_name,
        )

    def open_session(self) -> CardSession:
        """Connect to the resolved reader (Cryptnox/ACS-first) and return a CardSession."""
        name = pick_reader(self.reader)
        self.resolved_reader = name
        return self.make_session(connect(name), reader_name=name)

    def close(self) -> None:
        if self._log_fh is not None:
            try:
                self._log_fh.close()
            finally:
                self._log_fh = None
