# SPDX-FileCopyrightText: 2026 Cryptnox SA
# SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Commercial

"""Windows elevation, driven on any OS.

``is_windows`` reads ``sys.platform`` at call time and the Win32 calls go through
``ctypes.windll``, which is only an attribute lookup; both are substituted here, so
the real code runs, including the SHELLEXECUTEINFOW it builds.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cryptnox_id_cli.transport import elevation


class FakeWin32:
    """shell32/kernel32 as ``relaunch_elevated`` uses them; records what it was handed."""

    HANDLE = 0x2A

    def __init__(self, *, admin=1, started=True, exit_code=0):
        self.admin = admin
        self.started = started
        self.exit_code = exit_code
        self.sei = None
        self.calls: list[tuple] = []
        self.shell32 = SimpleNamespace(
            IsUserAnAdmin=lambda: self.admin, ShellExecuteExW=self._shell_execute
        )
        self.kernel32 = SimpleNamespace(
            WaitForSingleObject=lambda h, ms: self.calls.append(("wait", h, ms)),
            GetExitCodeProcess=self._exit_code,
            CloseHandle=lambda h: self.calls.append(("close", h)),
        )

    def _shell_execute(self, ref):
        self.sei = ref._obj
        if not self.started:
            return 0
        self.sei.hProcess = self.HANDLE
        return 1

    def _exit_code(self, handle, ref):
        self.calls.append(("exit_code", handle))
        ref._obj.value = self.exit_code
        return 1


@pytest.fixture
def windows(monkeypatch):
    def _install(win32=None):
        monkeypatch.setattr(sys, "platform", "win32")
        if win32 is not None:
            monkeypatch.setattr(ctypes, "windll", win32, raising=False)
        return win32

    return _install


@pytest.mark.parametrize(("admin", "expected"), [(1, True), (0, False)])
def test_is_elevated_on_windows_asks_shell32(windows, admin, expected):
    windows(FakeWin32(admin=admin))
    assert elevation.is_elevated() is expected


def test_is_elevated_on_windows_is_unknown_when_shell32_is_unavailable(windows, monkeypatch):
    windows()
    monkeypatch.delattr(ctypes, "windll", raising=False)
    assert elevation.is_elevated() is None


@pytest.mark.parametrize(("euid", "expected"), [(0, True), (1000, False)])
def test_is_elevated_on_posix_means_root(monkeypatch, euid, expected):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    assert elevation.is_elevated() is expected


def test_is_elevated_without_geteuid_is_unknown(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delattr(os, "geteuid")
    assert elevation.is_elevated() is None


def test_is_elevated_when_geteuid_fails_is_unknown(monkeypatch):
    def broken():
        raise OSError("no euid")

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", broken)
    assert elevation.is_elevated() is None


def test_relaunch_runs_the_same_command_elevated_with_root_options_first(windows, monkeypatch):
    win32 = windows(FakeWin32(exit_code=3))
    monkeypatch.setattr(sys, "argv", ["cryptnox-id", "fido", "info", "--rp", "a b"])
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert elevation.relaunch_elevated(["--elevated-result-out", "C:\\t\\r.json"]) == 3
    sei = win32.sei
    assert sei.lpVerb == "runas"
    assert sei.lpFile == sys.executable
    assert sei.lpParameters == subprocess.list2cmdline(
        [
            "-m",
            "cryptnox_id_cli",
            "--elevated-result-out",
            "C:\\t\\r.json",
            "fido",
            "info",
            "--rp",
            "a b",
        ]
    )
    assert sei.nShow == 0
    assert sei.fMask == 0x40  # SEE_MASK_NOCLOSEPROCESS, or there is no handle to wait on
    assert sei.cbSize == ctypes.sizeof(sei)
    assert win32.calls == [
        ("wait", FakeWin32.HANDLE, 0xFFFFFFFF),
        ("exit_code", FakeWin32.HANDLE),
        ("close", FakeWin32.HANDLE),
    ]


def test_relaunch_declined_at_the_uac_prompt_returns_none(windows):
    win32 = windows(FakeWin32(started=False))
    assert elevation.relaunch_elevated([]) is None
    assert win32.calls == []


@pytest.mark.parametrize(
    ("hresult", "message", "expected"),
    [
        (0x80100027, "Unable to connect", True),
        (-2146435033, "Unable to connect", True),  # the same code as a signed 32-bit value
        (None, "Failed: SCARD_E_NO_ACCESS", True),
        (None, "Failed to transmit with protocol T1. Access is denied.", True),
        (None, "access denied by policy", True),
        ("0x80100027", "Unable to connect (0x80100027)", True),
        (0x80100069, "Card was removed.", False),
        (None, "Card was removed.", False),
    ],
)
def test_no_access_is_recognised_by_code_or_by_message(hresult, message, expected):
    exc = Exception(message)
    exc.hresult = hresult
    assert elevation.looks_like_no_access(exc) is expected
