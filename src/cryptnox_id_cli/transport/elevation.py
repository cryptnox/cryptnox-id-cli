"""Windows elevation detection and the FIDO/SCARD_E_NO_ACCESS message.

On Windows, selecting the FIDO CTAP AID from a non-elevated process is refused by
the resource manager with ``SCARD_E_NO_ACCESS`` (0x80100027). We detect this so the
``fido``/``doctor`` commands can print actionable guidance instead of a raw error.
"""

from __future__ import annotations

import subprocess
import sys

SCARD_E_NO_ACCESS = 0x80100027

# The reason FIDO2 needs elevation - surfaced to the user, not just the bare rule.
FIDO_REQUIREMENT = (
    "FIDO2 needs an Administrator terminal on Windows because the OS reserves direct "
    "PC/SC access to the FIDO2/CTAP applet for the WebAuthn platform API and blocks "
    "non-elevated processes (SCARD_E_NO_ACCESS)."
)

FIDO_WINDOWS_MESSAGE = (
    "FIDO2 access was blocked by Windows.\n"
    "Why: the OS reserves direct PC/SC access to the FIDO2/CTAP AID for the WebAuthn "
    "platform API and denies non-elevated processes (SCARD_E_NO_ACCESS 0x80100027).\n"
    "Fix: run this command from an Administrator terminal - the CLI can relaunch itself "
    "elevated when you confirm - or use Android/NFC tooling."
)


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_elevated() -> bool | None:
    """True/False if determinable, else None (unknown platform/error)."""
    if is_windows():
        try:
            import ctypes

            shell32 = getattr(ctypes, "windll").shell32  # noqa: B009 (windll is Windows-only)
            return bool(shell32.IsUserAnAdmin())
        except Exception:
            return None
    try:
        import os

        geteuid = getattr(os, "geteuid", None)  # POSIX-only
        return geteuid() == 0 if geteuid is not None else None
    except OSError:
        return None


def fido_elevation_status() -> tuple[str, str]:
    """Describe the FIDO elevation requirement for the *current* process.

    Returns ``(severity, message)`` where severity is ``"ok"`` (requirement met or
    not applicable), ``"warn"`` (requirement not met - action needed), or ``"note"``
    (requirement applies but elevation could not be confirmed). An empty message
    means there is nothing to show (non-Windows).
    """
    if not is_windows():
        return ("ok", "")
    elev = is_elevated()
    if elev is True:
        return ("ok", f"{FIDO_REQUIREMENT} This terminal is elevated.")
    if elev is False:
        return (
            "warn",
            f"{FIDO_REQUIREMENT} This process is NOT elevated, so the call will fail; "
            "re-run from an Administrator terminal.",
        )
    return ("note", f"{FIDO_REQUIREMENT} Could not confirm this process is elevated.")


def relaunch_command() -> tuple[str, list[str], list[str]]:
    """The (program, prefix, user_args) needed to re-invoke this exact CLI command.

    ``prefix`` is any interpreter prefix (``-m cryptnox_id_cli``) and ``user_args``
    is the original ``sys.argv`` tail. Splitting them lets the caller inject *root*
    options (which click requires BEFORE the subcommand) in the right position.
    Handles both the PyInstaller one-file build (``sys.frozen``) and a module run.
    """
    if getattr(sys, "frozen", False):
        return sys.executable, [], list(sys.argv[1:])
    return sys.executable, ["-m", "cryptnox_id_cli"], list(sys.argv[1:])


# Distinguishes "user clicked No on the UAC prompt" from a real failure.
ERROR_CANCELLED = 1223


def relaunch_elevated(extra_args: list[str]) -> int | None:
    """Re-launch the current command elevated via a Windows UAC prompt and wait.

    ``extra_args`` are root-level options injected BEFORE the subcommand (e.g. a
    result-capture flag). Returns the elevated child's exit code, ``None`` if
    elevation could not be started (non-Windows, the user declined UAC, or an error).
    """
    if not is_windows():
        return None
    import ctypes
    import ctypes.wintypes as wintypes

    program, prefix, user_args = relaunch_command()
    params = subprocess.list2cmdline([*prefix, *extra_args, *user_args])

    class _SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    see_mask_nocloseprocess = 0x00000040
    sw_hide = 0
    infinite = 0xFFFFFFFF

    shell32 = getattr(ctypes, "windll").shell32  # noqa: B009 (windll is Windows-only)
    kernel32 = getattr(ctypes, "windll").kernel32  # noqa: B009

    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = see_mask_nocloseprocess
    sei.lpVerb = "runas"
    sei.lpFile = program
    sei.lpParameters = params
    sei.nShow = sw_hide

    if not shell32.ShellExecuteExW(ctypes.byref(sei)) or not sei.hProcess:
        return None  # declined UAC (GetLastError == ERROR_CANCELLED) or failed to start

    try:
        kernel32.WaitForSingleObject(sei.hProcess, infinite)
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
        return int(code.value)
    finally:
        kernel32.CloseHandle(sei.hProcess)


def looks_like_no_access(exc: BaseException) -> bool:
    """Heuristically detect the Windows no-access block from a pyscard exception."""
    hr = getattr(exc, "hresult", None)
    if isinstance(hr, int) and (hr & 0xFFFFFFFF) == SCARD_E_NO_ACCESS:
        return True
    s = str(exc).lower()
    return (
        "0x80100027" in s
        or "scard_e_no_access" in s
        or "access is denied" in s
        or "access denied" in s
    )
