"""The PyInstaller spec names what it freezes; those names must exist.

No job builds the spec, so a wrong name in it surfaces only in a frozen build,
as data files or modules that are silently missing. The spec is parsed here,
not run, so the check costs nothing and needs no PyInstaller.
"""

import ast
import fnmatch
import importlib
import importlib.util
import pathlib
from importlib.resources import files

import pytest

from cryptnox_id_cli import CLI_NAME

SPEC = pathlib.Path(__file__).resolve().parents[2] / "packaging" / f"{CLI_NAME}.spec"


def _calls(tree: ast.AST, name: str) -> list[ast.Call]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if called == name:
                found.append(node)
    return found


def _keyword(call: ast.Call, name: str):
    for keyword in call.keywords:
        if keyword.arg == name:
            return ast.literal_eval(keyword.value)
    return None


@pytest.fixture(scope="module")
def spec() -> ast.Module:
    return ast.parse(SPEC.read_text(encoding="utf-8"), filename=str(SPEC))


def test_data_files_are_collected_from_a_package_that_exists(spec):
    calls = _calls(spec, "collect_data_files")
    assert calls, "the spec collects no data files"
    for call in calls:
        package = ast.literal_eval(call.args[0])
        importlib.import_module(package)
        for pattern in _keyword(call, "includes") or []:
            directory, _, glob = pattern.rpartition("/")
            names = [entry.name for entry in files(package).joinpath(directory).iterdir()]
            assert fnmatch.filter(names, glob), f"{pattern!r} matches nothing in {package}"


def test_hidden_imports_resolve(spec):
    (analysis,) = _calls(spec, "Analysis")
    for module in _keyword(analysis, "hiddenimports") or []:
        assert importlib.util.find_spec(module) is not None, module


def test_the_executable_carries_the_cli_name(spec):
    (exe,) = _calls(spec, "EXE")
    assert _keyword(exe, "name") == CLI_NAME
