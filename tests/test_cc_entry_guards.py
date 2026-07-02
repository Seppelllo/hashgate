# SPDX-License-Identifier: Apache-2.0
"""Console scripts must die friendly without the 'server' extra: the scripts
are installed by a bare `pip install hashgate`, so a missing fastapi/
sqlalchemy must produce instructions + exit 1, never a raw ImportError
traceback. The wrapper is stdlib-only by design and needs no guard — pinned."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from hashgate.integrations.claude_code import cli, hook_wrapper, server

_HINT = ("hashgate: this command requires the server extra — "
         "install with: pip install 'hashgate[server]'")


def _simulated() -> ModuleNotFoundError:
    return ModuleNotFoundError("No module named 'sqlalchemy'")


def test_cli_main_dies_friendly_without_extra(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_IMPORT_ERROR", _simulated())
    with pytest.raises(SystemExit) as exc:
        cli.main(["pending"])
    assert exc.value.code == 1
    assert _HINT in capsys.readouterr().err


def test_server_main_dies_friendly_without_extra(monkeypatch, capsys) -> None:
    monkeypatch.setattr(server, "_IMPORT_ERROR", _simulated())
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    assert _HINT in capsys.readouterr().err


def test_create_app_raises_with_instructions(monkeypatch) -> None:
    monkeypatch.setattr(server, "_IMPORT_ERROR", _simulated())
    with pytest.raises(ModuleNotFoundError) as exc:
        server.create_app()
    assert _HINT in str(exc.value)


def test_wrapper_is_stdlib_only_and_needs_no_guard() -> None:
    # the fail-closed wrapper must never die because of a missing extra —
    # pinned: it imports only the standard library plus the package's own
    # stdlib-only rules module
    stdlib = {"__future__", "json", "os", "sys", "urllib"}
    for module, allowed in (
        (hook_wrapper, stdlib | {"hashgate"}),
        # rules itself must stay stdlib-only or the wrapper inherits a dep
        (None, {"__future__", "dataclasses", "re", "typing"}),
    ):
        path = Path(module.__file__) if module else \
            Path(hook_wrapper.__file__).parent / "rules.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
        assert found <= allowed, (path.name, found - allowed)
