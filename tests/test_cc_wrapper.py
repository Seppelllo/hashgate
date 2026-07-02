# SPDX-License-Identifier: Apache-2.0
"""Fail-closed wrapper with the RIGHT blast radius: server down blocks ONLY
gate-mandatory commands (exit 2); everything else passes through (exit 0) —
the agent stays able to commit/test/read while the gate is down."""
from __future__ import annotations

import ast
import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

_WRAPPER = Path(__file__).parent.parent / "src" / "hashgate" / "integrations" / \
    "claude_code" / "hook_wrapper.py"
_SRC = str(Path(__file__).parent.parent / "src")

_DOWN_URL = "http://127.0.0.1:9/hooks/pretooluse"  # closed port


def _event(command: str) -> str:
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})


def _run(stdin: str, env_extra: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_WRAPPER)],
        input=stdin, capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": _SRC,
             "HASHGATE_WRAPPER_TIMEOUT": "2", **env_extra},
    )


def test_server_down_blocks_gated_command_with_exit_2() -> None:
    proc = _run(_event("git push origin main"), {"HASHGATE_SERVER_URL": _DOWN_URL})
    assert proc.returncode == 2
    assert "gate server unreachable" in proc.stderr
    assert "gated action (git_push) blocked" in proc.stderr
    assert "hashgate-hook-server" in proc.stderr  # names the next step
    assert proc.stdout == ""


def test_server_down_passes_non_gated_commands(  # the blast-radius fix
) -> None:
    for command in ("ls -la", "git commit -m 'wip'", "git status", "python -m pytest"):
        proc = _run(_event(command), {"HASHGATE_SERVER_URL": _DOWN_URL})
        assert proc.returncode == 0, (command, proc.stderr)
        assert proc.stdout == "{}"  # undecided: normal permissions apply


def test_invalid_stdin_blocks_with_exit_2() -> None:
    proc = _run("this is not json", {"HASHGATE_SERVER_URL": _DOWN_URL})
    assert proc.returncode == 2
    assert "invalid hook JSON" in proc.stderr


def test_one_rulebook_not_two() -> None:
    # the wrapper must use the SAME classification as the server — structural
    # pin: it imports rules.classify and defines no regexes of its own
    source = _WRAPPER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert any(node.module == "hashgate.integrations.claude_code.rules"
               and any(alias.name == "classify" for alias in node.names)
               for node in imports)
    assert "re.compile" not in source
    assert "\nimport re\n" not in source


class _FakeGate(http.server.BaseHTTPRequestHandler):
    status = 200
    body = json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "hashgate: pending"}})
    seen_token: list[str | None] = []

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).seen_token.append(self.headers.get("X-Hashgate-Token"))
        payload = self.body.encode()
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence
        pass


def _serve(handler) -> tuple[http.server.HTTPServer, int]:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def test_2xx_response_passes_through_stdout_exit_0() -> None:
    server, port = _serve(_FakeGate)
    try:
        proc = _run(_event("git push"), {
            "HASHGATE_SERVER_URL": f"http://127.0.0.1:{port}/hooks/pretooluse",
            "HASHGATE_TOKEN": "s3cret",
        })
    finally:
        server.shutdown()
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _FakeGate.seen_token[-1] == "s3cret"  # shared secret forwarded


def test_non_2xx_blocks_gated_but_passes_harmless() -> None:
    class Unauthorized(_FakeGate):
        status = 401

    server, port = _serve(Unauthorized)
    try:
        url = f"http://127.0.0.1:{port}/hooks/pretooluse"
        gated = _run(_event("git push"), {"HASHGATE_SERVER_URL": url})
        harmless = _run(_event("ls"), {"HASHGATE_SERVER_URL": url})
    finally:
        server.shutdown()
    assert gated.returncode == 2 and "401" in gated.stderr
    assert harmless.returncode == 0 and harmless.stdout == "{}"
