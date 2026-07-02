# SPDX-License-Identifier: Apache-2.0
"""Fail-closed wrapper — server down means BLOCK (exit 2), never pass."""
from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
from pathlib import Path

_WRAPPER = Path(__file__).parent.parent / "src" / "hashgate" / "integrations" / \
    "claude_code" / "hook_wrapper.py"
_SRC = str(Path(__file__).parent.parent / "src")

_EVENT = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push"}})


def _run(stdin: str, env_extra: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_WRAPPER)],
        input=stdin, capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": _SRC, **env_extra},
    )


def test_server_down_blocks_with_exit_2() -> None:
    proc = _run(_EVENT, {
        "HASHGATE_SERVER_URL": "http://127.0.0.1:9/hooks/pretooluse",  # closed port
        "HASHGATE_WRAPPER_TIMEOUT": "2",
    })
    assert proc.returncode == 2
    assert "fail-closed block" in proc.stderr
    assert proc.stdout == ""  # no decision passthrough on failure


def test_invalid_stdin_blocks_with_exit_2() -> None:
    proc = _run("this is not json", {})
    assert proc.returncode == 2
    assert "invalid hook JSON" in proc.stderr


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
        proc = _run(_EVENT, {
            "HASHGATE_SERVER_URL": f"http://127.0.0.1:{port}/hooks/pretooluse",
            "HASHGATE_TOKEN": "s3cret",
        })
    finally:
        server.shutdown()
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _FakeGate.seen_token[-1] == "s3cret"  # shared secret forwarded


def test_non_2xx_blocks_with_exit_2() -> None:
    class Unauthorized(_FakeGate):
        status = 401

    server, port = _serve(Unauthorized)
    try:
        proc = _run(_EVENT, {
            "HASHGATE_SERVER_URL": f"http://127.0.0.1:{port}/hooks/pretooluse",
        })
    finally:
        server.shutdown()
    assert proc.returncode == 2
    assert "401" in proc.stderr
