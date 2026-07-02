# SPDX-License-Identifier: Apache-2.0
"""Fail-closed command-hook wrapper — the recommended way to wire hashgate
into Claude Code.

Claude Code hooks are FAIL-OPEN on transport problems: an unreachable
endpoint or a non-2xx answer produces a non-blocking error and the tool call
runs anyway. For a governance gate that is unacceptable as the only wire.
This wrapper inverts the semantics — with the RIGHT blast radius:

- reads the PreToolUse JSON from stdin,
- POSTs it to the local gate server,
- on 2xx: passes the server's JSON through on stdout, exit 0,
- on transport failure (connection refused, timeout, non-2xx): the wrapper
  classifies the command LOCALLY with the SAME rules the server uses
  (``rules.classify`` — one rulebook, not two) and blocks ONLY
  gate-mandatory commands (**exit 2**); everything else passes through
  (``{}``, exit 0). Server down means *gated actions* blocked — the agent
  can still run tests, commit, read files.
- malformed stdin: block (fail closed — an event we cannot classify could be
  anything).

No third-party imports — only the standard library plus the package's own
rules and config modules (same installation; the config module is
tomllib-based and stdlib-only).

Configuration: the wrapper reads the SAME shared source as server and CLI
(env > ~/.hashgate/config.toml > default) for the hook token and the port —
no environment juggling required. Overrides:
    HASHGATE_SERVER_URL       full endpoint URL (else port from the config)
    HASHGATE_TOKEN            hook token override (else 'token' from config)
    HASHGATE_CONFIG           alternate config file path
    HASHGATE_WRAPPER_TIMEOUT  seconds, default 10
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from hashgate.integrations.claude_code.config import GateConfigError, load_config
from hashgate.integrations.claude_code.rules import classify

DEFAULT_URL = "http://127.0.0.1:8377/hooks/pretooluse"
BLOCK_EXIT_CODE = 2  # Claude Code: exit 2 from a hook blocks the tool call


def _fail_closed_or_open(event: dict, error: str) -> int:
    """Transport failed: block only what the gate would gate."""
    cls = classify(str(event.get("tool_name") or ""), event.get("tool_input") or {})
    if cls.gated:
        print(f"hashgate wrapper: gate server unreachable ({error}) — gated "
              f"action ({cls.kind}) blocked. Start it with: hashgate-hook-server",
              file=sys.stderr)
        return BLOCK_EXIT_CODE
    sys.stdout.write("{}")  # not gate-mandatory: pass through undecided
    return 0


def run(stdin_data: str) -> int:
    try:
        event = json.loads(stdin_data)
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
    except (json.JSONDecodeError, TypeError, ValueError):
        print("hashgate wrapper: invalid hook JSON on stdin — fail-closed block",
              file=sys.stderr)
        return BLOCK_EXIT_CODE

    # the wrapper reads the SAME shared config as server and CLI (env >
    # config.toml > default) — a token set in config.toml therefore reaches
    # the wrapper without any environment juggling. Field finding: env-only
    # token reading produced 401s the moment the server got its token from
    # the file. The wrapper is a fresh process per hook call, so config
    # changes apply immediately.
    try:
        cfg = load_config()
        token, port = cfg.token, cfg.port
    except GateConfigError as exc:
        return _fail_closed_or_open(event, f"config error: {exc}")
    url = os.environ.get("HASHGATE_SERVER_URL") \
        or f"http://127.0.0.1:{port}/hooks/pretooluse"
    timeout = float(os.environ.get("HASHGATE_WRAPPER_TIMEOUT", "10"))
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Hashgate-Token"] = token

    def status_reason(status: int) -> str:
        if status == 401:
            return ("HTTP 401 — token mismatch between wrapper and server; "
                    "check 'token' in ~/.hashgate/config.toml (both read it) "
                    "or a stale HASHGATE_TOKEN override in the environment")
        return f"HTTP {status}"

    request = urllib.request.Request(
        url, data=stdin_data.encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode()
            if 200 <= response.status < 300:
                sys.stdout.write(body)
                return 0
            return _fail_closed_or_open(event, status_reason(response.status))
    except urllib.error.HTTPError as exc:  # non-2xx raises in urllib
        return _fail_closed_or_open(event, status_reason(exc.code))
    except Exception as exc:  # connection refused, timeout, DNS, …
        return _fail_closed_or_open(event, str(exc))


def main() -> None:
    sys.exit(run(sys.stdin.read()))


if __name__ == "__main__":
    main()
