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
rules module (same installation).

Environment:
    HASHGATE_SERVER_URL       default http://127.0.0.1:8377/hooks/pretooluse
    HASHGATE_TOKEN            optional shared secret (sent as X-Hashgate-Token)
    HASHGATE_WRAPPER_TIMEOUT  seconds, default 10
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

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

    url = os.environ.get("HASHGATE_SERVER_URL", DEFAULT_URL)
    timeout = float(os.environ.get("HASHGATE_WRAPPER_TIMEOUT", "10"))
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("HASHGATE_TOKEN")
    if token:
        headers["X-Hashgate-Token"] = token

    request = urllib.request.Request(
        url, data=stdin_data.encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode()
            if 200 <= response.status < 300:
                sys.stdout.write(body)
                return 0
            return _fail_closed_or_open(event, f"HTTP {response.status}")
    except urllib.error.HTTPError as exc:  # non-2xx raises in urllib
        return _fail_closed_or_open(event, f"HTTP {exc.code}")
    except Exception as exc:  # connection refused, timeout, DNS, …
        return _fail_closed_or_open(event, str(exc))


def main() -> None:
    sys.exit(run(sys.stdin.read()))


if __name__ == "__main__":
    main()
