# SPDX-License-Identifier: Apache-2.0
"""Fail-closed command-hook wrapper — the recommended way to wire hashgate
into Claude Code.

Claude Code hooks are FAIL-OPEN on transport problems: an unreachable
endpoint or a non-2xx answer produces a non-blocking error and the tool call
runs anyway. For a governance gate that is unacceptable as the only wire.
This wrapper inverts the semantics:

- reads the PreToolUse JSON from stdin,
- POSTs it to the local gate server,
- on 2xx: passes the server's JSON through on stdout, exit 0,
- on ANY failure (connection refused, timeout, non-2xx, bad input):
  a reason on stderr and **exit 2** — which Claude Code treats as a BLOCK.

Server down => gate closed, not gate open.

Standard library only (urllib) — the wrapper must not fail because of a
missing dependency.

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

DEFAULT_URL = "http://127.0.0.1:8377/hooks/pretooluse"
BLOCK_EXIT_CODE = 2  # Claude Code: exit 2 from a hook blocks the tool call


def run(stdin_data: str) -> int:
    try:
        json.loads(stdin_data)  # malformed hook input -> fail closed
    except (json.JSONDecodeError, TypeError):
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
            print(f"hashgate wrapper: gate server answered {response.status} — "
                  "fail-closed block", file=sys.stderr)
            return BLOCK_EXIT_CODE
    except urllib.error.HTTPError as exc:  # non-2xx raises in urllib
        print(f"hashgate wrapper: gate server answered {exc.code} — "
              "fail-closed block", file=sys.stderr)
        return BLOCK_EXIT_CODE
    except Exception as exc:  # connection refused, timeout, DNS, …
        print(f"hashgate wrapper: gate server unreachable ({exc}) — "
              "fail-closed block. Start it with: hashgate-hook-server",
              file=sys.stderr)
        return BLOCK_EXIT_CODE


def main() -> None:
    sys.exit(run(sys.stdin.read()))


if __name__ == "__main__":
    main()
