#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fresh-venv install verification (manual; see CONTRIBUTING.md).
# Proves: non-editable install works, console scripts resolve and run,
# the wrapper fails CLOSED on garbage input.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 -m venv "$tmp/venv"
"$tmp/venv/bin/pip" install --quiet '.[server]'

"$tmp/venv/bin/python" -c "import hashgate; print('import OK:', hashgate.__version__)"
"$tmp/venv/bin/hashgate" --help >/dev/null && echo "hashgate CLI OK"
"$tmp/venv/bin/python" -c "import hashgate.integrations.claude_code.server" \
  && echo "server module OK"

if "$tmp/venv/bin/hashgate-hook-wrapper" </dev/null >/dev/null 2>&1; then
  echo "ERROR: wrapper must fail closed on invalid stdin"; exit 1
else
  code=$?
  if [ "$code" -ne 2 ]; then
    echo "ERROR: wrapper expected exit 2 (block), got $code"; exit 1
  fi
  echo "wrapper fail-closed OK (exit 2 on invalid stdin)"
fi

echo "install verification PASSED"
