# SPDX-License-Identifier: Apache-2.0
"""The reference example must run end-to-end (single command, offline) and
show both scenarios — this keeps the README's promise green in CI."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parent.parent / "examples" / "pr_merge_gate" / "pr_merge_gate.py"


def test_example_runs_and_shows_both_scenarios() -> None:
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "Scenario A" in out and "Scenario B" in out
    assert "status=applied" in out
    assert "HashMismatch" in out
    assert "nothing was merged" in out
    assert out.count("verify_bundle: valid=True []") == 2
    assert "outcome=hash_mismatch" in out
