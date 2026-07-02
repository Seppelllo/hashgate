# SPDX-License-Identifier: Apache-2.0
"""Classification: which tool calls are gate-mandatory.

Deliberately CONSERVATIVE substring matching over the whole command string:
chained commands (``a && git push``), wrapped shells (``sh -c "git push"``),
``git -C path push``, env-prefixed invocations — anything that contains a
git-push/merge shaped part anywhere is gated. False positives (e.g.
``echo "git push"``) are accepted by design: when in doubt, gate. Precise
parsing would create bypass surface; a denied echo costs one operator glance.

Special kind ``self_approval``: the agent itself has Bash, so it could run
``hashgate accept …`` and approve its own action. Such commands are ALWAYS
denied — approvals happen in the operator's own terminal, never through the
agent. (Read-only ``hashgate pending``/``show`` stay allowed so the agent can
report status.)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

KIND_GIT_PUSH = "git_push"
KIND_GIT_MERGE = "git_merge"
KIND_SELF_APPROVAL = "self_approval"

_GIT_RE = re.compile(r"(^|[^\w.-])git([^\w.-]|$)")
_PUSH_RE = re.compile(r"(^|[^\w.-])push([^\w.-]|$)")
_MERGE_RE = re.compile(r"(^|[^\w.-])merge([^\w.-]|$)")
_SELF_APPROVAL_RE = re.compile(r"(^|[^\w.-])hashgate\b.*\b(accept|deny)\b", re.DOTALL)


@dataclass(frozen=True)
class Classification:
    gated: bool
    kind: str | None = None


def classify(tool_name: str, tool_input: dict[str, Any]) -> Classification:
    """Classify one PreToolUse event. Only Bash commands are inspected in
    v0.1; everything else passes through to Claude Code's normal permission
    machinery untouched (hashgate never actively allows what it does not
    gate)."""
    if tool_name != "Bash":
        return Classification(gated=False)
    command = str((tool_input or {}).get("command") or "")
    if not command.strip():
        return Classification(gated=False)
    if _SELF_APPROVAL_RE.search(command):
        return Classification(gated=True, kind=KIND_SELF_APPROVAL)
    if _GIT_RE.search(command):
        # push wins over merge when both appear (higher blast radius)
        if _PUSH_RE.search(command):
            return Classification(gated=True, kind=KIND_GIT_PUSH)
        if _MERGE_RE.search(command):
            return Classification(gated=True, kind=KIND_GIT_MERGE)
    return Classification(gated=False)
