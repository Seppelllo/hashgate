# SPDX-License-Identifier: Apache-2.0
"""Classification: which tool calls are gate-mandatory.

Deliberately CONSERVATIVE substring matching over the whole command string:
chained commands (``a && git push``), wrapped shells (``sh -c "git push"``),
``git -C path push``, env-prefixed invocations — anything that contains a
gate-worthy shape anywhere is gated. False positives (e.g.
``echo "git push"``) are accepted by design: when in doubt, gate. Precise
parsing would create bypass surface; a denied echo costs one operator glance.

When one command chains several gate-worthy parts, ONE kind is returned by
a fixed precedence (destructive git > plain git > rm > deploys) — the
operator reviews the FULL command in the payload either way; the kind only
selects which state gets bound and rendered.

Special kind ``self_approval``: the agent itself has Bash, so it could run
``hashgate accept …`` and approve its own action. Such commands are ALWAYS
denied — approvals happen in the operator's own terminal, never through the
agent. (Read-only ``hashgate pending``/``show`` stay allowed so the agent can
report status.)

Unlike the other rules, self_approval has NO operator-approval path — a
false positive here is an unfixable block, not one extra review. Its pattern
therefore matches ``hashgate accept/deny`` only in COMMAND position (start of
a command segment, incl. chained/wrapped/path-prefixed invocations), not as a
mere mention inside a string: a commit message *about* hashgate must not trip
the gate (field finding: it did).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

KIND_GIT_PUSH = "git_push"
KIND_GIT_FORCE_PUSH = "git_force_push"
KIND_GIT_MERGE = "git_merge"
KIND_GIT_RESET_HARD = "git_reset_hard"
KIND_RM_RF = "rm_rf"
KIND_KAMAL_DEPLOY = "kamal_deploy"
KIND_DOCKER_COMPOSE_UP = "docker_compose_up"
KIND_KUBECTL_APPLY = "kubectl_apply"
KIND_DEPLOY_SCRIPT = "deploy_script"
KIND_SELF_APPROVAL = "self_approval"


def _word(word: str) -> re.Pattern[str]:
    return re.compile(rf"(^|[^\w.-]){word}([^\w.-]|$)")


_GIT_RE = _word("git")
_PUSH_RE = _word("push")
_MERGE_RE = _word("merge")
_RESET_RE = _word("reset")
_HARD_RE = re.compile(r"(^|\s)--hard(\s|$)")
#: force flags: --force, --force-with-lease[=ref], --force-if-includes, and
#: short-flag tokens containing f (-f, -fu, …) — conservative: a push that
#: LOOKS forced is reviewed as forced
_FORCE_RE = re.compile(
    r"(^|\s)(--force(-with-lease(=\S+)?|-if-includes)?|-[a-zA-Z]*f[a-zA-Z]*)(\s|$)")
_RM_RE = _word("rm")
#: recursive deletion: -r/-R anywhere in a short-flag token, or --recursive
_RM_RECURSIVE_RE = re.compile(r"(^|\s)(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(\s|$)")
_KAMAL_RE = _word("kamal")
_KAMAL_VERB_RE = re.compile(r"(^|[^\w.-])(deploy|redeploy)([^\w.-]|$)")
_DOCKER_RE = _word("docker")
_COMPOSE_RE = re.compile(r"(^|[^\w.-])(compose|docker-compose)([^\w.-]|$)")
_UP_RE = _word("up")
_KUBECTL_RE = _word("kubectl")
_APPLY_RE = _word("apply")
_DEPLOY_SH_RE = re.compile(r"(^|[\s;&|'\"(`])\S*deploy\.sh([^\w.-]|$)")
_MAKE_RE = _word("make")
_DEPLOY_WORD_RE = _word("deploy")
# command position: line/segment start (also after ; & | ` ( $( and quote
# openings for wrapped shells), optional path prefix, options before the verb
_SELF_APPROVAL_RE = re.compile(
    r"""(?mx)
    (?:^|[;&|`(]|\$\(|["'])          # start of a command segment
    \s*(?:\S*/)?hashgate\s+          # the hashgate executable (any path)
    (?:--?\S+(?:\s+\S+)*?\s+)?       # tolerated options, e.g. --db X
    (?:accept|deny)\b                # the mutating verbs
    """,
)


@dataclass(frozen=True)
class Classification:
    gated: bool
    kind: str | None = None


def classify(tool_name: str, tool_input: dict[str, Any]) -> Classification:
    """Classify one PreToolUse event. Only Bash commands are inspected;
    everything else passes through to Claude Code's normal permission
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
        # push wins over merge/reset when several appear (it publishes)
        if _PUSH_RE.search(command):
            if _FORCE_RE.search(command):
                return Classification(gated=True, kind=KIND_GIT_FORCE_PUSH)
            return Classification(gated=True, kind=KIND_GIT_PUSH)
        if _RESET_RE.search(command) and _HARD_RE.search(command):
            return Classification(gated=True, kind=KIND_GIT_RESET_HARD)
        if _MERGE_RE.search(command):
            return Classification(gated=True, kind=KIND_GIT_MERGE)
    if _RM_RE.search(command) and _RM_RECURSIVE_RE.search(command):
        return Classification(gated=True, kind=KIND_RM_RF)
    if _KAMAL_RE.search(command) and _KAMAL_VERB_RE.search(command):
        return Classification(gated=True, kind=KIND_KAMAL_DEPLOY)
    if _COMPOSE_RE.search(command) and _UP_RE.search(command) \
            and (_DOCKER_RE.search(command) or "docker-compose" in command):
        return Classification(gated=True, kind=KIND_DOCKER_COMPOSE_UP)
    if _KUBECTL_RE.search(command) and _APPLY_RE.search(command):
        return Classification(gated=True, kind=KIND_KUBECTL_APPLY)
    if _DEPLOY_SH_RE.search(command) or (
            _MAKE_RE.search(command) and _DEPLOY_WORD_RE.search(command)):
        return Classification(gated=True, kind=KIND_DEPLOY_SCRIPT)
    return Classification(gated=False)
