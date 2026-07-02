# SPDX-License-Identifier: Apache-2.0
"""Rule classification — conservative by design, bypass attempts gated."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashgate.integrations.claude_code.rules import (
    KIND_GIT_MERGE,
    KIND_GIT_PUSH,
    KIND_SELF_APPROVAL,
    classify,
)

_FIXTURES = Path(__file__).parent / "fixtures"


def _bash(command: str):
    return classify("Bash", {"command": command})


@pytest.mark.parametrize("command", [
    "git push",
    "git push origin main",
    "git push --force-with-lease origin feature",
    "git -C /some/repo push",                      # global-option bypass
    "git -c user.name=x push origin main",
    "GIT_SSH_COMMAND='ssh -i k' git push",         # env-prefixed
    "cd /repo && git push",                        # chained
    "uv run pytest -q && git add -A && git push",  # long chain
    "git commit -m 'x'; git push",                 # semicolon chain
    "sh -c 'git push origin main'",                # wrapped shell
    "bash -c \"git push\"",
    "echo done | git push",                        # piped
    "git\tpush",                                   # tab separator
    "git push && git merge main",                  # both -> gated
])
def test_push_shaped_commands_are_gated(command: str) -> None:
    cls = _bash(command)
    assert cls.gated and cls.kind == KIND_GIT_PUSH, command


@pytest.mark.parametrize("command", [
    "git merge feature-branch",
    "git merge --no-ff release",
    "git -C /repo merge topic",
    "a && git merge topic",
    "sh -c 'git merge topic'",
])
def test_merge_shaped_commands_are_gated(command: str) -> None:
    cls = _bash(command)
    assert cls.gated and cls.kind == KIND_GIT_MERGE, command


def test_push_wins_over_merge_when_both_present() -> None:
    assert _bash("git merge topic && git push").kind == KIND_GIT_PUSH


@pytest.mark.parametrize("command", [
    "git status --short",
    "git log --oneline -5",
    "git diff HEAD~1",
    "ls -la",
    "echo hello",
    "python -m pytest",
    "gitk",                      # 'gitk' is not the 'git' word
    "echo pushkin",              # 'pushkin' is not the 'push' word
    "",
    "   ",
])
def test_harmless_commands_pass_through(command: str) -> None:
    assert _bash(command).gated is False, command


def test_false_positives_are_deliberate_when_in_doubt_gate() -> None:
    # substring matching gates even a quoted mention — accepted trade-off,
    # pinned so nobody "fixes" it into a bypassable parser
    assert _bash('echo "git push"').gated is True


def test_non_bash_tools_are_never_gated() -> None:
    assert classify("Write", {"content": "git push"}).gated is False
    assert classify("Read", {"file_path": "/x"}).gated is False
    assert classify("", {}).gated is False


@pytest.mark.parametrize("command", [
    "hashgate accept abc123 --hash ffff",
    "hashgate --db /tmp/x.db accept abc123 --hash ffff",
    "hashgate deny abc123 --reason 'no'",
    "cd /x && hashgate accept abc --hash h",
])
def test_agent_self_approval_is_always_flagged(command: str) -> None:
    cls = _bash(command)
    assert cls.gated and cls.kind == KIND_SELF_APPROVAL, command


@pytest.mark.parametrize("command", [
    "hashgate pending",
    "hashgate show abc123",
    "hashgate bundle chain1",
])
def test_readonly_hashgate_cli_is_not_gated(command: str) -> None:
    assert _bash(command).gated is False, command


def test_golden_fixture_inputs_classify_as_expected() -> None:
    def load(name: str) -> dict:
        return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))

    push = load("pretooluse_bash_push.json")
    assert classify(push["tool_name"], push["tool_input"]).kind == KIND_GIT_PUSH
    chained = load("pretooluse_bash_chained_push.json")
    assert classify(chained["tool_name"], chained["tool_input"]).kind == KIND_GIT_PUSH
    harmless = load("pretooluse_bash_harmless.json")
    assert classify(harmless["tool_name"], harmless["tool_input"]).gated is False
    non_bash = load("pretooluse_non_bash.json")
    assert classify(non_bash["tool_name"], non_bash["tool_input"]).gated is False
