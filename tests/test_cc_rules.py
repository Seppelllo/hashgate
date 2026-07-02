# SPDX-License-Identifier: Apache-2.0
"""Rule classification — conservative by design, bypass attempts gated."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashgate.integrations.claude_code.rules import (
    KIND_DEPLOY_SCRIPT,
    KIND_DOCKER_COMPOSE_UP,
    KIND_GIT_FORCE_PUSH,
    KIND_GIT_MERGE,
    KIND_GIT_PUSH,
    KIND_GIT_RESET_HARD,
    KIND_KAMAL_DEPLOY,
    KIND_KUBECTL_APPLY,
    KIND_RM_RF,
    KIND_SELF_APPROVAL,
    classify,
)

_FIXTURES = Path(__file__).parent / "fixtures"


def _bash(command: str):
    return classify("Bash", {"command": command})


@pytest.mark.parametrize("command", [
    "git push",
    "git push origin main",
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


# --- destructive git / rm (v0.2) ---------------------------------------------
@pytest.mark.parametrize("command", [
    "git push --force",
    "git push --force-with-lease origin main",
    "git push --force-with-lease=refs/heads/main origin main",
    "git push --force-if-includes",
    "git push -f",
    "git push -fu origin main",              # combined short flag
    "git -C /repo push --force",             # global-option bypass
    "cd /x && git push -f",                  # chained
    "sh -c 'git push --force origin main'",  # wrapped
])
def test_force_push_is_its_own_kind(command: str) -> None:
    cls = _bash(command)
    assert cls.gated and cls.kind == KIND_GIT_FORCE_PUSH, command


def test_plain_push_stays_plain() -> None:
    assert _bash("git push origin main").kind == KIND_GIT_PUSH
    # long flags starting with f are NOT force flags
    assert _bash("git push --follow-tags origin main").kind == KIND_GIT_PUSH
    assert _bash("git push --tags").kind == KIND_GIT_PUSH


@pytest.mark.parametrize("command", [
    "git reset --hard",
    "git reset --hard HEAD~3",
    "git reset --hard origin/main",
    "git -C /repo reset --hard abc123",
    "a && git reset --hard",
    "sh -c 'git reset --hard HEAD~1'",
])
def test_reset_hard_is_gated(command: str) -> None:
    cls = _bash(command)
    assert cls.gated and cls.kind == KIND_GIT_RESET_HARD, command


def test_soft_and_mixed_reset_are_not_gated() -> None:
    assert _bash("git reset --soft HEAD~1").gated is False
    assert _bash("git reset HEAD~1").gated is False


@pytest.mark.parametrize("command", [
    "rm -rf build/",
    "rm -fr /tmp/x",
    "rm -r dist",
    "rm -Rf node_modules",
    "rm --recursive --force x",
    "a && rm -rf out",
    "sh -c 'rm -rf $HOME/x'",
    "/bin/rm -rf y",
])
def test_recursive_rm_is_gated(command: str) -> None:
    cls = _bash(command)
    assert cls.gated and cls.kind == KIND_RM_RF, command


def test_single_file_rm_is_not_gated() -> None:
    assert _bash("rm file.txt").gated is False
    assert _bash("rm -f file.txt").gated is False  # not recursive


# --- deploy commands (v0.2) -----------------------------------------------------
@pytest.mark.parametrize("command,kind", [
    ("kamal deploy", KIND_KAMAL_DEPLOY),
    ("kamal redeploy", KIND_KAMAL_DEPLOY),
    ("kamal deploy -d staging", KIND_KAMAL_DEPLOY),
    ("cd app && kamal deploy", KIND_KAMAL_DEPLOY),
    ("docker compose up -d", KIND_DOCKER_COMPOSE_UP),
    ("docker-compose up", KIND_DOCKER_COMPOSE_UP),
    ("docker compose -f prod.yml up -d web", KIND_DOCKER_COMPOSE_UP),
    ("kubectl apply -f k8s/", KIND_KUBECTL_APPLY),
    ("kubectl --context prod apply -f app.yaml", KIND_KUBECTL_APPLY),
    ("./deploy.sh", KIND_DEPLOY_SCRIPT),
    ("bash scripts/deploy.sh production", KIND_DEPLOY_SCRIPT),
    ("make deploy", KIND_DEPLOY_SCRIPT),
    ("uv run pytest && make deploy", KIND_DEPLOY_SCRIPT),
])
def test_deploy_commands_are_gated(command: str, kind: str) -> None:
    cls = _bash(command)
    assert cls.gated and cls.kind == kind, command


@pytest.mark.parametrize("command", [
    "docker compose ps",
    "docker compose logs -f web",
    "kubectl get pods",
    "kubectl diff -f app.yaml",
    "make test",
    "kamal app logs",
])
def test_non_mutating_tool_commands_pass(command: str) -> None:
    assert _bash(command).gated is False, command


def test_precedence_git_wins_over_deploy_in_one_chain() -> None:
    # one command, several gate-worthy parts: ONE kind by fixed precedence;
    # the operator reviews the full command in the payload either way
    assert _bash("git push && kamal deploy").kind == KIND_GIT_PUSH
    assert _bash("rm -rf dist && make deploy").kind == KIND_RM_RF


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
    "/Users/x/.hashgate/venv/bin/hashgate accept abc --hash h",  # path-prefixed
    "sh -c 'hashgate deny abc --reason no'",                     # wrapped shell
    "true; hashgate accept abc --hash h",                        # semicolon chain
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


@pytest.mark.parametrize("command", [
    # field finding: a commit message ABOUT hashgate tripped the always-deny
    # self-approval rule and made the commit un-runnable. Mentions inside
    # strings are not command invocations.
    'git commit -m "docs: explain that hashgate accept requires the hash echo"',
    "echo the operator runs hashgate deny in their own terminal",
    'git commit -q -m "fix: hashgate accept/deny reasons"',
])
def test_mentions_of_the_cli_are_not_self_approval(command: str) -> None:
    assert _bash(command).kind != KIND_SELF_APPROVAL, command


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
