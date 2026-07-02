# SPDX-License-Identifier: Apache-2.0
"""Git action derivation against a REAL git repo (tmpdir fixture)."""
from __future__ import annotations

import subprocess

import pytest

from hashgate.canonical import canonical_hash
from hashgate.errors import ValidationFailed
from hashgate.integrations.claude_code.actions import (
    GitCommandContext,
    GitMergeAction,
    GitPushAction,
)

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    "HOME": "/tmp",
}


def _git(cwd, *args) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True, env=_GIT_ENV).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-b", "main", str(tmp_path)], check=True,
                   capture_output=True, env=_GIT_ENV)
    (tmp_path / "a.txt").write_text("one\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "first")
    return tmp_path


async def test_derive_binds_repo_state(repo) -> None:
    action = GitPushAction()
    ctx = GitCommandContext(cwd=str(repo), command="  git   push   origin main ")
    payload = await action.derive(ctx)
    assert payload["action"] == "git_push"
    assert payload["repo_root"] == _git(repo, "rev-parse", "--show-toplevel")
    assert payload["branch"] == "main"
    assert payload["head_sha"] == _git(repo, "rev-parse", "HEAD")
    assert len(payload["head_sha"]) == 40
    assert payload["command"] == "git push origin main"  # normalized
    await action.validate(ctx, payload)  # no raise


async def test_new_commit_changes_the_hash(repo) -> None:
    action = GitPushAction()
    ctx = GitCommandContext(cwd=str(repo), command="git push")
    h1 = canonical_hash(await action.derive(ctx))
    (repo / "a.txt").write_text("two\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "second")
    h2 = canonical_hash(await action.derive(ctx))
    assert h1 != h2  # the agent kept working -> the approved hash is stale


async def test_derive_is_deterministic_for_unchanged_repo(repo) -> None:
    action = GitPushAction()
    ctx = GitCommandContext(cwd=str(repo), command="git push")
    assert canonical_hash(await action.derive(ctx)) == \
        canonical_hash(await action.derive(ctx))


async def test_non_repo_cwd_fails_closed(tmp_path) -> None:
    action = GitPushAction()
    with pytest.raises(ValidationFailed) as exc:
        await action.derive(GitCommandContext(cwd=str(tmp_path / "empty"),
                                              command="git push"))
    assert exc.value.code == "repo_state_unavailable"


async def test_validate_refuses_kind_mismatch(repo) -> None:
    # a merge action never validates a push-shaped command (defense in depth)
    action = GitMergeAction()
    ctx = GitCommandContext(cwd=str(repo), command="git push origin main")
    payload = await action.derive(ctx)
    with pytest.raises(ValidationFailed) as exc:
        await action.validate(ctx, payload)
    assert exc.value.code == "command_kind_mismatch"


async def test_idempotency_key_requires_a_bound_approval(repo) -> None:
    action = GitPushAction()
    ctx = GitCommandContext(cwd=str(repo), command="git push")
    payload = await action.derive(ctx)
    with pytest.raises(ValidationFailed):
        action.idempotency_key(ctx, payload)
    ctx.approval_id = "appr-1"
    assert action.idempotency_key(ctx, payload) == "cc-approval:appr-1"
