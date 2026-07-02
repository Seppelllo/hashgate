# SPDX-License-Identifier: Apache-2.0
"""GatedAction implementations for git operations.

The derivation BINDS THE REPOSITORY STATE into the payload: repo root,
branch, current HEAD SHA and the normalized command. That makes the PR-merge
property hold live: if the agent commits again after the operator previewed,
the fresh re-derivation produces a different hash and the accept no longer
matches.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from hashgate.errors import ValidationFailed
from hashgate.integrations.claude_code.rules import _MERGE_RE, _PUSH_RE

_GIT_TIMEOUT_SECONDS = 10


@dataclass
class GitCommandContext:
    """Context for one gated Bash command."""

    cwd: str
    command: str
    session_id: str = ""
    #: set by the server on the accept path — binds the single-use claim to
    #: the concrete operator approval being redeemed
    approval_id: str | None = None


async def _git(cwd: str, *args: str) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", cwd, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), _GIT_TIMEOUT_SECONDS)
    except (OSError, TimeoutError) as exc:
        raise ValidationFailed(
            f"cannot read repository state: {exc}", code="repo_state_unavailable"
        ) from exc
    if proc.returncode != 0:
        raise ValidationFailed(
            f"git {' '.join(args)} failed: {stderr.decode(errors='replace').strip()[:200]}",
            code="repo_state_unavailable",
        )
    return stdout.decode().strip()


async def _git_optional(cwd: str, *args: str) -> str | None:
    """Like _git, but a git-level failure returns None (e.g. no upstream)."""
    try:
        return await _git(cwd, *args)
    except ValidationFailed:
        return None


def normalize_command(command: str) -> str:
    return " ".join(str(command or "").split())


#: transported-commit list cap (payloads stay reviewable and bounded)
MAX_COMMITS_IN_PAYLOAD = 50


class _GitActionBase:
    action_type = "git_command"
    feature_flag = "git_command_gate_enabled"
    _kind_re = None  # subclass responsibility

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        repo_root = await _git(ctx.cwd, "rev-parse", "--show-toplevel")
        branch = await _git(ctx.cwd, "rev-parse", "--abbrev-ref", "HEAD")
        head_sha = await _git(ctx.cwd, "rev-parse", "HEAD")
        return {
            "action": self.action_type,
            "repo_root": repo_root,
            "branch": branch,
            "head_sha": head_sha,  # the live anti-drift anchor
            "command": normalize_command(ctx.command),
        }

    async def validate(self, ctx: GitCommandContext, payload: dict[str, Any]) -> None:
        if not payload.get("command"):
            raise ValidationFailed("empty command", code="empty_command")
        if self._kind_re is not None and not self._kind_re.search(payload["command"]):
            raise ValidationFailed(
                f"command does not look like a {self.action_type}",
                code="command_kind_mismatch",
            )

    def idempotency_key(self, ctx: GitCommandContext, payload: dict[str, Any]) -> str:
        # single-use is per redeemed operator approval, not per hash — the
        # same payload hash can legitimately recur (a push does not move the
        # local HEAD), each occurrence needing a FRESH approval
        if not ctx.approval_id:
            raise ValidationFailed("no operator approval bound", code="approval_missing")
        return f"cc-approval:{ctx.approval_id}"

    async def apply(self, ctx: GitCommandContext, payload: dict[str, Any]) -> dict[str, Any]:
        # the effect IS the permission grant: hashgate answers "allow" and
        # Claude Code executes the command itself
        return {
            "permission": "allow",
            "action": self.action_type,
            "head_sha": payload["head_sha"],
            "approval_id": ctx.approval_id,
        }


class GitPushAction(_GitActionBase):
    """A push transports EVERY commit between the remote and HEAD — the
    payload must show exactly that, or the operator approves blind: it binds
    the remote-tracking state (``remote_sha``) and the transported commit
    list in addition to the HEAD SHA. Re-derivation reads both fresh, so a
    moved REMOTE invalidates an approval just like a moved HEAD does."""

    action_type = "git_push"
    feature_flag = "git_push_gate_enabled"
    _kind_re = _PUSH_RE

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        payload = await super().derive(ctx)
        remote_ref = await _git_optional(
            ctx.cwd, "rev-parse", "--abbrev-ref", "@{upstream}")
        remote_sha = await _git_optional(ctx.cwd, "rev-parse", "@{upstream}") \
            if remote_ref else None
        range_spec = f"{remote_sha}..HEAD" if remote_sha else "HEAD"
        log = await _git(ctx.cwd, "log", "--format=%H%x09%s",
                         "-n", str(MAX_COMMITS_IN_PAYLOAD + 1), range_spec)
        commits = []
        for line in log.splitlines():
            sha, _, subject = line.partition("\t")
            commits.append({"sha": sha, "subject": subject[:200]})
        truncated = len(commits) > MAX_COMMITS_IN_PAYLOAD
        payload.update({
            "remote_ref": remote_ref,  # None on a first push without upstream
            "remote_sha": remote_sha,
            "commits": commits[:MAX_COMMITS_IN_PAYLOAD],
            "commits_truncated": truncated,
        })
        return payload


class GitMergeAction(_GitActionBase):
    action_type = "git_merge"
    feature_flag = "git_merge_gate_enabled"
    _kind_re = _MERGE_RE


ACTIONS: dict[str, type[_GitActionBase]] = {
    GitPushAction.action_type: GitPushAction,
    GitMergeAction.action_type: GitMergeAction,
}
