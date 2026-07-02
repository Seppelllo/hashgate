# SPDX-License-Identifier: Apache-2.0
"""GatedAction implementations for git, destructive and deploy operations.

Every derivation BINDS THE RELEVANT STATE into the payload — repository
state (HEAD/remote/transported commits), resolved deletion targets, or
content hashes of the artifacts a deploy would ship. Re-derivation at accept
time reads everything fresh, so any drift refuses (the PR-merge property,
applied per action type).

Rules shared by all derivations:
- read-only, deterministic, NO network (no cluster call, no docker daemon —
  local files + git only),
- what cannot be determined offline is marked ``unresolved``/``None`` in the
  payload, never invented and never silently omitted,
- file contents are content-addressed (sha256 in the payload, never the raw
  content — .env and friends stay secret, only their hash binds),
- SPEC_canonical.md holds: no floats, no timestamps inside payloads.
"""
from __future__ import annotations

import asyncio
import glob
import hashlib
import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hashgate.errors import ValidationFailed
from hashgate.integrations.claude_code.rules import (
    _DEPLOY_SH_RE,
    _FORCE_RE,
    _HARD_RE,
    _KAMAL_RE,
    _KUBECTL_RE,
    _MERGE_RE,
    _PUSH_RE,
    _RESET_RE,
    _RM_RE,
    _UP_RE,
)

_GIT_TIMEOUT_SECONDS = 10

#: list caps (payloads stay reviewable and bounded)
MAX_COMMITS_IN_PAYLOAD = 50
MAX_PATHS_IN_PAYLOAD = 50
MAX_MANIFESTS_IN_PAYLOAD = 20

UNRESOLVED = "unresolved"

_CHAIN_TOKENS = {"&&", "||", ";", "|"}


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


def _file_hash(path: Path) -> str | None:
    """sha256 of a file's bytes; None when unreadable/missing (fail-visible:
    the None lands in the payload, it is never silently dropped)."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:  # unbalanced quotes etc. — degrade, stay deterministic
        return command.split()


def _segment_after(command: str, word_matches) -> list[str]:
    """Tokens of the command segment starting after the first token matching
    ``word_matches`` (a predicate), stopping at a chain operator."""
    tokens = _tokens(command)
    segment: list[str] = []
    seen = False
    for token in tokens:
        if not seen:
            if word_matches(token):
                seen = True
            continue
        if token in _CHAIN_TOKENS:
            break
        segment.append(token)
    return segment


def _flag_value(segment: list[str], *names: str) -> str | None:
    """Value of ``--flag value`` or ``--flag=value`` within a segment."""
    for i, token in enumerate(segment):
        for name in names:
            if token == name and i + 1 < len(segment):
                return segment[i + 1]
            if token.startswith(name + "="):
                return token.split("=", 1)[1]
    return None


async def _repo_context(cwd: str) -> dict[str, Any]:
    return {
        "repo_root": await _git(cwd, "rev-parse", "--show-toplevel"),
        "branch": await _git(cwd, "rev-parse", "--abbrev-ref", "HEAD"),
        "head_sha": await _git(cwd, "rev-parse", "HEAD"),
    }


async def _commit_list(cwd: str, range_spec: str) -> tuple[list[dict[str, str]], bool]:
    log = await _git(cwd, "log", "--format=%H%x09%s",
                     "-n", str(MAX_COMMITS_IN_PAYLOAD + 1), range_spec)
    commits = []
    for line in log.splitlines():
        sha, _, subject = line.partition("\t")
        commits.append({"sha": sha, "subject": subject[:200]})
    return commits[:MAX_COMMITS_IN_PAYLOAD], len(commits) > MAX_COMMITS_IN_PAYLOAD


class _CommandActionBase:
    """Shared hooks; derive() is per action. No repository requirement here —
    subclasses that need git state use :class:`_GitActionBase`."""

    action_type = "command"
    feature_flag = "command_gate_enabled"
    _kind_re = None  # subclass responsibility

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
        # same payload hash can legitimately recur, each occurrence needing
        # a FRESH approval
        if not ctx.approval_id:
            raise ValidationFailed("no operator approval bound", code="approval_missing")
        return f"cc-approval:{ctx.approval_id}"

    async def apply(self, ctx: GitCommandContext, payload: dict[str, Any]) -> dict[str, Any]:
        # the effect IS the permission grant: hashgate answers "allow" and
        # Claude Code executes the command itself
        return {
            "permission": "allow",
            "action": self.action_type,
            "approval_id": ctx.approval_id,
        }


class _GitActionBase(_CommandActionBase):
    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        payload = {"action": self.action_type}
        payload.update(await _repo_context(ctx.cwd))
        payload["command"] = normalize_command(ctx.command)
        return payload

    async def apply(self, ctx: GitCommandContext, payload: dict[str, Any]) -> dict[str, Any]:
        effects = await super().apply(ctx, payload)
        if "head_sha" in payload:
            effects["head_sha"] = payload["head_sha"]
        return effects


# --- git actions ---------------------------------------------------------------
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
        commits, truncated = await _commit_list(ctx.cwd, range_spec)
        payload.update({
            "remote_ref": remote_ref,  # None on a first push without upstream
            "remote_sha": remote_sha,
            "commits": commits,
            "commits_truncated": truncated,
        })
        return payload


class GitForcePushAction(GitPushAction):
    """Force-push overwrites remote history: everything a push binds, plus
    the explicit force flag and — via ``remote_sha`` — the remote state that
    would be overwritten (what would be lost)."""

    action_type = "git_force_push"
    feature_flag = "git_force_push_gate_enabled"
    _kind_re = _PUSH_RE  # a force-push is a push; the flag is bound below

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        payload = await super().derive(ctx)
        match = _FORCE_RE.search(payload["command"])
        payload.update({
            "force": True,
            "force_flag": match.group(2) if match else UNRESOLVED,
            # explicit semantic duplicate of remote_sha: THIS is what a
            # forced update would overwrite (None/unresolved without upstream)
            "overwrites_remote_sha": payload.get("remote_sha"),
        })
        return payload

    async def validate(self, ctx: GitCommandContext, payload: dict[str, Any]) -> None:
        await super().validate(ctx, payload)
        if not _FORCE_RE.search(payload["command"]):
            raise ValidationFailed("command does not look like a force-push",
                                   code="command_kind_mismatch")


class GitMergeAction(_GitActionBase):
    action_type = "git_merge"
    feature_flag = "git_merge_gate_enabled"
    _kind_re = _MERGE_RE


class GitResetHardAction(_GitActionBase):
    """``git reset --hard`` discards work: the payload binds the current
    HEAD (what would be discarded), the reset target (raw + resolved SHA)
    and the list of commits that would be dropped. An unresolvable target is
    marked, never guessed."""

    action_type = "git_reset_hard"
    feature_flag = "git_reset_hard_gate_enabled"
    _kind_re = _RESET_RE

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        payload = await super().derive(ctx)
        segment = _segment_after(payload["command"], lambda t: t == "reset")
        target_raw = next((t for t in segment if not t.startswith("-")), "HEAD")
        target_sha = await _git_optional(ctx.cwd, "rev-parse", f"{target_raw}^{{commit}}")
        if target_sha is not None:
            discarded, truncated = await _commit_list(
                ctx.cwd, f"{target_sha}..HEAD")
        else:
            discarded, truncated = None, False  # unresolved target: say so
        payload.update({
            "target": target_raw,
            "target_sha": target_sha,
            "discarded_commits": discarded,
            "discarded_commits_truncated": truncated,
        })
        return payload

    async def validate(self, ctx: GitCommandContext, payload: dict[str, Any]) -> None:
        await super().validate(ctx, payload)
        if not _HARD_RE.search(payload["command"]):
            raise ValidationFailed("command does not look like a hard reset",
                                   code="command_kind_mismatch")


class RmRfAction(_CommandActionBase):
    """Recursive deletion: the payload binds the RESOLVED target paths
    (globs expanded relative to cwd; shell variables cannot be resolved
    safely and are marked), plus whether tracked git files are affected
    (when cwd is inside a repository — otherwise marked unknown)."""

    action_type = "rm_rf"
    feature_flag = "rm_rf_gate_enabled"
    _kind_re = _RM_RE

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        command = normalize_command(ctx.command)
        segment = _segment_after(command, lambda t: t == "rm" or t.endswith("/rm"))
        targets: list[dict[str, Any]] = []
        resolved_paths: list[str] = []
        for raw in segment:
            if raw.startswith("-"):
                continue
            if "$" in raw or "`" in raw:
                targets.append({"raw": raw, "resolved": None})  # unresolvable
                continue
            pattern = raw if os.path.isabs(raw) else os.path.join(ctx.cwd, raw)
            matches = sorted(glob.glob(pattern))
            targets.append({"raw": raw, "resolved": matches})
            resolved_paths.extend(matches)
        truncated = len(resolved_paths) > MAX_PATHS_IN_PAYLOAD
        resolved_paths = resolved_paths[:MAX_PATHS_IN_PAYLOAD]
        repo_root = await _git_optional(ctx.cwd, "rev-parse", "--show-toplevel")
        tracked: bool | None = None
        if repo_root is not None:
            tracked = False
            if resolved_paths:
                listed = await _git_optional(
                    ctx.cwd, "ls-files", "--", *resolved_paths)
                tracked = bool(listed)
        return {
            "action": self.action_type,
            "cwd": str(Path(ctx.cwd)),
            "repo_root": repo_root,
            "command": command,
            "targets": targets,
            "paths": resolved_paths,
            "paths_truncated": truncated,
            "tracked_paths_affected": tracked,  # None: not a git repository
        }


# --- deploy actions --------------------------------------------------------------
class KamalDeployAction(_GitActionBase):
    """``kamal deploy`` ships the current commit: the payload binds the
    HEAD SHA being deployed, the destination from the command (or None) and
    content hashes of the deploy configuration."""

    action_type = "kamal_deploy"
    feature_flag = "kamal_deploy_gate_enabled"
    _kind_re = _KAMAL_RE

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        payload = await super().derive(ctx)
        segment = _segment_after(payload["command"], lambda t: t == "kamal")
        destination = _flag_value(segment, "-d", "--destination")
        root = Path(payload["repo_root"])
        payload.update({
            "destination": destination,
            "deploy_config_path": "config/deploy.yml",
            "deploy_config_hash": _file_hash(root / "config" / "deploy.yml"),
        })
        if destination:
            payload["destination_config_hash"] = _file_hash(
                root / "config" / f"deploy.{destination}.yml")
        return payload


class DockerComposeUpAction(_CommandActionBase):
    """``docker compose up``: the payload binds content hashes of the
    resolved compose file(s) (the ``-f`` arguments, else the first default
    that exists), the services named in the command, and the ``.env``
    content hash if present — never any values."""

    action_type = "docker_compose_up"
    feature_flag = "docker_compose_up_gate_enabled"
    _kind_re = _UP_RE

    _DEFAULT_FILES = ("compose.yaml", "compose.yml",
                      "docker-compose.yml", "docker-compose.yaml")

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        command = normalize_command(ctx.command)
        cwd = Path(ctx.cwd)
        segment = _segment_after(
            command, lambda t: t in ("compose", "docker-compose"))
        files: list[dict[str, Any]] = []
        explicit: list[str] = []
        for i, token in enumerate(segment):
            if token in ("-f", "--file") and i + 1 < len(segment):
                explicit.append(segment[i + 1])
            elif token.startswith("--file="):
                explicit.append(token.split("=", 1)[1])
        if explicit:
            for raw in explicit:
                path = Path(raw) if os.path.isabs(raw) else cwd / raw
                files.append({"path": raw, "content_hash": _file_hash(path)})
        else:
            default = next(
                (name for name in self._DEFAULT_FILES if (cwd / name).is_file()), None)
            if default:
                files.append({"path": default,
                              "content_hash": _file_hash(cwd / default)})
            else:
                files.append({"path": UNRESOLVED, "content_hash": None})
        up_segment = _segment_after(command, lambda t: t == "up")
        services = [t for t in up_segment if not t.startswith("-")]
        env_path = cwd / ".env"
        return {
            "action": self.action_type,
            "cwd": str(cwd),
            "command": command,
            "compose_files": files,
            "services": services,
            "env_file_hash": _file_hash(env_path) if env_path.is_file() else None,
        }


class KubectlApplyAction(_CommandActionBase):
    """``kubectl apply -f``: the payload binds resolved manifest paths with
    per-manifest content hashes, and the target context/namespace from the
    command — WHICH CLUSTER matters to the operator, so an undeterminable
    context is written as "unresolved", never omitted. No cluster call is
    made (offline derivation)."""

    action_type = "kubectl_apply"
    feature_flag = "kubectl_apply_gate_enabled"
    _kind_re = _KUBECTL_RE

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        command = normalize_command(ctx.command)
        cwd = Path(ctx.cwd)
        segment = _segment_after(command, lambda t: t == "kubectl")
        raw_files: list[str] = []
        for i, token in enumerate(segment):
            if token in ("-f", "--filename") and i + 1 < len(segment):
                raw_files.append(segment[i + 1])
            elif token.startswith("--filename=") or token.startswith("-f="):
                raw_files.append(token.split("=", 1)[1])
        manifests: list[dict[str, Any]] = []
        for raw in raw_files:
            if raw == "-":
                manifests.append({"path": "-", "content_hash": None})  # stdin
                continue
            path = Path(raw) if os.path.isabs(raw) else cwd / raw
            if path.is_dir():
                for child in sorted(path.glob("*.y*ml"))[:MAX_MANIFESTS_IN_PAYLOAD]:
                    manifests.append({"path": str(Path(raw) / child.name),
                                      "content_hash": _file_hash(child)})
            else:
                manifests.append({"path": raw, "content_hash": _file_hash(path)})
        manifests = manifests[:MAX_MANIFESTS_IN_PAYLOAD]
        return {
            "action": self.action_type,
            "cwd": str(cwd),
            "command": command,
            "manifests": manifests,
            "context": _flag_value(segment, "--context") or UNRESOLVED,
            "namespace": _flag_value(segment, "-n", "--namespace") or UNRESOLVED,
        }


class GenericDeployScriptAction(_GitActionBase):
    """A named deploy script (``./deploy.sh``, ``make deploy``): the payload
    binds the content hash of the concrete, hashable artifact (script or
    Makefile) plus the git HEAD being deployed — deliberately never
    "whatever command"."""

    action_type = "deploy_script"
    feature_flag = "deploy_script_gate_enabled"
    _kind_re = None  # validated below (two shapes)

    async def derive(self, ctx: GitCommandContext) -> dict[str, Any]:
        payload = await super().derive(ctx)
        command = payload["command"]
        cwd = Path(ctx.cwd)
        match = _DEPLOY_SH_RE.search(command)
        if match:
            raw = next((t for t in _tokens(command) if t.endswith("deploy.sh")),
                       "deploy.sh")
            path = Path(raw) if os.path.isabs(raw) else cwd / raw
            payload.update({"script": raw, "script_hash": _file_hash(path),
                            "make_target": None})
        else:  # make deploy
            payload.update({"script": "Makefile",
                            "script_hash": _file_hash(cwd / "Makefile"),
                            "make_target": "deploy"})
        return payload

    async def validate(self, ctx: GitCommandContext, payload: dict[str, Any]) -> None:
        if not payload.get("command"):
            raise ValidationFailed("empty command", code="empty_command")
        command = payload["command"]
        if not (_DEPLOY_SH_RE.search(command)
                or ("make" in _tokens(command) and "deploy" in _tokens(command))):
            raise ValidationFailed("command does not look like a deploy script",
                                   code="command_kind_mismatch")


ACTIONS: dict[str, type[_CommandActionBase]] = {
    cls.action_type: cls
    for cls in (
        GitPushAction,
        GitForcePushAction,
        GitMergeAction,
        GitResetHardAction,
        RmRfAction,
        KamalDeployAction,
        DockerComposeUpAction,
        KubectlApplyAction,
        GenericDeployScriptAction,
    )
}
