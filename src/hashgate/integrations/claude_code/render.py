# SPDX-License-Identifier: Apache-2.0
"""Shared presentation logic — ONE truth for what the operator must see.

The CLI (`hashgate show`/`pending`/`history`) and the web UI render from the
SAME functions here, so a warning that exists in one surface exists in the
other (force-overwrite, unresolved cluster, tracked-files, denied-commit ⚠).

Pure presentation: no database access, no sqlalchemy import (the CLI must
stay importable without the server extra).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from hashgate.store import utcnow

UNRESOLVED_LABEL = "unresolved"


def short(value: Any, n: int = 12) -> str:
    return str(value)[:n] if value else UNRESOLVED_LABEL


def local_time(iso: str | None) -> str:
    """Operator-facing times: local with UTC in brackets. Evidence bundles
    stay pure UTC — proofs are timezone-proof and are not touched."""
    if not iso:
        return "-"
    dt = datetime.fromisoformat(iso)
    local = dt.astimezone()
    return (f"{local.strftime('%Y-%m-%d %H:%M:%S')} "
            f"(UTC {dt.astimezone(UTC).strftime('%H:%M:%S')})")


def expiry(iso: str | None) -> str:
    if not iso:
        return "-"
    remaining = int((datetime.fromisoformat(iso) - utcnow()).total_seconds())
    suffix = f" — in {remaining}s" if remaining > 0 else " — EXPIRED"
    return local_time(iso) + suffix


def age(iso: str) -> str:
    try:
        seconds = int((utcnow() - datetime.fromisoformat(iso)).total_seconds())
    except ValueError:
        return "?"
    return f"{seconds}s" if seconds < 120 else f"{seconds // 60}m"


def summary_lines(action_type: str, payload: dict[str, Any],
                  denied_heads: dict[str, tuple[str, str]]) -> list[str]:
    """Per-action prominent rendering: the operator sees WHAT the approval
    would cover before any raw payload dump."""
    lines: list[str] = []
    if action_type in ("git_push", "git_force_push"):
        if action_type == "git_force_push":
            lines.append(
                f"⚠ force-push ({payload.get('force_flag')}) overwrites "
                f"{short(payload.get('overwrites_remote_sha'))} on "
                f"{payload.get('remote_ref') or UNRESOLVED_LABEL}")
        commits = payload.get("commits") or []
        if commits:
            flag = " (list truncated)" if payload.get("commits_truncated") else ""
            lines.append(f"this push transports {len(commits)} commit(s){flag}:")
            for commit in commits:
                lines.append(f"  {commit['sha'][:12]}  {commit['subject']}")
                if commit["sha"] in denied_heads:
                    reason, at = denied_heads[commit["sha"]]
                    lines.append(
                        f"  ⚠ commit {commit['sha'][:12]} was HEAD of a denied "
                        f"push proposal — reason: '{reason}', at {local_time(at)}")
    elif action_type == "git_reset_hard":
        lines.append(
            f"⚠ reset --hard discards commits down to "
            f"{short(payload.get('target_sha'))} (target '{payload.get('target')}'), "
            f"current HEAD {short(payload.get('head_sha'))}")
        discarded = payload.get("discarded_commits")
        if discarded is None:
            lines.append("  discarded commits: unresolved (target did not resolve)")
        else:
            flag = " (list truncated)" \
                if payload.get("discarded_commits_truncated") else ""
            lines.append(f"  discards {len(discarded)} commit(s){flag}:")
            for commit in discarded:
                lines.append(f"    {commit['sha'][:12]}  {commit['subject']}")
    elif action_type == "rm_rf":
        paths = payload.get("paths") or []
        flag = " (list truncated)" if payload.get("paths_truncated") else ""
        lines.append(f"⚠ deletes {len(paths)} resolved path(s){flag}:")
        lines.extend(f"  {p}" for p in paths)
        for target in payload.get("targets") or []:
            if target.get("resolved") is None:
                lines.append(f"  ⚠ target '{target['raw']}' could not be "
                             "resolved (shell variable/substitution)")
        if payload.get("tracked_paths_affected"):
            lines.append("  ⚠ affects files tracked by git")
    elif action_type == "kamal_deploy":
        lines.append(
            f"deploys HEAD {short(payload.get('head_sha'))} "
            f"(branch {payload.get('branch')}) to destination "
            f"{payload.get('destination') or 'default'}")
        lines.append(
            f"  deploy config hash: {short(payload.get('deploy_config_hash'))}"
            + ("" if payload.get("deploy_config_hash")
               else "  ⚠ config/deploy.yml missing/unreadable"))
    elif action_type == "docker_compose_up":
        lines.append("docker compose up:")
        for entry in payload.get("compose_files") or []:
            lines.append(f"  file {entry['path']}: "
                         f"hash {short(entry.get('content_hash'))}")
        services = payload.get("services") or []
        lines.append(f"  services: {', '.join(services) if services else 'all'}")
        env_hash = payload.get("env_file_hash")
        lines.append(f"  .env hash: {short(env_hash) if env_hash else 'no .env'}")
    elif action_type == "kubectl_apply":
        context = payload.get("context")
        namespace = payload.get("namespace")
        warn = "  ⚠ target cluster not determinable from the command" \
            if context == UNRESOLVED_LABEL else ""
        lines.append(f"kubectl apply → context: {context}, "
                     f"namespace: {namespace}{warn}")
        for manifest in payload.get("manifests") or []:
            lines.append(f"  manifest {manifest['path']}: "
                         f"hash {short(manifest.get('content_hash'))}")
    elif action_type == "deploy_script":
        target = " (make deploy)" if payload.get("make_target") else ""
        lines.append(
            f"runs deploy artifact {payload.get('script')}{target}, "
            f"hash {short(payload.get('script_hash'))}, "
            f"at HEAD {short(payload.get('head_sha'))}"
            + ("" if payload.get("script_hash")
               else "  ⚠ artifact missing/unreadable"))
    return lines
