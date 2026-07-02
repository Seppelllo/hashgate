# SPDX-License-Identifier: Apache-2.0
"""Operator CLI: pending / show / accept / deny / history / bundle.

Talks directly to the gate database (no server round-trip) and reads the
SAME configuration source as the server (env > ~/.hashgate/config.toml >
default) — the approval TTL is therefore identical no matter which terminal
runs what. Best effort, the CLI asks the running server (/health) whether
both point at the same database and warns on divergence.

The accept requires the FULL payload hash as an explicit echo argument — a
blind ``accept <id>`` does not exist by design: the echo is the operator's
cryptographic statement of what they reviewed.

Operator-facing times are shown in LOCAL time with UTC in brackets (and a
countdown for expiries). Evidence bundles and audit events stay pure UTC —
proofs are timezone-proof and are not touched.
"""
from __future__ import annotations

import argparse
import asyncio
import difflib
import getpass
import json
import os
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from hashgate.errors import EvidenceNotFound
from hashgate.evidence import EvidenceExporter
from hashgate.integrations.claude_code.config import GateConfig, load_config
from hashgate.store import utcnow

# The console script is installed even without the 'server' extra; die with
# instructions instead of a raw ImportError traceback (checked in main()).
_EXTRA_HINT = ("hashgate: this command requires the server extra — "
               "install with: pip install 'hashgate[server]'")
try:
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from hashgate.adapters.sqlalchemy_store import PreviewRow, SQLAlchemyStore
    from hashgate.adapters.sqlalchemy_store import create_all as create_core_tables
    from hashgate.integrations.claude_code.approvals import (
        DECISION_APPROVED,
        DECISION_DENIED,
        DECISION_DENIED_FINAL,
        ApprovalService,
        ClaudeCodeBase,
        HookApprovalRow,
        is_expired,
    )
    _IMPORT_ERROR: ModuleNotFoundError | None = None
except ModuleNotFoundError as exc:
    _IMPORT_ERROR = exc

_HASH_LEN = 64


def _operator_id() -> str:
    return os.environ.get("HASHGATE_OPERATOR") or f"operator:{getpass.getuser()}"


async def _open(cfg: GateConfig, db_override: str | None):
    db_file = Path(db_override or cfg.resolved_db_path).expanduser()
    db_file.parent.mkdir(parents=True, exist_ok=True)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    await create_core_tables(engine)
    async with engine.begin() as conn:
        await conn.run_sync(ClaudeCodeBase.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    store = SQLAlchemyStore(sessionmaker)
    return sessionmaker, store, ApprovalService(sessionmaker, store,
                                                ttl_seconds=cfg.ttl_seconds)


def _warn_if_server_db_differs(cfg: GateConfig, db_override: str | None) -> None:
    """Best effort: if the server runs, make sure we look at the same DB."""
    cli_db = str(Path(db_override or cfg.resolved_db_path).expanduser())
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{cfg.port}/health", timeout=1) as response:
            info = json.loads(response.read().decode())
    except Exception:
        return  # server not running / unreachable — nothing to check
    server_db = info.get("db")
    if server_db and server_db != cli_db:
        print(f"warning: the gate server uses db={server_db} but this CLI uses "
              f"db={cli_db} — your decision will NOT be visible to the server. "
              "Check HASHGATE_DB / config.toml.", file=sys.stderr)


# --- time rendering (operator-facing: local + UTC + countdown) ----------------
def _local(iso: str | None) -> str:
    if not iso:
        return "-"
    dt = datetime.fromisoformat(iso)
    local = dt.astimezone()
    return f"{local.strftime('%Y-%m-%d %H:%M:%S')} (UTC {dt.astimezone(UTC).strftime('%H:%M:%S')})"


def _expiry(iso: str | None) -> str:
    if not iso:
        return "-"
    remaining = int((datetime.fromisoformat(iso) - utcnow()).total_seconds())
    suffix = f" — in {remaining}s" if remaining > 0 else " — EXPIRED"
    return _local(iso) + suffix


def _age(iso: str) -> str:
    try:
        seconds = int((utcnow() - datetime.fromisoformat(iso)).total_seconds())
    except ValueError:
        return "?"
    return f"{seconds}s" if seconds < 120 else f"{seconds // 60}m"


# --- outcome classification (history) -----------------------------------------
async def _outcome(store, approvals, row: PreviewRow):
    """(outcome, decided_at, deny_reason) for one preview."""
    approval = await approvals.latest_for_preview(row.preview_id)
    if approval is None:
        return "pending", None, None
    if approval.decision == DECISION_DENIED_FINAL:
        return "denied_final", approval.created_at, approval.reason
    if approval.decision == DECISION_DENIED:
        return "denied", approval.created_at, approval.reason
    if approval.consumed_at:
        return "applied", approval.consumed_at, None
    if is_expired(approval):
        return "expired", approval.created_at, None
    if row.chain_id:
        events = await store.list_chain_events(row.chain_id)
        if any(e.get("kind") == "approval_stale" for e in events):
            return "stale", approval.created_at, None
    return "approved", approval.created_at, None


async def _denied_head_map(sessionmaker) -> dict[str, tuple[str, str]]:
    """head_sha of previously DENIED push proposals -> (reason, decided_at)."""
    async with sessionmaker() as session:
        denied = (await session.execute(
            select(HookApprovalRow)
            .where(HookApprovalRow.decision == DECISION_DENIED))).scalars().all()
        result: dict[str, tuple[str, str]] = {}
        for approval in denied:
            preview = await session.get(PreviewRow, approval.preview_id)
            head = ((preview.payload or {}).get("head_sha")
                    if preview is not None else None)
            if head:
                result[head] = (approval.reason, approval.created_at)
    return result


# --- commands -------------------------------------------------------------------
async def cmd_pending(args: argparse.Namespace) -> int:
    cfg = load_config()
    sessionmaker, _store, approvals = await _open(cfg, args.db)
    async with sessionmaker() as session:
        previews = (await session.execute(
            select(PreviewRow).order_by(PreviewRow.derived_at))).scalars().all()
    shown = 0
    for row in previews:
        approval = await approvals.latest_for_preview(row.preview_id)
        if approval is not None and (
            approval.decision in (DECISION_DENIED, DECISION_DENIED_FINAL)
            or approval.consumed_at
            or (approval.decision == DECISION_APPROVED and not is_expired(approval))
        ):
            continue  # decided/consumed/currently-approved -> not pending
        shown += 1
        command = (row.payload or {}).get("command", "")
        print(f"{row.preview_id}  {row.action_type:10s}  age={_age(row.derived_at):>4s}  "
              f"hash={row.payload_hash}")
        print(f"    {command}")
    if shown == 0:
        print("no pending previews")
    return 0


def _short(value, n: int = 12) -> str:
    return str(value)[:n] if value else UNRESOLVED_LABEL


UNRESOLVED_LABEL = "unresolved"


def _summary_lines(action_type: str, payload: dict,
                   denied_heads: dict) -> list[str]:
    """Per-action prominent rendering: the operator sees WHAT the approval
    would cover before the JSON dump."""
    lines: list[str] = []
    if action_type in ("git_push", "git_force_push"):
        if action_type == "git_force_push":
            lines.append(
                f"⚠ force-push ({payload.get('force_flag')}) overwrites "
                f"{_short(payload.get('overwrites_remote_sha'))} on "
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
                        f"push proposal — reason: '{reason}', at {_local(at)}")
    elif action_type == "git_reset_hard":
        lines.append(
            f"⚠ reset --hard discards commits down to "
            f"{_short(payload.get('target_sha'))} (target '{payload.get('target')}'), "
            f"current HEAD {_short(payload.get('head_sha'))}")
        discarded = payload.get("discarded_commits")
        if discarded is None:
            lines.append("  discarded commits: unresolved (target did not resolve)")
        else:
            flag = " (list truncated)" if payload.get("discarded_commits_truncated") else ""
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
            f"deploys HEAD {_short(payload.get('head_sha'))} "
            f"(branch {payload.get('branch')}) to destination "
            f"{payload.get('destination') or 'default'}")
        lines.append(
            f"  deploy config hash: {_short(payload.get('deploy_config_hash'))}"
            + ("" if payload.get("deploy_config_hash")
               else "  ⚠ config/deploy.yml missing/unreadable"))
    elif action_type == "docker_compose_up":
        lines.append("docker compose up:")
        for entry in payload.get("compose_files") or []:
            lines.append(f"  file {entry['path']}: "
                         f"hash {_short(entry.get('content_hash'))}")
        services = payload.get("services") or []
        lines.append(f"  services: {', '.join(services) if services else 'all'}")
        env_hash = payload.get("env_file_hash")
        lines.append(f"  .env hash: {_short(env_hash) if env_hash else 'no .env'}")
    elif action_type == "kubectl_apply":
        context = payload.get("context")
        namespace = payload.get("namespace")
        warn = "  ⚠ target cluster not determinable from the command" \
            if context == UNRESOLVED_LABEL else ""
        lines.append(f"kubectl apply → context: {context}, "
                     f"namespace: {namespace}{warn}")
        for manifest in payload.get("manifests") or []:
            lines.append(f"  manifest {manifest['path']}: "
                         f"hash {_short(manifest.get('content_hash'))}")
    elif action_type == "deploy_script":
        target = " (make deploy)" if payload.get("make_target") else ""
        lines.append(
            f"runs deploy artifact {payload.get('script')}{target}, "
            f"hash {_short(payload.get('script_hash'))}, "
            f"at HEAD {_short(payload.get('head_sha'))}"
            + ("" if payload.get("script_hash")
               else "  ⚠ artifact missing/unreadable"))
    return lines


async def cmd_show(args: argparse.Namespace) -> int:
    if not args.preview_id:
        return await cmd_pending(args)  # bare 'show' = what needs my decision?
    cfg = load_config()
    sessionmaker, _store, approvals = await _open(cfg, args.db)
    async with sessionmaker() as session:
        row = await session.get(PreviewRow, args.preview_id)
    if row is None:
        print(f"unknown preview {args.preview_id}", file=sys.stderr)
        return 1
    payload = row.payload or {}
    denied_heads = await _denied_head_map(sessionmaker) \
        if payload.get("commits") else {}
    summary = _summary_lines(row.action_type, payload, denied_heads)
    if summary:
        for line in summary:
            print(line)
        print()
    approval = await approvals.latest_for_preview(row.preview_id)
    print(json.dumps({
        "preview_id": row.preview_id,
        "action_type": row.action_type,
        "payload": payload,
        "payload_hash": row.payload_hash,
        "canon_version": row.canon_version,
        "derived_at": row.derived_at,
        "chain_id": row.chain_id,
        "operator": {"operator_id": row.operator_id, "channel": row.channel},
        "approval": None if approval is None else {
            "id": approval.id, "decision": approval.decision,
            "operator_id": approval.operator_id, "expires_at": approval.expires_at,
            "consumed_at": approval.consumed_at,
            "expired": is_expired(approval),
        },
    }, indent=2, ensure_ascii=False))
    return 0


async def _decide(args: argparse.Namespace, decision: str) -> int:
    cfg = load_config()
    sessionmaker, _store, approvals = await _open(cfg, args.db)
    async with sessionmaker() as session:
        row = await session.get(PreviewRow, args.preview_id)
    if row is None:
        print(f"unknown preview {args.preview_id}", file=sys.stderr)
        return 1
    if decision == DECISION_APPROVED:
        echoed = str(args.hash or "").strip()
        if echoed != row.payload_hash:
            print(f"hash echo mismatch: --hash must be the FULL {_HASH_LEN}-character "
                  f"payload hash of the preview (you passed {len(echoed)} characters).\n"
                  f"Find it via 'hashgate pending' or 'hashgate show {row.preview_id}'.\n"
                  f"  expected: {row.payload_hash}\n"
                  f"  got:      {echoed or '(empty)'}", file=sys.stderr)
            return 1
    # ONE path for repeated decisions: an open approval is reported, never
    # silently re-issued (and never re-printed as if freshly approved)
    existing = await approvals.latest_for_preview(row.preview_id)
    if existing is not None and existing.decision == DECISION_DENIED_FINAL:
        print(f"this exact state was FINALLY denied as {existing.id} "
              f"({existing.reason}) — a changed state (new commit/amend) "
              "is a new decision", file=sys.stderr)
        return 1
    if existing is not None and existing.decision == DECISION_APPROVED \
            and not existing.consumed_at and not is_expired(existing):
        print(f"preview already has an open approval {existing.id} "
              f"(expires {_expiry(existing.expires_at)}).")
        print("the agent can retry the command now")
        return 0  # idempotent: nothing changed, nothing re-issued
    reason = args.reason or (
        "approved via hashgate CLI" if decision == DECISION_APPROVED else "")
    if not reason:
        print("--reason is required", file=sys.stderr)
        return 1
    _warn_if_server_db_differs(cfg, args.db)
    final = bool(getattr(args, "final", False))
    approval = await approvals.decide(
        preview_id=row.preview_id, chain_id=row.chain_id,
        action_type=row.action_type, payload_hash=row.payload_hash,
        decision=decision, operator_id=_operator_id(), reason=reason,
        ttl_seconds=args.ttl if decision == DECISION_APPROVED else None,
        final=final,
    )
    if decision == DECISION_APPROVED:
        print(f"approved {row.preview_id} as {approval.id} "
              f"(single-use, expires {_expiry(approval.expires_at)})")
        print("the agent can retry the command now")
    elif final:
        print(f"FINALLY denied {row.preview_id} as {approval.id}: {reason}")
        print(f"this exact state (hash {row.payload_hash[:12]}…) will never "
              "be approved; a changed state is a new decision")
    else:
        print(f"denied {row.preview_id} as {approval.id}: {reason}")
    return 0


async def cmd_accept(args: argparse.Namespace) -> int:
    return await _decide(args, DECISION_APPROVED)


async def cmd_deny(args: argparse.Namespace) -> int:
    return await _decide(args, DECISION_DENIED)


async def cmd_history(args: argparse.Namespace) -> int:
    cfg = load_config()
    sessionmaker, store, approvals = await _open(cfg, args.db)
    async with sessionmaker() as session:
        previews = (await session.execute(
            select(PreviewRow).order_by(PreviewRow.derived_at.desc())
            .limit(max(1, args.limit)))).scalars().all()
    if not previews:
        print("no previews recorded")
        return 0
    for row in previews:
        outcome, decided_at, deny_reason = await _outcome(store, approvals, row)
        head = str((row.payload or {}).get("head_sha") or "")[:12] or "-"
        line = (f"{row.preview_id[:12]}  {row.action_type:10s}  {outcome:8s}  "
                f"decided={_local(decided_at)}  head={head}")
        if deny_reason:
            line += f"  reason='{deny_reason}'"
        print(line)
    return 0


async def cmd_bundle(args: argparse.Namespace) -> int:
    cfg = load_config()
    sessionmaker, store, _approvals = await _open(cfg, args.db)
    chain_id = args.chain_id
    async with sessionmaker() as session:  # allow a preview id as convenience
        row = await session.get(PreviewRow, chain_id)
    if row is not None and row.chain_id:
        chain_id = row.chain_id
    try:
        bundle = await EvidenceExporter(store=store) \
            .export_oversight_bundle_by_chain(chain_id)
    except EvidenceNotFound as exc:
        print(f"no bundle: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out} (outcome={bundle['outcome']}, "
              f"bundle_hash={bundle['bundle_hash'][:16]}…)")
    else:
        print(text)
    return 0


class _Parser(argparse.ArgumentParser):
    """argparse with 'did you mean …?' for mistyped subcommands."""

    def error(self, message: str) -> None:  # type: ignore[override]
        match = re.search(r"invalid choice: '([^']+)'", message)
        if match:
            close = difflib.get_close_matches(match.group(1), list(_COMMANDS), n=1)
            if close:
                self.exit(2, f"{self.prog}: error: {message}\n"
                             f"did you mean '{close[0]}'?\n")
        super().error(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="hashgate",
        description="operator CLI for the hashgate Claude Code gate")
    parser.add_argument("--db", default=os.environ.get("HASHGATE_DB") or None,
                        help="database path (default: shared config)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("pending", help="list previews awaiting an operator decision")

    show = sub.add_parser("show", help="show one preview's full payload")
    show.add_argument("preview_id", nargs="?", default=None,
                      help="omit to list pending previews")

    accept = sub.add_parser("accept", help="approve a preview (hash echo mandatory)")
    accept.add_argument("preview_id")
    accept.add_argument("--hash", required=True,
                        help="FULL 64-character payload hash (explicit echo)")
    accept.add_argument("--reason", default=None)
    accept.add_argument("--ttl", type=int, default=None,
                        help="approval lifetime in seconds (default: shared config)")

    deny = sub.add_parser("deny", help="deny a preview")
    deny.add_argument("preview_id")
    deny.add_argument("--reason", required=True)
    deny.add_argument("--final", action="store_true",
                      help="bind the denial to this exact payload hash: the "
                           "identical state is never asked about again (a "
                           "changed state is a new decision)")

    history = sub.add_parser("history", help="past previews and their outcomes")
    history.add_argument("--limit", type=int, default=20)

    bundle = sub.add_parser("bundle", help="export the oversight bundle of a chain")
    bundle.add_argument("chain_id", help="chain id (or a preview id)")
    bundle.add_argument("--out", default=None)

    return parser


_COMMANDS = {
    "pending": cmd_pending,
    "show": cmd_show,
    "accept": cmd_accept,
    "deny": cmd_deny,
    "history": cmd_history,
    "bundle": cmd_bundle,
}


def main(argv: list[str] | None = None) -> None:
    if _IMPORT_ERROR is not None:
        print(_EXTRA_HINT, file=sys.stderr)
        sys.exit(1)
    args = build_parser().parse_args(argv)
    sys.exit(asyncio.run(_COMMANDS[args.command](args)))


if __name__ == "__main__":
    main()
