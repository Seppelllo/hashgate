# SPDX-License-Identifier: Apache-2.0
"""Operator CLI: pending / show / accept / deny / history / bundle.

Talks directly to the gate database (no server round-trip) and reads the
SAME configuration source as the server (env > ~/.hashgate/config.toml >
default) — the approval TTL is therefore identical no matter which terminal
runs what. Best effort, the CLI asks the running server (/health) whether
both point at the same database and warns on divergence.

The accept requires the FULL payload hash as an explicit echo argument — a
blind ``accept <id>`` does not exist by design: the echo is the operator's
cryptographic statement of what they reviewed. (The web UI uses a typed
12-hex prefix instead; the CLI keeps the full hash.)

Presentation (summary warnings, times, outcomes) is shared with the web UI
via ``render.py``/``approvals.py`` — one truth for what the operator sees.
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
from pathlib import Path

from hashgate.errors import EvidenceNotFound
from hashgate.evidence import EvidenceExporter
from hashgate.integrations.claude_code.config import GateConfig, load_config
from hashgate.integrations.claude_code.render import age, expiry, local_time, summary_lines

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
        denied_head_map,
        is_expired,
        outcome_for_preview,
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
        print(f"{row.preview_id}  {row.action_type:10s}  age={age(row.derived_at):>4s}  "
              f"hash={row.payload_hash}")
        print(f"    {command}")
    if shown == 0:
        print("no pending previews")
    return 0


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
    denied_heads = await denied_head_map(sessionmaker) \
        if payload.get("commits") else {}
    summary = summary_lines(row.action_type, payload, denied_heads)
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
              f"(expires {expiry(existing.expires_at)}).")
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
              f"(single-use, expires {expiry(approval.expires_at)})")
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
        outcome, decided_at, deny_reason = await outcome_for_preview(
            store, approvals, row)
        head = str((row.payload or {}).get("head_sha") or "")[:12] or "-"
        line = (f"{row.preview_id[:12]}  {row.action_type:10s}  {outcome:8s}  "
                f"decided={local_time(decided_at)}  head={head}")
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
