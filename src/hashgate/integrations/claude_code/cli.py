# SPDX-License-Identifier: Apache-2.0
"""Operator CLI: pending / show / accept / deny / bundle.

Talks directly to the gate database (no server round-trip). The accept
requires the FULL payload hash as an explicit echo argument — a blind
``accept <id>`` does not exist by design: the echo is the operator's
cryptographic statement of what they reviewed.

Environment:
    HASHGATE_DB         database path (default ~/.hashgate/hooks.db)
    HASHGATE_OPERATOR   operator id (default operator:<username>)
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hashgate.adapters.sqlalchemy_store import PreviewRow, SQLAlchemyStore
from hashgate.adapters.sqlalchemy_store import create_all as create_core_tables
from hashgate.errors import EvidenceNotFound
from hashgate.evidence import EvidenceExporter
from hashgate.integrations.claude_code.approvals import (
    DECISION_APPROVED,
    DECISION_DENIED,
    ApprovalService,
    ClaudeCodeBase,
    is_expired,
)
from hashgate.store import utcnow

DEFAULT_DB_PATH = "~/.hashgate/hooks.db"


def _operator_id() -> str:
    return os.environ.get("HASHGATE_OPERATOR") or f"operator:{getpass.getuser()}"


async def _open(db_path: str):
    db_file = Path(db_path).expanduser()
    db_file.parent.mkdir(parents=True, exist_ok=True)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    await create_core_tables(engine)
    async with engine.begin() as conn:
        await conn.run_sync(ClaudeCodeBase.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    store = SQLAlchemyStore(sessionmaker)
    return sessionmaker, store, ApprovalService(sessionmaker, store)


def _age(iso: str) -> str:
    try:
        seconds = int((utcnow() - datetime.fromisoformat(iso)).total_seconds())
    except ValueError:
        return "?"
    return f"{seconds}s" if seconds < 120 else f"{seconds // 60}m"


async def cmd_pending(args: argparse.Namespace) -> int:
    sessionmaker, _store, approvals = await _open(args.db)
    async with sessionmaker() as session:
        previews = (await session.execute(
            select(PreviewRow).order_by(PreviewRow.derived_at))).scalars().all()
    shown = 0
    for row in previews:
        approval = await approvals.latest_for_preview(row.preview_id)
        if approval is not None and (
            approval.decision == DECISION_DENIED
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


async def cmd_show(args: argparse.Namespace) -> int:
    sessionmaker, _store, approvals = await _open(args.db)
    async with sessionmaker() as session:
        row = await session.get(PreviewRow, args.preview_id)
    if row is None:
        print(f"unknown preview {args.preview_id}", file=sys.stderr)
        return 1
    approval = await approvals.latest_for_preview(row.preview_id)
    print(json.dumps({
        "preview_id": row.preview_id,
        "action_type": row.action_type,
        "payload": row.payload,
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
    sessionmaker, _store, approvals = await _open(args.db)
    async with sessionmaker() as session:
        row = await session.get(PreviewRow, args.preview_id)
    if row is None:
        print(f"unknown preview {args.preview_id}", file=sys.stderr)
        return 1
    if decision == DECISION_APPROVED:
        echoed = str(args.hash or "").strip()
        if echoed != row.payload_hash:
            print("hash echo mismatch: the --hash argument must be the FULL "
                  f"payload hash of the preview\n  expected: {row.payload_hash}\n"
                  f"  got:      {echoed or '(empty)'}", file=sys.stderr)
            return 1
    existing = await approvals.latest_for_preview(row.preview_id)
    if existing is not None and existing.decision == DECISION_APPROVED \
            and not existing.consumed_at and not is_expired(existing):
        print(f"preview already has an open approval {existing.id} "
              f"(expires {existing.expires_at})", file=sys.stderr)
        return 1
    reason = args.reason or (
        "approved via hashgate CLI" if decision == DECISION_APPROVED else "")
    if not reason:
        print("--reason is required", file=sys.stderr)
        return 1
    approval = await approvals.decide(
        preview_id=row.preview_id, chain_id=row.chain_id,
        action_type=row.action_type, payload_hash=row.payload_hash,
        decision=decision, operator_id=_operator_id(), reason=reason,
        ttl_seconds=args.ttl if decision == DECISION_APPROVED else None,
    )
    if decision == DECISION_APPROVED:
        print(f"approved {row.preview_id} as {approval.id} "
              f"(single-use, expires {approval.expires_at})")
        print("the agent can retry the command now")
    else:
        print(f"denied {row.preview_id} as {approval.id}: {reason}")
    return 0


async def cmd_accept(args: argparse.Namespace) -> int:
    return await _decide(args, DECISION_APPROVED)


async def cmd_deny(args: argparse.Namespace) -> int:
    return await _decide(args, DECISION_DENIED)


async def cmd_bundle(args: argparse.Namespace) -> int:
    sessionmaker, store, _approvals = await _open(args.db)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashgate",
        description="operator CLI for the hashgate Claude Code gate")
    parser.add_argument("--db", default=os.environ.get("HASHGATE_DB", DEFAULT_DB_PATH))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("pending", help="list previews awaiting an operator decision")

    show = sub.add_parser("show", help="show one preview's full payload")
    show.add_argument("preview_id")

    accept = sub.add_parser("accept", help="approve a preview (hash echo mandatory)")
    accept.add_argument("preview_id")
    accept.add_argument("--hash", required=True,
                        help="FULL payload hash of the preview (explicit echo)")
    accept.add_argument("--reason", default=None)
    accept.add_argument("--ttl", type=int, default=None,
                        help="approval lifetime in seconds (default 900)")

    deny = sub.add_parser("deny", help="deny a preview")
    deny.add_argument("preview_id")
    deny.add_argument("--reason", required=True)

    bundle = sub.add_parser("bundle", help="export the oversight bundle of a chain")
    bundle.add_argument("chain_id", help="chain id (or a preview id)")
    bundle.add_argument("--out", default=None)

    return parser


_COMMANDS = {
    "pending": cmd_pending,
    "show": cmd_show,
    "accept": cmd_accept,
    "deny": cmd_deny,
    "bundle": cmd_bundle,
}


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    sys.exit(asyncio.run(_COMMANDS[args.command](args)))


if __name__ == "__main__":
    main()
