# SPDX-License-Identifier: Apache-2.0
"""Operator approvals for hook-gated actions — integration-owned storage.

An approval is the operator's recorded, hash-bound decision: it references a
preview, echoes its payload hash, expires (default 15 minutes) and is
consumed atomically exactly once. The core library is unchanged: approvals
live in their own table next to the hashgate tables in the same SQLite file.

Approval lifecycle events (operator_approved / operator_denied /
approval_stale) are appended to the preview's evidence chain, so exported
bundles tell the whole story including the operator's decision.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import String, Text, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from hashgate.errors import EvidenceNotFound
from hashgate.evidence import order_chain_events
from hashgate.redact import redact_payload
from hashgate.store import Store, new_id, utcnow

DECISION_APPROVED = "approved"
DECISION_DENIED = "denied"
#: hash-bound permanent denial: THIS exact state is never asked about again.
#: Deliberately bound to the payload_hash, not to content — a changed state
#: (amend/rebase/new commit) is a NEW decision, which is what the promise
#: can actually keep. Stored as a decision value: no schema change.
DECISION_DENIED_FINAL = "denied_final"

DEFAULT_TTL_SECONDS = 900  # 15 minutes


class ClaudeCodeBase(DeclarativeBase):
    """Integration-owned metadata (kept out of the core hashgate tables)."""


class HookApprovalRow(ClaudeCodeBase):
    __tablename__ = "hashgate_cc_hook_approvals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    preview_id: Mapped[str] = mapped_column(String(64), index=True)
    chain_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_type: Mapped[str] = mapped_column(String(120), index=True)
    payload_hash: Mapped[str] = mapped_column(String(128), index=True)
    decision: Mapped[str] = mapped_column(String(20))
    operator_id: Mapped[str] = mapped_column(String(160))
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    consumed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)


def is_expired(row: HookApprovalRow, now: datetime | None = None) -> bool:
    if not row.expires_at:
        return False
    return (now or utcnow()) >= datetime.fromisoformat(row.expires_at)


async def append_chain_event(store: Store, chain_id: str, kind: str,
                             **fields: Any) -> str:
    """Append one linked event to an existing evidence chain."""
    events = await store.list_chain_events(chain_id)
    try:
        ordered = order_chain_events(events)
    except EvidenceNotFound:
        ordered = events
    prev = str(ordered[-1]["event_id"]) if ordered else None
    event = {
        "event_id": new_id(),
        "chain_id": chain_id,
        "prev_event_id": prev,
        "kind": kind,
        "at": utcnow().isoformat(),
        **redact_payload(fields),
    }
    return await store.append_audit(event)


class ApprovalService:
    def __init__(self, sessionmaker: async_sessionmaker, store: Store,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._sessionmaker = sessionmaker
        self._store = store
        self.ttl_seconds = int(ttl_seconds)

    async def decide(self, *, preview_id: str, chain_id: str | None,
                     action_type: str, payload_hash: str, decision: str,
                     operator_id: str, reason: str,
                     ttl_seconds: int | None = None,
                     final: bool = False) -> HookApprovalRow:
        now = utcnow()
        ttl = self.ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        if final and decision == DECISION_DENIED:
            decision = DECISION_DENIED_FINAL
        row = HookApprovalRow(
            id=new_id(),
            preview_id=preview_id,
            chain_id=chain_id,
            action_type=action_type,
            payload_hash=payload_hash,
            decision=decision,
            operator_id=str(operator_id)[:160],
            reason=str(reason)[:2000],
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl)).isoformat()
            if decision == DECISION_APPROVED else None,
        )
        async with self._sessionmaker() as session:
            session.add(row)
            await session.commit()
        if chain_id:
            event_kind = {
                DECISION_APPROVED: "operator_approved",
                DECISION_DENIED: "operator_denied",
                DECISION_DENIED_FINAL: "denied_final",
            }[decision]
            await append_chain_event(
                self._store, chain_id, event_kind,
                action_type=action_type, channel="cli",
                approval_id=row.id, operator_id=row.operator_id, reason=row.reason,
                payload_hash=payload_hash, expires_at=row.expires_at,
            )
        return row

    async def latest_for_hash(self, action_type: str,
                              payload_hash: str) -> HookApprovalRow | None:
        async with self._sessionmaker() as session:
            return (
                await session.execute(
                    select(HookApprovalRow)
                    .where(HookApprovalRow.action_type == action_type,
                           HookApprovalRow.payload_hash == payload_hash)
                    .order_by(HookApprovalRow.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()

    async def latest_for_preview(self, preview_id: str) -> HookApprovalRow | None:
        async with self._sessionmaker() as session:
            return (
                await session.execute(
                    select(HookApprovalRow)
                    .where(HookApprovalRow.preview_id == preview_id)
                    .order_by(HookApprovalRow.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()

    async def open_approvals_for_action(self, action_type: str) -> list[HookApprovalRow]:
        """Approved, unconsumed, unexpired approvals for one action type."""
        async with self._sessionmaker() as session:
            rows = (
                await session.execute(
                    select(HookApprovalRow)
                    .where(HookApprovalRow.action_type == action_type,
                           HookApprovalRow.decision == DECISION_APPROVED,
                           HookApprovalRow.consumed_at.is_(None))
                )
            ).scalars().all()
        return [r for r in rows if not is_expired(r)]

    async def mark_consumed(self, approval_id: str) -> bool:
        """Atomic single-use: UPDATE … WHERE consumed_at IS NULL."""
        async with self._sessionmaker() as session:
            result = await session.execute(
                update(HookApprovalRow)
                .where(HookApprovalRow.id == approval_id,
                       HookApprovalRow.consumed_at.is_(None))
                .values(consumed_at=utcnow().isoformat())
            )
            await session.commit()
            return result.rowcount == 1
