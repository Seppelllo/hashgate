# SPDX-License-Identifier: Apache-2.0
"""SQLAlchemy (async) reference implementation of the :class:`hashgate.store.Store`
protocol.

Extraction lineage: the idempotency claim is the DB-hard variant of the
source project's atomic single-use consume mutex — here as an INSERT against
a UNIQUE constraint, which is the correct primitive for a pure key claim (the
``UPDATE … WHERE consumed_at IS NULL`` form applies to consumable rows and
returns in approval-shaped flows later). A losing racer gets a clean
``False``, never a raw IntegrityError.

Timestamps are stored as ISO-8601 strings (exact, timezone-preserving
round-trip on every backend, including SQLite).

Requires the optional ``hashgate[sqlalchemy]`` extra (sqlalchemy>=2.0).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, Text, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from hashgate.store import new_id, utcnow
from hashgate.types import ApplyResult, ApplyStatus, OperatorContext, Preview


class HashgateBase(DeclarativeBase):
    """Separate metadata — hashgate tables never mix into the host app's Base."""


class PreviewRow(HashgateBase):
    __tablename__ = "hashgate_previews"

    preview_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_type: Mapped[str] = mapped_column(String(120), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    payload_hash: Mapped[str] = mapped_column(String(128), index=True)
    canon_version: Mapped[str] = mapped_column(String(64))
    derived_at: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    operator_id: Mapped[str] = mapped_column(String(160))
    reason: Mapped[str] = mapped_column(Text)
    channel: Mapped[str] = mapped_column(String(64))
    chain_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class IdempotencyClaimRow(HashgateBase):
    __tablename__ = "hashgate_idempotency_claims"
    __table_args__ = (UniqueConstraint("key", name="uq_hashgate_idempotency_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(400))
    claimed_at: Mapped[str] = mapped_column(String(64))


class ApplyRow(HashgateBase):
    __tablename__ = "hashgate_applies"

    apply_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_type: Mapped[str] = mapped_column(String(120), index=True)
    status: Mapped[str] = mapped_column(String(40))
    payload_hash: Mapped[str] = mapped_column(String(128), index=True)
    effects: Mapped[dict[str, Any]] = mapped_column(JSON)
    audit_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64))


class AuditEventRow(HashgateBase):
    __tablename__ = "hashgate_audit_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # chain linkage (preview -> accept/refuse -> apply); populated by the gate
    chain_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    prev_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    operator_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    channel: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64))
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


async def create_all(engine: AsyncEngine) -> None:
    """Create the hashgate tables (idempotent)."""
    async with engine.begin() as conn:
        await conn.run_sync(HashgateBase.metadata.create_all)


_EVENT_COLUMNS = (
    "chain_id",
    "prev_event_id",
    "kind",
    "action_type",
    "operator_id",
    "reason",
    "channel",
    "payload_hash",
)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class SQLAlchemyStore:
    """Async SQLAlchemy store; every call runs in its own short session."""

    def __init__(self, sessionmaker: async_sessionmaker) -> None:
        self._sessionmaker = sessionmaker

    async def save_preview(self, preview: Preview) -> None:
        async with self._sessionmaker() as session:
            existing = await session.get(PreviewRow, preview.preview_id)
            if existing is not None:
                return  # idempotent on preview_id
            session.add(
                PreviewRow(
                    preview_id=preview.preview_id,
                    action_type=preview.action_type,
                    payload=preview.payload,
                    payload_hash=preview.payload_hash,
                    canon_version=preview.canon_version,
                    derived_at=_iso(preview.derived_at) or "",
                    expires_at=_iso(preview.expires_at),
                    frozen=bool(preview.frozen),
                    operator_id=preview.operator.operator_id,
                    reason=preview.operator.reason,
                    channel=preview.operator.channel,
                    chain_id=preview.chain_id,
                )
            )
            await session.commit()

    async def load_preview(self, preview_id: str) -> Preview | None:
        async with self._sessionmaker() as session:
            row = await session.get(PreviewRow, preview_id)
            return self._to_preview(row) if row is not None else None

    async def find_preview_by_hash(self, action_type: str, payload_hash: str) -> Preview | None:
        async with self._sessionmaker() as session:
            row = (
                await session.execute(
                    select(PreviewRow)
                    .where(
                        PreviewRow.action_type == action_type,
                        PreviewRow.payload_hash == payload_hash,
                    )
                    .order_by(PreviewRow.derived_at)
                    .limit(1)
                )
            ).scalar_one_or_none()
            return self._to_preview(row) if row is not None else None

    async def try_claim_idempotency(self, key: str) -> bool:
        async with self._sessionmaker() as session:
            session.add(IdempotencyClaimRow(key=key, claimed_at=utcnow().isoformat()))
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return False
            return True

    async def save_apply(self, result: ApplyResult) -> None:
        async with self._sessionmaker() as session:
            session.add(
                ApplyRow(
                    apply_id=result.apply_id,
                    action_type=result.action_type,
                    status=result.status.value,
                    payload_hash=result.payload_hash,
                    effects=result.effects,
                    audit_event_id=result.audit_event_id,
                    created_at=utcnow().isoformat(),
                )
            )
            await session.commit()

    async def load_apply(self, apply_id: str) -> ApplyResult | None:
        async with self._sessionmaker() as session:
            row = await session.get(ApplyRow, apply_id)
            if row is None:
                return None
            return ApplyResult(
                status=ApplyStatus(row.status),
                apply_id=row.apply_id,
                action_type=row.action_type,
                payload_hash=row.payload_hash,
                effects=dict(row.effects or {}),
                audit_event_id=row.audit_event_id,
            )

    async def append_audit(self, event: dict[str, Any]) -> str:
        event_id = str(event.get("event_id") or new_id())
        known = {name: event.get(name) for name in _EVENT_COLUMNS}
        extra = {
            k: v
            for k, v in event.items()
            if k not in _EVENT_COLUMNS and k not in ("event_id", "at", "created_at")
        }
        async with self._sessionmaker() as session:
            session.add(
                AuditEventRow(
                    event_id=event_id,
                    created_at=str(event.get("at") or utcnow().isoformat()),
                    extra=extra,
                    **known,
                )
            )
            await session.commit()
        return event_id

    async def get_audit_event(self, event_id: str) -> dict[str, Any] | None:
        async with self._sessionmaker() as session:
            row = await session.get(AuditEventRow, event_id)
            return self._event_dict(row) if row is not None else None

    async def list_chain_events(self, chain_id: str) -> list[dict[str, Any]]:
        async with self._sessionmaker() as session:
            rows = (
                await session.execute(
                    select(AuditEventRow)
                    .where(AuditEventRow.chain_id == chain_id)
                    .order_by(AuditEventRow.created_at)
                )
            ).scalars().all()
            return [self._event_dict(row) for row in rows]

    @staticmethod
    def _event_dict(row: AuditEventRow) -> dict[str, Any]:
        event: dict[str, Any] = {
            "event_id": row.event_id,
            "chain_id": row.chain_id,
            "prev_event_id": row.prev_event_id,
            "kind": row.kind,
            "action_type": row.action_type,
            "operator_id": row.operator_id,
            "reason": row.reason,
            "channel": row.channel,
            "payload_hash": row.payload_hash,
            "at": row.created_at,
        }
        event.update(dict(row.extra or {}))
        return event

    @staticmethod
    def _to_preview(row: PreviewRow) -> Preview:
        return Preview(
            preview_id=row.preview_id,
            action_type=row.action_type,
            payload=dict(row.payload or {}),
            payload_hash=row.payload_hash,
            canon_version=row.canon_version,
            derived_at=_parse_iso(row.derived_at) or utcnow(),
            expires_at=_parse_iso(row.expires_at),
            frozen=bool(row.frozen),
            operator=OperatorContext(
                operator_id=row.operator_id, reason=row.reason, channel=row.channel
            ),
            chain_id=row.chain_id,
        )


__all__ = [
    "ApplyStatus",
    "AuditEventRow",
    "ApplyRow",
    "HashgateBase",
    "IdempotencyClaimRow",
    "PreviewRow",
    "SQLAlchemyStore",
    "create_all",
]
