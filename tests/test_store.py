# SPDX-License-Identifier: Apache-2.0
"""Store contract — run against BOTH the in-memory reference store and the
SQLAlchemy adapter. Includes the concurrency pin ported from the source
system's approval-consume race test: N concurrent claims on one key ->
EXACTLY ONE winner."""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hashgate.adapters.sqlalchemy_store import SQLAlchemyStore, create_all
from hashgate.store import MemoryStore, new_id, utcnow
from hashgate.types import ApplyResult, ApplyStatus, OperatorContext, Preview


async def _sqlalchemy_store() -> SQLAlchemyStore:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await create_all(engine)
    return SQLAlchemyStore(async_sessionmaker(engine, expire_on_commit=False))


_STORES = ["memory", "sqlalchemy"]


async def _make(kind: str):
    return MemoryStore() if kind == "memory" else await _sqlalchemy_store()


def _preview(**over) -> Preview:
    base = dict(
        preview_id=new_id(),
        action_type="pr_merge",
        payload={"repo": "acme/api", "pr": 7, "head_sha": "a" * 40},
        payload_hash="b" * 64,
        derived_at=utcnow(),
        operator=OperatorContext(operator_id="operator:basti", reason="review ok"),
    )
    base.update(over)
    return Preview(**base)


@pytest.mark.parametrize("kind", _STORES)
async def test_preview_roundtrip(kind: str) -> None:
    store = await _make(kind)
    preview = _preview()
    await store.save_preview(preview)
    loaded = await store.load_preview(preview.preview_id)
    assert loaded is not None
    assert loaded.payload == preview.payload
    assert loaded.payload_hash == preview.payload_hash
    assert loaded.action_type == preview.action_type
    assert loaded.operator.operator_id == "operator:basti"
    assert loaded.derived_at == preview.derived_at  # exact ISO round-trip
    assert loaded.frozen is False


@pytest.mark.parametrize("kind", _STORES)
async def test_load_unknown_preview_is_none(kind: str) -> None:
    store = await _make(kind)
    assert await store.load_preview("nope") is None


@pytest.mark.parametrize("kind", _STORES)
async def test_save_preview_idempotent_on_id(kind: str) -> None:
    store = await _make(kind)
    preview = _preview()
    await store.save_preview(preview)
    await store.save_preview(preview)  # no raise, no duplicate
    assert await store.load_preview(preview.preview_id) is not None


@pytest.mark.parametrize("kind", _STORES)
async def test_find_preview_by_hash(kind: str) -> None:
    store = await _make(kind)
    preview = _preview(frozen=True)
    await store.save_preview(preview)
    found = await store.find_preview_by_hash("pr_merge", preview.payload_hash)
    assert found is not None and found.preview_id == preview.preview_id
    assert found.frozen is True
    assert await store.find_preview_by_hash("pr_merge", "c" * 64) is None
    assert await store.find_preview_by_hash("other_action", preview.payload_hash) is None


@pytest.mark.parametrize("kind", _STORES)
async def test_claim_single_use(kind: str) -> None:
    store = await _make(kind)
    assert await store.try_claim_idempotency("merge:acme/api:abc") is True
    assert await store.try_claim_idempotency("merge:acme/api:abc") is False
    assert await store.try_claim_idempotency("merge:acme/api:OTHER") is True


@pytest.mark.parametrize("kind", _STORES)
async def test_claim_race_exactly_one_winner(kind: str) -> None:
    # ported invariant from the source project: N concurrent consumes -> one winner
    store = await _make(kind)
    results = await asyncio.gather(
        *[store.try_claim_idempotency("race-key") for _ in range(20)]
    )
    assert results.count(True) == 1
    assert results.count(False) == 19


@pytest.mark.parametrize("kind", _STORES)
async def test_apply_and_audit_roundtrip(kind: str) -> None:
    store = await _make(kind)
    event_id = await store.append_audit(
        {"kind": "applied", "action_type": "pr_merge", "operator_id": "operator:basti",
         "reason": "review ok", "channel": "api", "payload_hash": "b" * 64,
         "merged_sha": "a" * 40}
    )
    assert isinstance(event_id, str) and event_id
    apply_id = new_id()
    await store.save_apply(
        ApplyResult(status=ApplyStatus.APPLIED, apply_id=apply_id, action_type="pr_merge",
                    payload_hash="b" * 64, effects={"merged_sha": "a" * 40},
                    audit_event_id=event_id)
    )
    loaded = await store.load_apply(apply_id)
    assert loaded is not None
    assert loaded.status is ApplyStatus.APPLIED
    assert loaded.effects == {"merged_sha": "a" * 40}
    assert loaded.audit_event_id == event_id
    assert await store.load_apply("nope") is None
    event = await store.get_audit_event(event_id)
    assert event is not None and event["kind"] == "applied"
    assert await store.get_audit_event("nope") is None


@pytest.mark.parametrize("kind", _STORES)
async def test_chain_events_listed_per_chain(kind: str) -> None:
    store = await _make(kind)
    e1 = await store.append_audit(
        {"kind": "preview", "chain_id": "c1", "prev_event_id": None,
         "action_type": "pr_merge", "at": "2026-07-02T10:00:00+00:00"})
    e2 = await store.append_audit(
        {"kind": "applied", "chain_id": "c1", "prev_event_id": e1,
         "action_type": "pr_merge", "at": "2026-07-02T10:00:01+00:00"})
    await store.append_audit(
        {"kind": "preview", "chain_id": "c2", "prev_event_id": None,
         "action_type": "pr_merge", "at": "2026-07-02T10:00:02+00:00"})
    chain = await store.list_chain_events("c1")
    assert [e["event_id"] for e in chain] == [e1, e2]
    assert await store.list_chain_events("nope") == []


async def test_sqlalchemy_audit_persists_columns_and_extra() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await create_all(engine)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    store = SQLAlchemyStore(sm)
    event_id = await store.append_audit(
        {"kind": "hash_mismatch", "action_type": "pr_merge", "operator_id": "op",
         "reason": "r", "channel": "api", "payload_hash": "d" * 64,
         "expected": "e" * 64, "chain_id": "chain-1", "prev_event_id": None}
    )
    from hashgate.adapters.sqlalchemy_store import AuditEventRow

    async with sm() as session:
        row = await session.get(AuditEventRow, event_id)
    assert row is not None
    assert row.kind == "hash_mismatch" and row.chain_id == "chain-1"
    assert row.payload_hash == "d" * 64
    assert row.extra == {"expected": "e" * 64}  # unknown keys land in extra
    assert row.created_at  # timestamped
