# SPDX-License-Identifier: Apache-2.0
"""Storage protocol + in-memory reference implementation.

The store interface is deliberately narrow. The load-bearing method is
:meth:`Store.try_claim_idempotency`: it MUST be atomic (backed by a unique
constraint or an equivalent compare-and-set primitive), because it is the
mutex that guarantees ``apply()`` never runs twice for the same logical
effect — pre-check-SELECT patterns are NOT acceptable implementations.

Audit events are REDACTED BY CONTRACT: they carry IDs, hashes, action types,
operator identity/reason/channel, timestamps and effect summaries — never
payload bodies, never secrets. The gate composes events accordingly; a store
implementation must not add payload material of its own.

All methods are async; hashgate is async-first (see README: design decisions).
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from hashgate.types import ApplyResult, Preview


def new_id() -> str:
    """Opaque unique id (uuid4 hex)."""
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC)


class Store(Protocol):
    """Persistence boundary of the gate."""

    async def save_preview(self, preview: Preview) -> None:
        """Persist a preview (idempotent on preview_id)."""
        ...

    async def load_preview(self, preview_id: str) -> Preview | None:
        """Load a preview by id; ``None`` if unknown."""
        ...

    async def find_preview_by_hash(self, action_type: str, payload_hash: str) -> Preview | None:
        """Load a preview by (action_type, payload_hash); ``None`` if unknown.
        Used by frozen-payload flows, where the operator echoes the hash."""
        ...

    async def try_claim_idempotency(self, key: str) -> bool:
        """Atomic single-use claim. ``False`` means the key was already
        claimed (=> AlreadyApplied). MUST be backed by a unique constraint
        or an atomic compare-and-set — never by a pre-check SELECT."""
        ...

    async def save_apply(self, result: ApplyResult) -> None:
        """Persist an apply result."""
        ...

    async def load_apply(self, apply_id: str) -> ApplyResult | None:
        """Load an apply result by id; ``None`` if unknown."""
        ...

    async def append_audit(self, event: dict[str, Any]) -> str:
        """Append a REDACTED audit event (IDs + hashes only, never payload
        bodies or secrets) and return its event_id. If the event carries an
        ``event_id`` it is honored (the gate pre-generates ids for chain
        linkage)."""
        ...

    async def get_audit_event(self, event_id: str) -> dict[str, Any] | None:
        """Load one audit event by id; ``None`` if unknown."""
        ...

    async def list_chain_events(self, chain_id: str) -> list[dict[str, Any]]:
        """All audit events of one chain, in insertion order."""
        ...


class MemoryStore:
    """In-process reference store (tests, examples, prototyping).

    Race-safe within one event loop via a lock; NOT a durable or
    multi-process store — use the SQLAlchemy adapter for real deployments.
    """

    def __init__(self) -> None:
        self._previews: dict[str, Preview] = {}
        self._claims: set[str] = set()
        self._applies: dict[str, ApplyResult] = {}
        self._audit: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def save_preview(self, preview: Preview) -> None:
        async with self._lock:
            self._previews[preview.preview_id] = preview

    async def load_preview(self, preview_id: str) -> Preview | None:
        async with self._lock:
            return self._previews.get(preview_id)

    async def find_preview_by_hash(self, action_type: str, payload_hash: str) -> Preview | None:
        async with self._lock:
            for preview in self._previews.values():
                if preview.action_type == action_type and preview.payload_hash == payload_hash:
                    return preview
            return None

    async def try_claim_idempotency(self, key: str) -> bool:
        async with self._lock:
            if key in self._claims:
                return False
            self._claims.add(key)
            return True

    async def save_apply(self, result: ApplyResult) -> None:
        async with self._lock:
            self._applies[result.apply_id] = result

    async def load_apply(self, apply_id: str) -> ApplyResult | None:
        async with self._lock:
            return self._applies.get(apply_id)

    async def append_audit(self, event: dict[str, Any]) -> str:
        async with self._lock:
            event_id = str(event.get("event_id") or new_id())
            self._audit.append({**event, "event_id": event_id})
            return event_id

    async def get_audit_event(self, event_id: str) -> dict[str, Any] | None:
        async with self._lock:
            for event in self._audit:
                if event.get("event_id") == event_id:
                    return dict(event)
            return None

    async def list_chain_events(self, chain_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            return [dict(e) for e in self._audit if e.get("chain_id") == chain_id]

    # --- introspection helpers for tests/examples (not part of the protocol)
    @property
    def audit_events(self) -> list[dict[str, Any]]:
        return list(self._audit)

    @property
    def applies(self) -> list[ApplyResult]:
        return list(self._applies.values())
