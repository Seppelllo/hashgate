# SPDX-License-Identifier: Apache-2.0
"""The Gate — preview / accept orchestration (the core of hashgate).

``accept`` enforces EXACTLY this order (structurally pinned by tests):

1. policy check (fail-closed, again — never trust the preview)
2. server-side re-derivation (or frozen-bytes load for frozen actions)
3. hash compare against the operator-echoed ``expected_hash``
   -> mismatch: audited refusal
4. ``validate``
5. atomic idempotency claim — AFTER the hash match, BEFORE apply
6. ``apply``
7. ApplyResult + audit

Refusals ARE audited (policy_denied, hash_mismatch, validation_failed,
already_applied) — with IDs and hashes, never payload bodies.

Every flow leaves a LINKED audit chain: the preview event is the chain root
(``chain_id`` = its ``event_id``); accept-side events attach to the chain of
the preview whose hash the operator echoed, each carrying ``prev_event_id``.
A re-preview after a refusal derives a new payload/hash and therefore starts
a NEW chain. :mod:`hashgate.evidence` exports chains as verifiable bundles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hashgate.action import ALREADY_APPLIED_RAISE, ALREADY_APPLIED_RESULT, GatedAction
from hashgate.canonical import CANONICAL_VERSION, canonical_hash
from hashgate.errors import (
    AlreadyApplied,
    EvidenceNotFound,
    HashMismatch,
    PolicyDenied,
    PreviewNotFound,
    ValidationFailed,
)
from hashgate.policy import PolicyEngine
from hashgate.redact import Redactor
from hashgate.store import Store, new_id, utcnow
from hashgate.types import ApplyResult, ApplyStatus, OperatorContext, Preview


def _is_frozen(action: GatedAction) -> bool:
    return bool(getattr(action, "frozen", False))


def _already_applied_mode(action: GatedAction) -> str:
    return str(getattr(action, "already_applied_mode", ALREADY_APPLIED_RAISE))


class _Trail:
    """Mutable chain cursor: which chain we audit into, and the last event."""

    __slots__ = ("chain_id", "prev_event_id")

    def __init__(self, chain_id: str | None = None, prev_event_id: str | None = None):
        self.chain_id = chain_id
        self.prev_event_id = prev_event_id


@dataclass
class Gate:
    """Orchestrates GatedActions over a store and a fail-closed policy engine."""

    store: Store
    policy: PolicyEngine
    redactor: Redactor = field(default_factory=Redactor)

    # --- preview ------------------------------------------------------------
    async def preview(self, action: GatedAction, ctx: Any, op: OperatorContext) -> Preview:
        """Read-only. Persists preview + audit event (the chain root). No
        effect.

        For frozen actions the preview is idempotent on the payload hash:
        re-previewing an identical frozen payload returns the existing
        preview (same chain) instead of storing a duplicate."""
        try:
            self.policy.check(action_type=action.action_type, feature_flag=action.feature_flag)
        except PolicyDenied as exc:
            await self._emit(_Trail(), "policy_denied", action, op, None,
                             blocked_reasons=list(exc.blocked_reasons))
            raise
        payload = await action.derive(ctx)
        await action.validate(ctx, payload)
        payload_hash = canonical_hash(payload)
        frozen = _is_frozen(action)
        if frozen:
            existing = await self.store.find_preview_by_hash(action.action_type, payload_hash)
            if existing is not None:
                return existing
        root_event_id = new_id()
        preview = Preview(
            preview_id=new_id(),
            action_type=action.action_type,
            payload=payload,
            payload_hash=payload_hash,
            derived_at=utcnow(),
            operator=op,
            frozen=frozen,
            chain_id=root_event_id,
        )
        await self.store.save_preview(preview)
        await self._emit(_Trail(), "preview", action, op, payload_hash,
                         event_id=root_event_id, preview_id=preview.preview_id)
        return preview

    # --- accept ---------------------------------------------------------
    async def accept(
        self,
        action: GatedAction,
        ctx: Any,
        op: OperatorContext,
        expected_hash: str,
    ) -> ApplyResult:
        """The core of the pattern. ``expected_hash`` is mandatory — it is
        the operator's cryptographic echo of what they reviewed."""
        expected = str(expected_hash or "").strip()
        if not expected:
            raise ValidationFailed("expected_hash is required", code="expected_hash_required")

        # 1. policy — fail-closed, re-checked (flags may have changed)
        try:
            self.policy.check(action_type=action.action_type, feature_flag=action.feature_flag)
        except PolicyDenied as exc:
            trail = await self._trail_for(action.action_type, expected)
            await self._emit(trail, "policy_denied", action, op, None,
                             blocked_reasons=list(exc.blocked_reasons))
            raise
        trail = await self._trail_for(action.action_type, expected)

        # 2. server-side re-derivation — or frozen-bytes load
        if _is_frozen(action):
            preview = await self.store.find_preview_by_hash(action.action_type, expected)
            if preview is None:
                raise PreviewNotFound(
                    f"no frozen preview for {action.action_type} with hash {expected[:12]}…"
                )
            payload = preview.payload
        else:
            payload = await action.derive(ctx)
        derived_hash = canonical_hash(payload)  # frozen: re-hash of the STORED bytes

        # 3. hash compare — mismatch is an audited refusal
        if derived_hash != expected:
            await self._emit(trail, "hash_mismatch", action, op, derived_hash,
                             expected_hash=expected, derived_hash=derived_hash)
            raise HashMismatch(
                f"expected {expected[:12]}…, got {derived_hash[:12]}…",
                expected_hash=expected,
                derived_hash=derived_hash,
            )

        # 4. validate
        try:
            await action.validate(ctx, payload)
        except ValidationFailed as exc:
            await self._emit(trail, "validation_failed", action, op, derived_hash,
                             error_code=exc.code, blocked_reasons=list(exc.blocked_reasons))
            raise

        # 5. atomic idempotency claim — after hash match, before apply
        key = action.idempotency_key(ctx, payload)
        if not await self.store.try_claim_idempotency(key):
            event_id = await self._emit(trail, "already_applied", action, op, derived_hash,
                                        idempotency_key=key)
            if _already_applied_mode(action) == ALREADY_APPLIED_RESULT:
                return ApplyResult(
                    status=ApplyStatus.ALREADY_APPLIED,
                    apply_id=new_id(),
                    action_type=action.action_type,
                    payload_hash=derived_hash,
                    effects={},
                    audit_event_id=event_id,
                )
            raise AlreadyApplied(key, idempotency_key=key)

        # 6. apply
        effects = await action.apply(ctx, payload)

        # 7. result + audit (policy snapshot: check passed => allow_with_gates)
        event_id = await self._emit(trail, "applied", action, op, derived_hash,
                                    idempotency_key=key,
                                    feature_flag=action.feature_flag,
                                    policy_decision="allow_with_gates",
                                    effects=self.redactor.redact(dict(effects or {})))
        result = ApplyResult(
            status=ApplyStatus.APPLIED,
            apply_id=new_id(),
            action_type=action.action_type,
            payload_hash=derived_hash,
            effects=dict(effects or {}),
            audit_event_id=event_id,
        )
        await self.store.save_apply(result)
        return result

    # --- explainability ---------------------------------------------------
    def refuse_reason(self, action: GatedAction) -> str | None:
        """Why WOULD accept fail, without any effect — for UIs (disabled
        buttons + reason). Covers the policy layer; hash/idempotency gates
        depend on a concrete expected_hash and are not pre-computable."""
        decision = self.policy.evaluate(
            action_type=action.action_type, feature_flag=action.feature_flag
        )
        if decision.denied:
            return "; ".join(decision.reasons)
        return None

    # --- internals ----------------------------------------------------------
    async def _trail_for(self, action_type: str, payload_hash: str) -> _Trail:
        """Attach to the chain of the preview the operator echoed, if any —
        pure audit bookkeeping, never a gate."""
        preview = await self.store.find_preview_by_hash(action_type, payload_hash)
        if preview is None or not preview.chain_id:
            return _Trail()
        events = await self.store.list_chain_events(preview.chain_id)
        try:
            from hashgate.evidence import order_chain_events

            ordered = order_chain_events(events)
        except EvidenceNotFound:
            ordered = events
        prev = str(ordered[-1]["event_id"]) if ordered else None
        return _Trail(preview.chain_id, prev)

    async def _emit(
        self,
        trail: _Trail,
        kind: str,
        action: GatedAction,
        op: OperatorContext,
        payload_hash: str | None,
        *,
        event_id: str | None = None,
        **extra: Any,
    ) -> str:
        event_id = event_id or new_id()
        if trail.chain_id is None:
            trail.chain_id = event_id  # this event roots a new chain
        event = {
            "event_id": event_id,
            "chain_id": trail.chain_id,
            "prev_event_id": trail.prev_event_id,
            "kind": kind,
            "action_type": action.action_type,
            "operator_id": op.operator_id,
            "reason": op.reason,
            "channel": op.channel,
            "payload_hash": payload_hash,
            "canon_version": CANONICAL_VERSION,
            "at": utcnow().isoformat(),
            **self.redactor.redact(extra),
        }
        await self.store.append_audit(event)
        trail.prev_event_id = event_id
        return event_id
