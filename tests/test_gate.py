# SPDX-License-Identifier: Apache-2.0
"""Gate behavior — instrumented-action pins for the accept order.

The action records every hook call; the tests assert not just outcomes but
WHICH hooks ran (and which did not) on every path.
"""
from __future__ import annotations

import pytest

from hashgate.action import ALREADY_APPLIED_RESULT
from hashgate.canonical import canonical_hash
from hashgate.errors import (
    AlreadyApplied,
    HashMismatch,
    PolicyDenied,
    ValidationFailed,
)
from hashgate.gate import Gate
from hashgate.policy import MappingPolicySource, PolicyEngine
from hashgate.store import MemoryStore
from hashgate.types import ApplyStatus, OperatorContext

_OP = OperatorContext(operator_id="operator:basti", reason="review ok", channel="cli")


class LogAction:
    """Deterministic instrumented action."""

    action_type = "pr_merge"
    feature_flag = "pr_merge_enabled"

    def __init__(self, *, payload=None, fail_validate=False, already_applied_mode=None):
        self.calls: list[str] = []
        self._payload = payload or {"repo": "acme/api", "pr": 7, "head_sha": "a" * 40}
        self._fail_validate = fail_validate
        if already_applied_mode is not None:
            self.already_applied_mode = already_applied_mode

    async def derive(self, ctx):
        self.calls.append("derive")
        return dict(self._payload)

    async def validate(self, ctx, payload):
        self.calls.append("validate")
        if self._fail_validate:
            raise ValidationFailed("nope", code="diff_too_large")

    def idempotency_key(self, ctx, payload):
        self.calls.append("idempotency_key")
        return f"merge:{payload['repo']}:{payload['head_sha']}"

    async def apply(self, ctx, payload):
        self.calls.append("apply")
        return {"merged_sha": payload["head_sha"]}


def _gate(store=None, *, allow=True) -> Gate:
    flags = {"pr_merge_enabled": True} if allow else {}
    policies = {"pr_merge": "allow"} if allow else {}
    return Gate(
        store=store or MemoryStore(),
        policy=PolicyEngine(source=MappingPolicySource(flags=flags, policies=policies)),
    )


def _kinds(store: MemoryStore) -> list[str]:
    return [e["kind"] for e in store.audit_events]


# --- (d) happy path: exact order, each step exactly once ---------------------
async def test_happy_path_order_and_result() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = LogAction()
    preview = await gate.preview(action, None, _OP)
    assert action.calls == ["derive", "validate"]
    result = await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    assert action.calls == [
        "derive", "validate",                                # preview
        "derive", "validate", "idempotency_key", "apply",    # accept, in order
    ]
    assert result.status is ApplyStatus.APPLIED
    assert result.payload_hash == preview.payload_hash
    assert result.effects == {"merged_sha": "a" * 40}
    assert result.audit_event_id
    assert _kinds(store) == ["preview", "applied"]
    assert len(store.applies) == 1


# --- (a) mismatch: derive ran, validate/claim/apply did NOT ------------------
async def test_hash_mismatch_refuses_before_validate_claim_apply() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = LogAction()
    with pytest.raises(HashMismatch) as exc:
        await gate.accept(action, None, _OP, expected_hash="f" * 64)
    assert action.calls == ["derive"]  # nothing after the hash compare
    assert exc.value.expected_hash == "f" * 64
    assert exc.value.derived_hash == canonical_hash(action._payload)
    assert exc.value.http_status == 409
    # refusal is audited, with BOTH hashes and no payload body
    (event,) = store.audit_events
    assert event["kind"] == "hash_mismatch"
    assert event["expected_hash"] == "f" * 64
    assert event["derived_hash"] == exc.value.derived_hash
    assert "repo" not in event and "payload" not in event
    # the idempotency key was NOT claimed (a later valid accept still works)
    assert await store.try_claim_idempotency("merge:acme/api:" + "a" * 40) is True


async def test_nondeterministic_derive_surfaces_as_mismatch() -> None:
    class Drifting(LogAction):
        def __init__(self):
            super().__init__()
            self._n = 0

        async def derive(self, ctx):
            self.calls.append("derive")
            self._n += 1
            return {"n": self._n}

    gate = _gate()
    action = Drifting()
    preview = await gate.preview(action, None, _OP)
    with pytest.raises(HashMismatch):
        await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)


# --- (b) already claimed: apply did NOT run ----------------------------------
async def test_second_accept_raises_already_applied_without_apply() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = LogAction()
    preview = await gate.preview(action, None, _OP)
    await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    calls_before = list(action.calls)
    with pytest.raises(AlreadyApplied) as exc:
        await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    assert exc.value.idempotency_key == "merge:acme/api:" + "a" * 40
    assert exc.value.http_status == 409
    # derive/validate/key ran (gates), apply did NOT run a second time
    assert action.calls == calls_before + ["derive", "validate", "idempotency_key"]
    assert action.calls.count("apply") == 1
    assert _kinds(store) == ["preview", "applied", "already_applied"]
    assert len(store.applies) == 1


async def test_already_applied_result_mode_returns_status() -> None:
    gate = _gate()
    action = LogAction(already_applied_mode=ALREADY_APPLIED_RESULT)
    preview = await gate.preview(action, None, _OP)
    await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    result = await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    assert result.status is ApplyStatus.ALREADY_APPLIED
    assert result.effects == {}
    assert action.calls.count("apply") == 1


# --- (c) policy deny: NOTHING ran except the policy check --------------------
async def test_policy_deny_runs_no_action_hook() -> None:
    store = MemoryStore()
    gate = _gate(store, allow=False)
    action = LogAction()
    with pytest.raises(PolicyDenied):
        await gate.accept(action, None, _OP, expected_hash="f" * 64)
    assert action.calls == []
    assert _kinds(store) == ["policy_denied"]
    with pytest.raises(PolicyDenied):
        await gate.preview(action, None, _OP)
    assert action.calls == []


# --- remaining gates ----------------------------------------------------------
async def test_expected_hash_is_mandatory() -> None:
    gate = _gate()
    action = LogAction()
    for empty in ("", "   ", None):
        with pytest.raises(ValidationFailed) as exc:
            await gate.accept(action, None, _OP, expected_hash=empty)  # type: ignore[arg-type]
        assert exc.value.code == "expected_hash_required"
    assert action.calls == []


async def test_validate_failure_refuses_before_claim_and_apply() -> None:
    store = MemoryStore()
    gate = _gate(store)
    good = LogAction()
    preview = await gate.preview(good, None, _OP)
    bad = LogAction(fail_validate=True)
    with pytest.raises(ValidationFailed):
        await gate.accept(bad, None, _OP, expected_hash=preview.payload_hash)
    assert bad.calls == ["derive", "validate"]  # no claim, no apply
    assert _kinds(store)[-1] == "validation_failed"
    assert await store.try_claim_idempotency("merge:acme/api:" + "a" * 40) is True


async def test_refuse_reason_explainability() -> None:
    denied = _gate(allow=False)
    reason = denied.refuse_reason(LogAction())
    assert reason and "flag_off:pr_merge_enabled" in reason
    assert _gate(allow=True).refuse_reason(LogAction()) is None


async def test_preview_is_effect_free() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = LogAction()
    await gate.preview(action, None, _OP)
    assert "apply" not in action.calls and "idempotency_key" not in action.calls
    assert store.applies == []
    assert await store.try_claim_idempotency("merge:acme/api:" + "a" * 40) is True
