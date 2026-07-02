# SPDX-License-Identifier: Apache-2.0
"""FrozenPayloadAction path — freeze once, accept binds to stored bytes."""
from __future__ import annotations

from dataclasses import replace

import pytest

from hashgate.errors import AlreadyApplied, PreviewNotFound
from hashgate.gate import Gate
from hashgate.policy import MappingPolicySource, PolicyEngine
from hashgate.store import MemoryStore
from hashgate.types import ApplyStatus, OperatorContext

_OP = OperatorContext(operator_id="operator:basti", reason="intake reviewed")


class FrozenIntake:
    """Simulates a non-deterministic (LLM-shaped) derivation: every derive
    call returns a different payload — freezing is the only sane binding."""

    action_type = "mission_intake"
    feature_flag = "mission_intake_enabled"
    frozen = True

    def __init__(self):
        self.calls: list[str] = []
        self._n = 0

    async def derive(self, ctx):
        self.calls.append("derive")
        self._n += 1
        return {"goal": "build report", "plan_variant": self._n}

    async def validate(self, ctx, payload):
        self.calls.append("validate")

    def idempotency_key(self, ctx, payload):
        self.calls.append("idempotency_key")
        return f"intake:{payload['plan_variant']}"

    async def apply(self, ctx, payload):
        self.calls.append("apply")
        return {"mission_id": 42}


def _gate(store=None) -> Gate:
    return Gate(
        store=store or MemoryStore(),
        policy=PolicyEngine(source=MappingPolicySource(
            flags={"mission_intake_enabled": True},
            policies={"mission_intake": "allow"})),
    )


async def test_freeze_once_accept_never_rederives() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = FrozenIntake()
    preview = await gate.preview(action, None, _OP)
    assert preview.frozen is True
    assert action.calls.count("derive") == 1
    result = await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    assert result.status is ApplyStatus.APPLIED
    assert action.calls.count("derive") == 1  # NOT called again at accept
    assert result.payload_hash == preview.payload_hash


async def test_unknown_hash_is_preview_not_found_404() -> None:
    gate = _gate()
    action = FrozenIntake()
    await gate.preview(action, None, _OP)
    with pytest.raises(PreviewNotFound) as exc:
        await gate.accept(action, None, _OP, expected_hash="f" * 64)
    assert exc.value.http_status == 404
    assert action.calls.count("apply") == 0


async def test_second_accept_is_already_applied() -> None:
    gate = _gate()
    action = FrozenIntake()
    preview = await gate.preview(action, None, _OP)
    await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    with pytest.raises(AlreadyApplied):
        await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    assert action.calls.count("apply") == 1


async def test_tampered_stored_payload_is_caught_by_rehash() -> None:
    # accept re-hashes the STORED bytes — a store-side tamper (payload swapped
    # while keeping the stored payload_hash) must refuse, not apply.
    from hashgate.errors import HashMismatch

    store = MemoryStore()
    gate = _gate(store)
    action = FrozenIntake()
    preview = await gate.preview(action, None, _OP)
    tampered = replace(preview, payload={"goal": "rm -rf /", "plan_variant": 1})
    store._previews[preview.preview_id] = tampered  # simulate store corruption
    with pytest.raises(HashMismatch):
        await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    assert action.calls.count("apply") == 0


async def test_identical_frozen_payload_previews_dedupe_on_hash() -> None:
    class Stable(FrozenIntake):
        async def derive(self, ctx):
            self.calls.append("derive")
            return {"goal": "stable"}

    store = MemoryStore()
    gate = _gate(store)
    action = Stable()
    p1 = await gate.preview(action, None, _OP)
    p2 = await gate.preview(action, None, _OP)
    assert p1.preview_id == p2.preview_id  # idempotent on the frozen hash
