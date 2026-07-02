# SPDX-License-Identifier: Apache-2.0
"""OwnershipGuard — no silent hijacking, drift refuses, takeover mutates
only the owner + one audit event."""
from __future__ import annotations

import dataclasses

import pytest

from hashgate.errors import OwnershipViolation, StateDrift
from hashgate.ownership import OwnedResource, OwnershipGuard
from hashgate.store import MemoryStore
from hashgate.types import OperatorContext

_ALICE = OperatorContext(operator_id="operator:alice", reason="taking over stalled run")
_RES = OwnedResource(resource_id="runner:7", owner_operator_id="operator:bob",
                     state="waiting_for_operator_accept")


def _guard(store=None) -> OwnershipGuard:
    return OwnershipGuard(
        store=store or MemoryStore(),
        terminal_states=frozenset({"completed", "failed", "cancelled"}),
        takeoverable_states=frozenset({"waiting_for_operator_accept", "artifact_ready"}),
    )


def test_assert_owner_allows_owner_and_refuses_foreign() -> None:
    guard = _guard()
    guard.assert_owner(_RES, OperatorContext(operator_id="operator:bob", reason="mine"))
    with pytest.raises(OwnershipViolation) as exc:
        guard.assert_owner(_RES, _ALICE)
    assert exc.value.code == "foreign_owner"
    assert exc.value.http_status == 409


async def test_takeover_happy_path_mutates_only_owner_plus_audit() -> None:
    store = MemoryStore()
    result = await _guard(store).take_over(
        _RES, _ALICE,
        expected_operator_id="operator:bob",
        expected_state="waiting_for_operator_accept",
    )
    assert result.resource.owner_operator_id == "operator:alice"
    assert result.prior_operator_id == "operator:bob"
    # ONLY the owner differs — every other field is byte-identical
    for f in dataclasses.fields(OwnedResource):
        if f.name != "owner_operator_id":
            assert getattr(result.resource, f.name) == getattr(_RES, f.name)
    assert _RES.owner_operator_id == "operator:bob"  # input never mutated
    # exactly one audit event, nothing else written
    (event,) = store.audit_events
    assert event["kind"] == "takeover"
    assert event["prior_operator_id"] == "operator:bob"
    assert event["new_operator_id"] == "operator:alice"
    assert result.audit_event_id == event["event_id"]
    assert store.applies == []


async def test_operator_drift_is_ownership_violation() -> None:
    store = MemoryStore()
    with pytest.raises(OwnershipViolation) as exc:
        await _guard(store).take_over(
            _RES, _ALICE,
            expected_operator_id="operator:carol",  # stale view of the owner
            expected_state="waiting_for_operator_accept",
        )
    assert exc.value.code == "owner_drift"
    assert store.audit_events == []  # refusal writes nothing here


async def test_state_drift_is_state_drift() -> None:
    with pytest.raises(StateDrift) as exc:
        await _guard().take_over(
            _RES, _ALICE,
            expected_operator_id="operator:bob",
            expected_state="artifact_ready",  # stale view of the state
        )
    assert exc.value.code == "state_drift"


async def test_terminal_resource_refuses() -> None:
    done = dataclasses.replace(_RES, state="completed")
    with pytest.raises(StateDrift) as exc:
        await _guard().take_over(
            done, _ALICE,
            expected_operator_id="operator:bob", expected_state="completed",
        )
    assert exc.value.code == "resource_terminal"


async def test_non_takeoverable_state_refuses() -> None:
    running = dataclasses.replace(_RES, state="running")
    with pytest.raises(StateDrift) as exc:
        await _guard().take_over(
            running, _ALICE,
            expected_operator_id="operator:bob", expected_state="running",
        )
    assert exc.value.code == "state_not_takeoverable"


async def test_default_takeoverable_is_any_non_terminal() -> None:
    guard = OwnershipGuard(store=MemoryStore(),
                           terminal_states=frozenset({"completed"}))
    running = dataclasses.replace(_RES, state="running")
    result = await guard.take_over(
        running, _ALICE,
        expected_operator_id="operator:bob", expected_state="running",
    )
    assert result.resource.owner_operator_id == "operator:alice"
