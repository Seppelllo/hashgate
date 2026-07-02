# SPDX-License-Identifier: Apache-2.0
"""Ownership guard — no silent hijacking, no silent forking.

Extracted from the source project's cross-operator recovery: a non-terminal
resource owned by another operator must never be silently resumed or forked;
the operator either takes it over EXPLICITLY (binding the takeover to the
expected owner AND expected state, so any drift refuses) or cancels it.

A takeover mutates ONLY the owner (plus an audit event). It never resumes,
never applies, never touches domain state — hashgate returns an updated copy
of the resource; persisting the owner change is the consumer's job, and the
consumer must persist nothing else.

Error taxonomy (deliberately two distinct types):
- :class:`OwnershipViolation` — the ownership fact is the problem (foreign
  owner without takeover; owner drifted since the operator looked).
- :class:`StateDrift` — the state is the problem (terminal, not takeoverable,
  or drifted since the operator looked).
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from hashgate.errors import OwnershipViolation, StateDrift
from hashgate.store import Store
from hashgate.types import OperatorContext


@dataclass(frozen=True)
class OwnedResource:
    """Minimal ownership projection of a consumer-side resource."""

    resource_id: str
    owner_operator_id: str
    state: str


@dataclass(frozen=True)
class TakeoverResult:
    resource: OwnedResource  # updated copy — ONLY the owner differs
    prior_operator_id: str
    audit_event_id: str


@dataclass
class OwnershipGuard:
    """Validates ownership actions against explicit state sets.

    ``terminal_states``: takeover is never allowed (the chain is closed).
    ``takeoverable_states``: if given, takeover is allowed ONLY in these
    states (fail-closed default: ``None`` means any non-terminal state).
    """

    store: Store
    terminal_states: frozenset[str] = frozenset()
    takeoverable_states: frozenset[str] | None = None

    def assert_owner(self, resource: OwnedResource, op: OperatorContext) -> None:
        """Refuse any action on a foreign-owned resource (no silent fork)."""
        if resource.owner_operator_id != op.operator_id:
            raise OwnershipViolation(
                f"{resource.resource_id} is owned by {resource.owner_operator_id}",
                code="foreign_owner",
            )

    async def take_over(
        self,
        resource: OwnedResource,
        op: OperatorContext,
        *,
        expected_operator_id: str,
        expected_state: str,
    ) -> TakeoverResult:
        """Explicit takeover. Drift in owner OR state refuses. Mutates only
        the owner + appends one audit event. No resume, no apply."""
        if resource.state in self.terminal_states:
            raise StateDrift(
                f"{resource.resource_id} is terminal ({resource.state})",
                code="resource_terminal",
            )
        if self.takeoverable_states is not None and resource.state not in self.takeoverable_states:
            raise StateDrift(
                f"state {resource.state} is not takeoverable",
                code="state_not_takeoverable",
            )
        if resource.state != expected_state:
            raise StateDrift(
                f"expected state {expected_state}, found {resource.state}",
                code="state_drift",
            )
        if resource.owner_operator_id != expected_operator_id:
            raise OwnershipViolation(
                f"expected owner {expected_operator_id}, found {resource.owner_operator_id}",
                code="owner_drift",
            )
        event_id = await self.store.append_audit(
            {
                "kind": "takeover",
                "resource_id": resource.resource_id,
                "prior_operator_id": resource.owner_operator_id,
                "new_operator_id": op.operator_id,
                "operator_id": op.operator_id,
                "reason": op.reason,
                "channel": op.channel,
                "state": resource.state,
            }
        )
        return TakeoverResult(
            resource=replace(resource, owner_operator_id=op.operator_id),
            prior_operator_id=resource.owner_operator_id,
            audit_event_id=event_id,
        )
