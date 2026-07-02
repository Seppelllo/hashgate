# SPDX-License-Identifier: Apache-2.0
"""Fail-closed policy engine.

Design lineage: the runtime policy engine of the production agent-runtime
project hashgate was extracted from — a pure function over a policy source
that NEVER returns a blank "allow":
either ``deny`` (with machine-readable reasons) or ``allow_with_gates``
(allowed, but every remaining gate — hash match, idempotency claim,
validation — still stands). Defaults are deny everywhere:

- unknown/missing flag  -> ``False``
- unknown/missing budget -> ``0``
- unknown/missing policy -> ``"deny"``
- a policy source that RAISES -> deny (``policy_source_error``)
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from hashgate.errors import PolicyDenied

POLICY_ALLOW = "allow"
POLICY_DENY = "deny"

DECISION_DENY = "deny"
DECISION_ALLOW_WITH_GATES = "allow_with_gates"


class PolicySource(Protocol):
    """Where flags/budgets/policies come from (settings object, DB row, …).

    Implementations MUST be fail-closed: unknown names return the deny
    default, never raise for "not configured"."""

    def flag(self, name: str) -> bool:
        """Feature flag value; default ``False``."""
        ...

    def budget(self, name: str) -> int:
        """Numeric budget (e.g. max_llm_calls); default ``0``."""
        ...

    def policy(self, action_type: str) -> str:
        """``"allow"`` or ``"deny"`` per action type; default ``"deny"``."""
        ...


class MappingPolicySource:
    """Dict-backed reference :class:`PolicySource` (fail-closed defaults)."""

    def __init__(
        self,
        flags: Mapping[str, bool] | None = None,
        budgets: Mapping[str, int] | None = None,
        policies: Mapping[str, str] | None = None,
    ) -> None:
        self._flags = dict(flags or {})
        self._budgets = dict(budgets or {})
        self._policies = dict(policies or {})

    def flag(self, name: str) -> bool:
        return bool(self._flags.get(name, False))

    def budget(self, name: str) -> int:
        value = self._budgets.get(name, 0)
        # bools are ints in Python — a bool budget is a config mistake, deny it
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return value

    def policy(self, action_type: str) -> str:
        return str(self._policies.get(action_type, POLICY_DENY))


@dataclass(frozen=True)
class PolicyDecision:
    """Never a blank allow: ``deny`` or ``allow_with_gates``."""

    allowed: bool
    decision: str  # DECISION_DENY | DECISION_ALLOW_WITH_GATES
    reasons: tuple[str, ...] = ()

    @property
    def denied(self) -> bool:
        return not self.allowed


@dataclass
class PolicyEngine:
    """Evaluates flag + policy for an action, fail-closed."""

    source: PolicySource

    def evaluate(self, *, action_type: str, feature_flag: str) -> PolicyDecision:
        """Non-raising evaluation (for ``refuse_reason`` / UI explainability)."""
        reasons: list[str] = []
        try:
            flag_on = bool(self.source.flag(feature_flag))
            policy = str(self.source.policy(action_type))
        except Exception as exc:  # fail-closed: a broken source is a deny
            return PolicyDecision(
                allowed=False,
                decision=DECISION_DENY,
                reasons=(f"policy_source_error:{type(exc).__name__}",),
            )
        if not flag_on:
            reasons.append(f"flag_off:{feature_flag}")
        if policy != POLICY_ALLOW:
            reasons.append(f"policy_deny:{action_type}")
        if reasons:
            return PolicyDecision(allowed=False, decision=DECISION_DENY, reasons=tuple(reasons))
        # allowed — but only "with gates": hash match, validation and the
        # idempotency claim still stand between here and any effect.
        return PolicyDecision(
            allowed=True,
            decision=DECISION_ALLOW_WITH_GATES,
            reasons=("gates_outstanding:hash_match,validate,idempotency_claim",),
        )

    def check(self, *, action_type: str, feature_flag: str) -> None:
        """Raising variant used by the gate; raises :class:`PolicyDenied`."""
        decision = self.evaluate(action_type=action_type, feature_flag=feature_flag)
        if not decision.allowed:
            raise PolicyDenied(
                f"policy denied for {action_type}: {', '.join(decision.reasons)}",
                blocked_reasons=list(decision.reasons),
            )
