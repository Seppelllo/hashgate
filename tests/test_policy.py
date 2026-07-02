# SPDX-License-Identifier: Apache-2.0
"""PolicyEngine — fail-closed pins."""
from __future__ import annotations

import pytest

from hashgate.errors import PolicyDenied
from hashgate.policy import (
    DECISION_ALLOW_WITH_GATES,
    DECISION_DENY,
    MappingPolicySource,
    PolicyEngine,
)


def _engine(**kw) -> PolicyEngine:
    return PolicyEngine(source=MappingPolicySource(**kw))


def test_default_is_deny_everything() -> None:
    decision = _engine().evaluate(action_type="pr_merge", feature_flag="pr_merge_enabled")
    assert decision.denied and decision.decision == DECISION_DENY
    assert "flag_off:pr_merge_enabled" in decision.reasons
    assert "policy_deny:pr_merge" in decision.reasons


def test_flag_on_alone_is_not_enough() -> None:
    decision = _engine(flags={"pr_merge_enabled": True}).evaluate(
        action_type="pr_merge", feature_flag="pr_merge_enabled")
    assert decision.denied
    assert decision.reasons == ("policy_deny:pr_merge",)


def test_policy_allow_alone_is_not_enough() -> None:
    decision = _engine(policies={"pr_merge": "allow"}).evaluate(
        action_type="pr_merge", feature_flag="pr_merge_enabled")
    assert decision.denied
    assert decision.reasons == ("flag_off:pr_merge_enabled",)


def test_allow_is_never_blank_always_with_gates() -> None:
    decision = _engine(flags={"pr_merge_enabled": True},
                       policies={"pr_merge": "allow"}).evaluate(
        action_type="pr_merge", feature_flag="pr_merge_enabled")
    assert decision.allowed and decision.decision == DECISION_ALLOW_WITH_GATES
    assert any(r.startswith("gates_outstanding:") for r in decision.reasons)


def test_unknown_policy_string_is_deny() -> None:
    decision = _engine(flags={"f": True}, policies={"a": "yes-please"}).evaluate(
        action_type="a", feature_flag="f")
    assert decision.denied


def test_check_raises_policy_denied_with_reasons() -> None:
    with pytest.raises(PolicyDenied) as exc:
        _engine().check(action_type="a", feature_flag="f")
    assert exc.value.http_status == 403
    assert exc.value.code == "policy_denied"
    assert "flag_off:f" in exc.value.blocked_reasons


def test_broken_policy_source_is_deny_not_crash() -> None:
    class Broken:
        def flag(self, name: str) -> bool:
            raise RuntimeError("db down")

        def budget(self, name: str) -> int:
            return 0

        def policy(self, action_type: str) -> str:
            return "allow"

    decision = PolicyEngine(source=Broken()).evaluate(action_type="a", feature_flag="f")
    assert decision.denied
    assert decision.reasons == ("policy_source_error:RuntimeError",)


def test_bool_budget_is_config_mistake_and_reads_zero() -> None:
    source = MappingPolicySource(budgets={"max_llm_calls": True, "ok": 3})
    assert source.budget("max_llm_calls") == 0
    assert source.budget("ok") == 3
    assert source.budget("missing") == 0
