# SPDX-License-Identifier: Apache-2.0
"""Core data types shared across the library."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from hashgate.canonical import CANONICAL_VERSION
from hashgate.errors import ValidationFailed

#: length caps carried over from the source system (operator ids / free-text
#: reasons are clipped, never rejected for length).
MAX_OPERATOR_ID_LEN = 160
MAX_REASON_LEN = 2000


@dataclass(frozen=True)
class OperatorContext:
    """Who acts, and why. Mandatory on every preview/accept.

    ``operator_id`` and ``reason`` must be non-empty (fail-closed: an action
    without an accountable operator and a recorded reason is refused).
    ``channel`` records where the action came from ("api", "cockpit-ui",
    "cli", …) and ends up in the audit trail.
    """

    operator_id: str
    reason: str
    channel: str = "api"

    def __post_init__(self) -> None:
        operator_id = str(self.operator_id or "").strip()
        reason = str(self.reason or "").strip()
        channel = str(self.channel or "").strip() or "api"
        if not operator_id or not reason:
            raise ValidationFailed(
                "operator_id and reason are required",
                code="operator_id_and_reason_required",
            )
        object.__setattr__(self, "operator_id", operator_id[:MAX_OPERATOR_ID_LEN])
        object.__setattr__(self, "reason", reason[:MAX_REASON_LEN])
        object.__setattr__(self, "channel", channel[:64])


@dataclass(frozen=True)
class Preview:
    """Read-only result of a derivation. Persisted, but effect-free."""

    preview_id: str
    action_type: str
    payload: dict[str, Any]
    payload_hash: str
    derived_at: datetime
    operator: OperatorContext
    canon_version: str = CANONICAL_VERSION
    expires_at: datetime | None = None
    #: frozen previews bind accept to stored bytes instead of a re-derivation
    frozen: bool = False
    #: audit-chain root this preview started (event_id of the preview event);
    #: accept/refuse/apply events attach to the same chain
    chain_id: str | None = None


class ApplyStatus(StrEnum):
    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"


@dataclass(frozen=True)
class ApplyResult:
    """Outcome of a successful (or idempotent) accept."""

    status: ApplyStatus
    apply_id: str
    action_type: str
    payload_hash: str
    effects: dict[str, Any] = field(default_factory=dict)
    audit_event_id: str | None = None
