# SPDX-License-Identifier: Apache-2.0
"""hashgate — execution governance for AI agents.

Preview -> canonical hash -> operator accept -> server-side re-derivation ->
apply. Fail-closed, idempotent, audited.

hashgate executes nothing itself; it gates. There is no auto-accept and no
scheduler in the core.
"""
from hashgate.canonical import CANONICAL_VERSION, HASH_ALGO, canonical_bytes, canonical_hash
from hashgate.errors import (
    AlreadyApplied,
    CanonicalizationError,
    HashgateError,
    HashMismatch,
    OwnershipViolation,
    PolicyDenied,
    PreviewNotFound,
    StateDrift,
    ValidationFailed,
)
from hashgate.policy import MappingPolicySource, PolicyDecision, PolicyEngine, PolicySource
from hashgate.store import MemoryStore, Store
from hashgate.types import ApplyResult, ApplyStatus, OperatorContext, Preview

__version__ = "0.1.0.dev0"

__all__ = [
    "CANONICAL_VERSION",
    "HASH_ALGO",
    "canonical_bytes",
    "canonical_hash",
    "HashgateError",
    "CanonicalizationError",
    "PolicyDenied",
    "ValidationFailed",
    "HashMismatch",
    "AlreadyApplied",
    "StateDrift",
    "OwnershipViolation",
    "PreviewNotFound",
    "PolicySource",
    "MappingPolicySource",
    "PolicyDecision",
    "PolicyEngine",
    "Store",
    "MemoryStore",
    "OperatorContext",
    "Preview",
    "ApplyResult",
    "ApplyStatus",
    "__version__",
]
