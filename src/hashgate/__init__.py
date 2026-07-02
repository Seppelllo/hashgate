# SPDX-License-Identifier: Apache-2.0
"""hashgate — execution governance for AI agents.

Preview -> canonical hash -> operator accept -> server-side re-derivation ->
apply. Fail-closed (transport and policy semantics), idempotent, audited.

hashgate executes nothing itself; it gates. There is no auto-accept and no
scheduler in the core. It is a governance/oversight layer, not a sandbox —
see docs/threat_model.md for the threat model.
"""
from hashgate.action import (
    ALREADY_APPLIED_RAISE,
    ALREADY_APPLIED_RESULT,
    FrozenPayloadAction,
    GatedAction,
)
from hashgate.canonical import CANONICAL_VERSION, HASH_ALGO, canonical_bytes, canonical_hash
from hashgate.errors import (
    AlreadyApplied,
    CanonicalizationError,
    EvidenceNotFound,
    HashgateError,
    HashMismatch,
    OwnershipViolation,
    PolicyDenied,
    PreviewNotFound,
    StateDrift,
    ValidationFailed,
)
from hashgate.evidence import (
    BUNDLE_FORMAT,
    BundleSigner,
    BundleVerification,
    EvidenceExporter,
    order_chain_events,
    verify_bundle,
)
from hashgate.gate import Gate
from hashgate.ownership import OwnedResource, OwnershipGuard, TakeoverResult
from hashgate.policy import MappingPolicySource, PolicyDecision, PolicyEngine, PolicySource
from hashgate.redact import Redactor, redact_payload
from hashgate.store import MemoryStore, Store
from hashgate.types import ApplyResult, ApplyStatus, OperatorContext, Preview

__version__ = "0.1.1"

__all__ = [
    "Gate",
    "EvidenceExporter",
    "EvidenceNotFound",
    "BundleSigner",
    "BundleVerification",
    "BUNDLE_FORMAT",
    "verify_bundle",
    "order_chain_events",
    "GatedAction",
    "FrozenPayloadAction",
    "ALREADY_APPLIED_RAISE",
    "ALREADY_APPLIED_RESULT",
    "OwnedResource",
    "OwnershipGuard",
    "TakeoverResult",
    "Redactor",
    "redact_payload",
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
