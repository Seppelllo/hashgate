# SPDX-License-Identifier: Apache-2.0
"""hashgate error taxonomy.

Deliberately narrow so API consumers never have to guess. Every error carries:

- ``code``: a stable, machine-readable string (safe to expose in API payloads),
- ``http_status``: the suggested HTTP mapping (403 policy, 409 state/idempotency,
  400 validation, 404 lookup),
- ``blocked_reasons``: optional machine-readable detail list.

This mirrors the convention that converged in the production agent-runtime
project hashgate was extracted from (``http_status`` + ``code`` +
``blocked_reasons`` on the exception class), which allows a single generic
exception-to-HTTP adapter on the consumer side.
"""
from __future__ import annotations


class HashgateError(Exception):
    """Base class for all hashgate errors."""

    code: str = "hashgate_error"
    http_status: int = 500

    def __init__(
        self,
        message: str = "",
        *,
        code: str | None = None,
        blocked_reasons: list[str] | None = None,
    ) -> None:
        if code is not None:
            self.code = code
        super().__init__(message or self.code)
        self.blocked_reasons: list[str] = list(blocked_reasons or [])


class CanonicalizationError(HashgateError):
    """The payload cannot be canonically serialized (e.g. contains a float,
    a non-string dict key, or an unsupported type). See docs/SPEC_canonical.md."""

    code = "canonicalization_error"
    http_status = 400


class PolicyDenied(HashgateError):
    """A feature flag is off or the action policy is deny (fail-closed default)."""

    code = "policy_denied"
    http_status = 403


class ValidationFailed(HashgateError):
    """The action's validate() hook rejected the payload, or a required
    parameter (operator_id, reason, expected_hash) is missing/malformed."""

    code = "validation_failed"
    http_status = 400


class HashMismatch(HashgateError):
    """The server-side re-derivation produced a different hash than the one
    the operator accepted. Carries both hashes (hashes are safe to expose;
    payload bodies are not)."""

    code = "hash_mismatch"
    http_status = 409

    def __init__(
        self,
        message: str = "",
        *,
        expected_hash: str | None = None,
        derived_hash: str | None = None,
        blocked_reasons: list[str] | None = None,
    ) -> None:
        super().__init__(message, blocked_reasons=blocked_reasons)
        self.expected_hash = expected_hash
        self.derived_hash = derived_hash


class AlreadyApplied(HashgateError):
    """The idempotency key was already claimed — the logical effect has
    happened (or is happening). Maps to HTTP 409."""

    code = "already_applied"
    http_status = 409

    def __init__(
        self,
        message: str = "",
        *,
        idempotency_key: str | None = None,
        blocked_reasons: list[str] | None = None,
    ) -> None:
        super().__init__(message, blocked_reasons=blocked_reasons)
        self.idempotency_key = idempotency_key


class StateDrift(HashgateError):
    """An expected precondition (state, target identity, …) no longer holds."""

    code = "state_drift"
    http_status = 409


class OwnershipViolation(HashgateError):
    """An operator acted on a resource owned by a different operator without
    an explicit takeover."""

    code = "ownership_violation"
    http_status = 409


class PreviewNotFound(HashgateError):
    """A frozen preview was referenced by an unknown id/hash (FrozenPayload
    flows look previews up instead of re-deriving)."""

    code = "preview_not_found"
    http_status = 404
