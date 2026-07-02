# SPDX-License-Identifier: Apache-2.0
"""GatedAction — the central extension interface.

A GatedAction is anything that follows the pattern: derive deterministically
-> show the operator -> apply hash-bound. Domain logic lives in the
implementation's four hooks; the :class:`hashgate.gate.Gate` enforces the
invariants around them:

- ``derive()`` runs AGAIN server-side at accept time and the hash is
  compared. The implementation must be deterministic; hashgate surfaces
  non-determinism as a :class:`hashgate.errors.HashMismatch`.
- ``apply()`` is never called without a prior hash match.
- ``apply()`` is never called twice for the same idempotency key.

Two payload modes:

- **Deterministic (default):** the strongest guarantee — the server binds
  the operator's accept to a re-computable derivation, not to stored data.
- **Frozen** (``frozen = True``, :class:`FrozenPayloadAction`): for
  non-deterministic sources (LLM output). ``derive()`` runs ONCE at preview
  time, the payload is frozen in the store, and accept re-hashes the STORED
  payload instead of re-deriving. Documented trade-off: the guarantee is
  weaker — the server binds to stored bytes (integrity-checked by re-hash),
  not to a re-computable derivation.
"""
from __future__ import annotations

from typing import Any, Protocol, TypeVar

Ctx = TypeVar("Ctx", contravariant=True)

#: values for the optional ``already_applied_mode`` attribute
ALREADY_APPLIED_RAISE = "raise"  # default: raise AlreadyApplied (HTTP 409)
ALREADY_APPLIED_RESULT = "result"  # return ApplyResult(status=ALREADY_APPLIED)


class GatedAction(Protocol[Ctx]):
    """Implemented by the consumer; the gate only ever calls these hooks.

    Optional class attributes (read via ``getattr`` with these defaults):

    - ``already_applied_mode = "raise"`` — how a second accept behaves
      (``"raise"`` -> :class:`AlreadyApplied`; ``"result"`` -> an
      ``ApplyResult`` with status ``ALREADY_APPLIED``).
    - ``frozen = False`` — see :class:`FrozenPayloadAction`.
    """

    action_type: str
    feature_flag: str

    async def derive(self, ctx: Ctx) -> dict[str, Any]:
        """Pure, read-only, deterministic. Zero side effects. May be
        expensive (DB reads) but must never write. No timestamps, no floats,
        no secrets in the returned payload (see docs/SPEC_canonical.md §6)."""
        ...

    async def validate(self, ctx: Ctx, payload: dict[str, Any]) -> None:
        """Raise :class:`hashgate.errors.ValidationFailed` to refuse.
        Registries, allowlists, secret scans, size limits live here."""
        ...

    def idempotency_key(self, ctx: Ctx, payload: dict[str, Any]) -> str:
        """Unique per logical effect, e.g. ``f"merge:{repo}:{head_sha}"``."""
        ...

    async def apply(self, ctx: Ctx, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute the effect and return an effects summary (IDs, hashes —
        it ends up redacted in the audit trail). Must go through existing,
        reviewed services; hashgate cannot enforce that, but the contract
        makes it a condition: controllers never write state directly."""
        ...


class FrozenPayloadAction(GatedAction[Ctx], Protocol[Ctx]):
    """Variant for non-deterministic sources (LLM output).

    ``derive()`` runs ONCE (at preview); the payload is frozen and persisted.
    ``accept()`` looks the preview up by the operator-echoed hash
    (unknown hash -> :class:`hashgate.errors.PreviewNotFound`), re-hashes the
    STORED payload (tamper check) and never calls ``derive()`` again.

    Trade-off vs. the deterministic mode, stated plainly: the server binds
    the accept to stored bytes rather than to a re-computable derivation.
    Use this only where re-derivation is impossible in principle.
    """

    frozen: bool
