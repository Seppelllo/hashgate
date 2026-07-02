# SPDX-License-Identifier: Apache-2.0
"""Oversight evidence — audit chains and exportable, verifiable bundles.

Every gated flow leaves a linked audit chain: the preview event is the chain
root (``chain_id`` = its ``event_id``); every subsequent event on the same
flow carries the same ``chain_id`` plus a ``prev_event_id`` pointer. A
re-preview after a refusal derives a new payload/hash and therefore starts a
NEW chain — chains are per reviewed payload, not per intent.

An **oversight bundle** is a self-contained JSON document over one chain:
the full event sequence (who, when, which hash, what outcome), sealed with a
``bundle_hash`` (canonical hash over the bundle EXCLUDING the ``bundle_hash``
and ``signature`` fields). Refusal chains are first-class bundles: "the agent
tried, the gate prevented it" is a central evidence case, so bundles export
both by ``apply_id`` (applied outcomes) and by ``chain_id`` (any outcome).

:func:`verify_bundle` is the receiving side — an auditor checks hash
integrity, gap-free ``prev_event_id`` linkage and timestamp monotonicity
without needing hashgate's store.

Signatures are a hook only (:class:`BundleSigner`); no cryptography ships in
v0.1. A signature block sits OUTSIDE the hashed content and covers
``bundle_hash``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from hashgate.canonical import CANONICAL_VERSION, canonical_hash
from hashgate.errors import EvidenceNotFound
from hashgate.store import Store

BUNDLE_FORMAT = "hashgate-oversight-bundle-v1"

#: fields excluded from the bundle hash (seal + anything covering the seal)
_UNSEALED_FIELDS = ("bundle_hash", "signature")

#: per-event fields exported into a bundle (order fixed for readability)
_EVENT_FIELDS = (
    "event_id",
    "chain_id",
    "prev_event_id",
    "kind",
    "action_type",
    "operator_id",
    "reason",
    "channel",
    "payload_hash",
    "canon_version",
    "at",
)


class BundleSigner(Protocol):
    """Optional signing hook. ``sign`` receives the bundle_hash and returns a
    JSON-compatible signature block (algorithm, key id, signature, …).
    Implementations live outside hashgate v0.1."""

    def sign(self, bundle_hash: str) -> dict[str, Any]: ...


def order_chain_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order a chain's events by their ``prev_event_id`` linkage.

    Raises :class:`EvidenceNotFound` if the chain has no unique root or the
    linkage has gaps (store-side corruption should not export silently)."""
    if not events:
        return []
    by_prev: dict[Any, dict[str, Any]] = {}
    for event in events:
        prev = event.get("prev_event_id")
        if prev in by_prev:
            raise EvidenceNotFound(f"chain linkage is ambiguous at prev={prev!r}")
        by_prev[prev] = event
    ordered: list[dict[str, Any]] = []
    cursor: Any = None
    while cursor in by_prev:
        event = by_prev.pop(cursor)
        ordered.append(event)
        cursor = event.get("event_id")
    if by_prev:
        raise EvidenceNotFound("chain linkage has gaps (orphaned events)")
    return ordered


@dataclass(frozen=True)
class BundleVerification:
    valid: bool
    problems: tuple[str, ...] = ()


def verify_bundle(bundle: dict[str, Any]) -> BundleVerification:
    """Receiver-side verification: hash integrity (self-exclusion), gap-free
    prev_event_id linkage, consistent chain_id, chronological timestamps."""
    problems: list[str] = []
    body = {k: v for k, v in bundle.items() if k not in _UNSEALED_FIELDS}
    try:
        recomputed = canonical_hash(body)
    except Exception as exc:  # non-canonical content is a verification failure
        return BundleVerification(False, (f"bundle not canonicalizable: {exc}",))
    if bundle.get("bundle_hash") != recomputed:
        problems.append("bundle_hash mismatch (content was modified)")
    events = list(bundle.get("events") or [])
    if not events:
        problems.append("bundle has no events")
        return BundleVerification(False, tuple(problems))
    chain_id = bundle.get("chain_id")
    if events[0].get("prev_event_id") is not None:
        problems.append("first event is not a chain root (prev_event_id set)")
    if events[0].get("event_id") != chain_id:
        problems.append("chain_id is not the root event's event_id")
    for i, event in enumerate(events):
        if event.get("chain_id") != chain_id:
            problems.append(f"event {i} belongs to a different chain")
        if i > 0 and event.get("prev_event_id") != events[i - 1].get("event_id"):
            problems.append(f"linkage gap between event {i - 1} and event {i}")
    timestamps = [str(e.get("at") or "") for e in events]
    if any(a > b for a, b in zip(timestamps, timestamps[1:], strict=False)):
        problems.append("event timestamps are not chronological")
    return BundleVerification(not problems, tuple(problems))


@dataclass
class EvidenceExporter:
    """Builds self-contained oversight bundles from the audit store."""

    store: Store
    signer: BundleSigner | None = None

    async def export_oversight_bundle(self, apply_id: str) -> dict[str, Any]:
        """Bundle for an APPLIED outcome, addressed by its apply_id."""
        result = await self.store.load_apply(apply_id)
        if result is None:
            raise EvidenceNotFound(f"unknown apply_id {apply_id!r}")
        if not result.audit_event_id:
            raise EvidenceNotFound(f"apply {apply_id!r} carries no audit event")
        event = await self.store.get_audit_event(result.audit_event_id)
        if event is None or not event.get("chain_id"):
            raise EvidenceNotFound(f"apply {apply_id!r} has no audit chain")
        return await self.export_oversight_bundle_by_chain(str(event["chain_id"]))

    async def export_oversight_bundle_by_chain(self, chain_id: str) -> dict[str, Any]:
        """Bundle for ANY outcome — refusal chains (hash_mismatch,
        policy_denied, …) are full-value evidence and export the same way."""
        events = await self.store.list_chain_events(chain_id)
        if not events:
            raise EvidenceNotFound(f"unknown chain_id {chain_id!r}")
        ordered = order_chain_events(events)
        exported = [self._export_event(e) for e in ordered]
        last = exported[-1]
        bundle: dict[str, Any] = {
            "bundle_format": BUNDLE_FORMAT,
            "canon_version": CANONICAL_VERSION,
            "chain_id": chain_id,
            "action_type": last.get("action_type"),
            "outcome": last.get("kind"),
            "event_count": len(exported),
            "events": exported,
        }
        bundle["bundle_hash"] = canonical_hash(bundle)
        if self.signer is not None:
            bundle["signature"] = dict(self.signer.sign(bundle["bundle_hash"]))
        return bundle

    @staticmethod
    def _export_event(event: dict[str, Any]) -> dict[str, Any]:
        exported: dict[str, Any] = {name: event.get(name) for name in _EVENT_FIELDS}
        # everything beyond the fixed fields (effects summary, expected/derived
        # hashes, blocked_reasons, …) was redacted at emit time and rides along
        extra = {
            k: v
            for k, v in event.items()
            if k not in _EVENT_FIELDS and k not in ("created_at",)
        }
        exported.update(extra)
        return exported
