# SPDX-License-Identifier: Apache-2.0
"""Audit chains + oversight bundles — linkage, export, verification, tampering."""
from __future__ import annotations

import pytest

from hashgate.canonical import canonical_hash
from hashgate.errors import AlreadyApplied, EvidenceNotFound, HashMismatch
from hashgate.evidence import (
    BUNDLE_FORMAT,
    EvidenceExporter,
    order_chain_events,
    verify_bundle,
)
from hashgate.gate import Gate
from hashgate.policy import MappingPolicySource, PolicyEngine
from hashgate.store import MemoryStore
from hashgate.types import OperatorContext

_OP = OperatorContext(operator_id="operator:basti", reason="review ok", channel="cockpit-ui")


class MergeAction:
    action_type = "pr_merge"
    feature_flag = "pr_merge_enabled"

    def __init__(self, head_sha: str = "a" * 40):
        self.head_sha = head_sha

    async def derive(self, ctx):
        return {"repo": "acme/api", "pr": 7, "head_sha": self.head_sha}

    async def validate(self, ctx, payload):
        return None

    def idempotency_key(self, ctx, payload):
        return f"merge:{payload['repo']}:{payload['head_sha']}"

    async def apply(self, ctx, payload):
        return {"merged_sha": payload["head_sha"]}


def _gate(store: MemoryStore) -> Gate:
    return Gate(
        store=store,
        policy=PolicyEngine(source=MappingPolicySource(
            flags={"pr_merge_enabled": True}, policies={"pr_merge": "allow"})),
    )


# --- chain linkage -------------------------------------------------------------
async def test_happy_chain_is_linked_preview_to_applied() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    preview = await gate.preview(action, None, _OP)
    await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    events = await store.list_chain_events(preview.chain_id)
    ordered = order_chain_events(events)
    assert [e["kind"] for e in ordered] == ["preview", "applied"]
    assert ordered[0]["event_id"] == preview.chain_id  # preview event roots the chain
    assert ordered[0]["prev_event_id"] is None
    assert ordered[1]["prev_event_id"] == ordered[0]["event_id"]
    assert all(e["chain_id"] == preview.chain_id for e in ordered)


async def test_refusal_and_replay_attach_to_the_same_chain() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    preview = await gate.preview(action, None, _OP)
    await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    with pytest.raises(AlreadyApplied):
        await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    ordered = order_chain_events(await store.list_chain_events(preview.chain_id))
    assert [e["kind"] for e in ordered] == ["preview", "applied", "already_applied"]


async def test_mismatch_joins_the_stale_previews_chain() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    preview = await gate.preview(action, None, _OP)
    action.head_sha = "b" * 40  # the agent pushed after the preview
    with pytest.raises(HashMismatch):
        await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    ordered = order_chain_events(await store.list_chain_events(preview.chain_id))
    assert [e["kind"] for e in ordered] == ["preview", "hash_mismatch"]
    assert ordered[1]["expected_hash"] == preview.payload_hash


async def test_re_preview_after_mismatch_starts_a_new_chain() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    p1 = await gate.preview(action, None, _OP)
    action.head_sha = "b" * 40
    with pytest.raises(HashMismatch):
        await gate.accept(action, None, _OP, expected_hash=p1.payload_hash)
    p2 = await gate.preview(action, None, _OP)  # operator reviews the new state
    assert p2.chain_id != p1.chain_id
    assert [e["kind"] for e in await store.list_chain_events(p2.chain_id)] == ["preview"]


# --- export ---------------------------------------------------------------------
async def test_export_by_apply_id_equals_export_by_chain() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    preview = await gate.preview(action, None, _OP)
    result = await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    exporter = EvidenceExporter(store=store)
    by_apply = await exporter.export_oversight_bundle(result.apply_id)
    by_chain = await exporter.export_oversight_bundle_by_chain(preview.chain_id)
    assert by_apply == by_chain
    assert by_apply["bundle_format"] == BUNDLE_FORMAT
    assert by_apply["outcome"] == "applied"
    assert by_apply["event_count"] == 2
    assert verify_bundle(by_apply).valid


async def test_refusal_chain_exports_a_full_value_bundle() -> None:
    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    preview = await gate.preview(action, None, _OP)
    action.head_sha = "b" * 40
    with pytest.raises(HashMismatch):
        await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    bundle = await EvidenceExporter(store=store).export_oversight_bundle_by_chain(
        preview.chain_id)
    assert bundle["outcome"] == "hash_mismatch"
    assert [e["kind"] for e in bundle["events"]] == ["preview", "hash_mismatch"]
    mismatch = bundle["events"][1]
    assert mismatch["expected_hash"] == preview.payload_hash
    assert mismatch["derived_hash"] != preview.payload_hash
    assert verify_bundle(bundle).valid
    # no payload bodies anywhere in the bundle
    assert "repo" not in str(bundle)


async def test_export_unknown_ids_refuse() -> None:
    exporter = EvidenceExporter(store=MemoryStore())
    with pytest.raises(EvidenceNotFound):
        await exporter.export_oversight_bundle("nope")
    with pytest.raises(EvidenceNotFound):
        await exporter.export_oversight_bundle_by_chain("nope")


async def test_signer_hook_sits_outside_the_sealed_content() -> None:
    class FakeSigner:
        def sign(self, bundle_hash: str) -> dict:
            return {"alg": "fake", "sig": f"signed:{bundle_hash[:8]}"}

    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    preview = await gate.preview(action, None, _OP)
    await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    bundle = await EvidenceExporter(store=store, signer=FakeSigner()) \
        .export_oversight_bundle_by_chain(preview.chain_id)
    assert bundle["signature"]["sig"].startswith("signed:")
    assert verify_bundle(bundle).valid  # signature is excluded from the seal


# --- integrity / tampering -----------------------------------------------------
async def _bundle() -> dict:
    store = MemoryStore()
    gate = _gate(store)
    action = MergeAction()
    preview = await gate.preview(action, None, _OP)
    await gate.accept(action, None, _OP, expected_hash=preview.payload_hash)
    return await EvidenceExporter(store=store).export_oversight_bundle_by_chain(
        preview.chain_id)


async def test_bundle_hash_self_exclusion_pinned() -> None:
    bundle = await _bundle()
    body = {k: v for k, v in bundle.items() if k not in ("bundle_hash", "signature")}
    assert canonical_hash(body) == bundle["bundle_hash"]


async def test_tampered_event_field_fails_verification() -> None:
    bundle = await _bundle()
    bundle["events"][1]["operator_id"] = "operator:mallory"
    verdict = verify_bundle(bundle)
    assert not verdict.valid
    assert any("bundle_hash mismatch" in p for p in verdict.problems)


async def test_removed_event_fails_even_with_recomputed_hash() -> None:
    bundle = await _bundle()
    del bundle["events"][0]  # drop the preview event, then re-seal
    body = {k: v for k, v in bundle.items() if k not in ("bundle_hash", "signature")}
    bundle["bundle_hash"] = canonical_hash(body)
    verdict = verify_bundle(bundle)
    assert not verdict.valid  # linkage/root checks catch it despite a valid seal
    assert any("root" in p or "chain_id" in p for p in verdict.problems)


async def test_changed_bundle_hash_fails() -> None:
    bundle = await _bundle()
    bundle["bundle_hash"] = "f" * 64
    assert not verify_bundle(bundle).valid


async def test_reordered_events_fail_linkage() -> None:
    bundle = await _bundle()
    bundle["events"] = list(reversed(bundle["events"]))
    body = {k: v for k, v in bundle.items() if k not in ("bundle_hash", "signature")}
    bundle["bundle_hash"] = canonical_hash(body)
    verdict = verify_bundle(bundle)
    assert not verdict.valid
    assert any("linkage" in p or "root" in p for p in verdict.problems)


def test_order_chain_events_refuses_gaps_and_ambiguity() -> None:
    a = {"event_id": "a", "prev_event_id": None}
    b = {"event_id": "b", "prev_event_id": "a"}
    orphan = {"event_id": "x", "prev_event_id": "missing"}
    assert [e["event_id"] for e in order_chain_events([b, a])] == ["a", "b"]
    with pytest.raises(EvidenceNotFound):
        order_chain_events([a, b, orphan])
    with pytest.raises(EvidenceNotFound):
        order_chain_events([a, {"event_id": "a2", "prev_event_id": None}, b])
