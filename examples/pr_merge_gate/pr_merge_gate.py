# SPDX-License-Identifier: Apache-2.0
"""PR-merge gate — the hashgate reference example.

A coding agent produced a pull request; hashgate gates the merge. Because the
PR's ``head_sha`` is part of the hashed payload, the accept automatically
fails if the agent pushes ANOTHER commit after the operator previewed — the
operator approved something other than what would be merged. That is the
value of server-side re-derivation over a plain "Approve" button.

Runs fully offline: the PR and the merge API are fakes.

    python examples/pr_merge_gate/pr_merge_gate.py
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

try:
    import hashgate  # noqa: F401  (installed package)
except ModuleNotFoundError:  # running from a repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from hashgate import (
    EvidenceExporter,
    Gate,
    HashMismatch,
    MappingPolicySource,
    MemoryStore,
    OperatorContext,
    PolicyEngine,
    ValidationFailed,
    verify_bundle,
)


# --- fake world (no network, no real GitHub) ---------------------------------
class FakePullRequest:
    def __init__(self) -> None:
        self.repo = "acme/api"
        self.number = 1337
        self.head_sha = "9fceb02d0ae598e95dc970b74767f19372d61af8"
        self.files_changed = {"total": 3, "additions": 120, "deletions": 8}

    def push_new_commit(self, sha: str) -> None:
        """The agent keeps working after the operator previewed…"""
        self.head_sha = sha


class FakeMergeApi:
    def __init__(self) -> None:
        self.merged: list[tuple[str, int, str]] = []

    def merge(self, repo: str, pr: int, *, sha: str) -> None:
        # SHA-pinned merge: the API merges exactly the reviewed commit
        self.merged.append((repo, pr, sha))


# --- the gated action ---------------------------------------------------------
class PRMergeAction:
    """derive() reads the PR's head_sha + diff stat (read-only, deterministic
    relative to the PR state); apply() calls the merge API SHA-pinned."""

    action_type = "pr_merge"
    feature_flag = "pr_merge_enabled"

    def __init__(self, api: FakeMergeApi):
        self.api = api

    async def derive(self, pr: FakePullRequest) -> dict:
        return {
            "repo": pr.repo,
            "pr": pr.number,
            "head_sha": pr.head_sha,  # part of the hashed payload!
            "files_changed": dict(pr.files_changed),
        }

    async def validate(self, pr: FakePullRequest, payload: dict) -> None:
        if payload["files_changed"]["total"] > 50:
            raise ValidationFailed("diff too large for a gated merge",
                                   code="diff_too_large")

    def idempotency_key(self, pr: FakePullRequest, payload: dict) -> str:
        return f"merge:{payload['repo']}:{payload['head_sha']}"

    async def apply(self, pr: FakePullRequest, payload: dict) -> dict:
        self.api.merge(payload["repo"], payload["pr"], sha=payload["head_sha"])
        return {"merged_sha": payload["head_sha"]}


def _brief(bundle: dict) -> str:
    lines = [f"  bundle: outcome={bundle['outcome']}  events={bundle['event_count']}  "
             f"hash={bundle['bundle_hash'][:16]}…"]
    for event in bundle["events"]:
        lines.append(f"    - {event['kind']:14s} by {event['operator_id']} "
                     f"payload_hash={str(event['payload_hash'])[:16]}…")
    verdict = verify_bundle(bundle)
    lines.append(f"  verify_bundle: valid={verdict.valid} {list(verdict.problems)}")
    return "\n".join(lines)


async def main() -> None:
    operator = OperatorContext(operator_id="operator:alex",
                               reason="reviewed diff, tests green", channel="cli")

    # --- scenario A: happy path ------------------------------------------------
    print("=== Scenario A: preview -> accept -> SHA-pinned merge ===")
    api = FakeMergeApi()
    store = MemoryStore()
    gate = Gate(store=store, policy=PolicyEngine(source=MappingPolicySource(
        flags={"pr_merge_enabled": True}, policies={"pr_merge": "allow"})))
    pr = FakePullRequest()
    action = PRMergeAction(api)

    preview = await gate.preview(action, pr, operator)
    print(f"operator reviews: {json.dumps(preview.payload)}")
    print(f"operator accepts hash {preview.payload_hash[:16]}…")
    result = await gate.accept(action, pr, operator, expected_hash=preview.payload_hash)
    print(f"merged: {api.merged}  status={result.status.value}")
    bundle = await EvidenceExporter(store=store).export_oversight_bundle(result.apply_id)
    print(_brief(bundle))

    # --- scenario B: the agent pushes AFTER the preview -------------------------
    print()
    print("=== Scenario B: agent pushes after the preview -> accept bursts ===")
    api = FakeMergeApi()
    store = MemoryStore()
    gate = Gate(store=store, policy=PolicyEngine(source=MappingPolicySource(
        flags={"pr_merge_enabled": True}, policies={"pr_merge": "allow"})))
    pr = FakePullRequest()
    action = PRMergeAction(api)

    preview = await gate.preview(action, pr, operator)
    print(f"operator reviews head_sha {preview.payload['head_sha'][:12]}… "
          f"and accepts hash {preview.payload_hash[:16]}…")
    pr.push_new_commit("3b18e512dba79e4c8300dd08aeb37f8e728b8dad")
    print(f"meanwhile the agent pushes {pr.head_sha[:12]}… — the operator never saw it")
    try:
        await gate.accept(action, pr, operator, expected_hash=preview.payload_hash)
    except HashMismatch as exc:
        print(f"accept refused: HashMismatch ({exc})")
    print(f"merged: {api.merged}  <- nothing was merged")
    bundle = await EvidenceExporter(store=store).export_oversight_bundle_by_chain(
        preview.chain_id)
    print(_brief(bundle))


if __name__ == "__main__":
    asyncio.run(main())
