# hashgate

**Execution governance for AI agents: cryptographically bound human oversight.**

hashgate gates the effects of AI agents behind an operator accept that is
bound to a canonical hash of *exactly* what the operator reviewed — and
re-derived server-side at accept time. Others log what your agent did;
hashgate makes it provable that the agent could only do what a human approved
by hash. It executes nothing on its own: no auto-accept, no scheduler.

## The core idea, in one scenario

A coding agent opens a pull request. The operator previews the merge payload —
repo, PR number, **`head_sha`**, diff stat — and accepts by echoing its
canonical hash. Between preview and accept, the agent pushes another commit.

With a plain "Approve" button, the approval silently applies to whatever the
branch points at by then. With hashgate, the accept **bursts automatically**:
the server re-derives the payload, the `head_sha` changed, the hash no longer
matches, nothing is merged — and the refusal itself becomes a verifiable
evidence bundle: *the agent tried, the gate prevented it, and you can prove
it.* Run it yourself (offline, fake PR):

```bash
python examples/pr_merge_gate/pr_merge_gate.py
```

## Quickstart

```python
from hashgate import (
    Gate, MemoryStore, OperatorContext,
    PolicyEngine, MappingPolicySource, ValidationFailed,
)

class PRMergeAction:
    action_type = "pr_merge"
    feature_flag = "pr_merge_enabled"

    async def derive(self, pr) -> dict:
        # pure, read-only, deterministic — the operator reviews THIS
        return {"repo": pr.repo, "pr": pr.number, "head_sha": pr.head_sha,
                "files_changed": pr.diff_stat()}

    async def validate(self, pr, payload) -> None:
        if payload["files_changed"]["total"] > 50:
            raise ValidationFailed("diff too large for a gated merge")

    def idempotency_key(self, pr, payload) -> str:
        return f"merge:{payload['repo']}:{payload['head_sha']}"

    async def apply(self, pr, payload) -> dict:
        pr.merge(sha=payload["head_sha"])          # SHA-pinned effect
        return {"merged_sha": payload["head_sha"]}

gate = Gate(
    store=MemoryStore(),  # or the SQLAlchemy adapter (hashgate[sqlalchemy])
    policy=PolicyEngine(source=MappingPolicySource(
        flags={"pr_merge_enabled": True}, policies={"pr_merge": "allow"})),
)

preview = await gate.preview(action, pr, OperatorContext(
    operator_id="operator:alex", reason="reviewed diff, tests green"))
# ... operator reviews preview.payload, then echoes preview.payload_hash:
result = await gate.accept(action, pr, op, expected_hash=preview.payload_hash)
```

`accept` enforces exactly this order — pinned both behaviorally and
structurally in the test suite:

1. policy check (fail-closed, re-checked — never trust the preview)
2. server-side re-derivation (or frozen-bytes load)
3. hash compare against the operator-echoed `expected_hash`
4. `validate`
5. **atomic** idempotency claim — after the hash match, before apply
6. `apply`
7. result + audit

## Concepts

**Gate / GatedAction.** The `Gate` owns the mechanics; your domain lives in a
`GatedAction` with four hooks (`derive`, `validate`, `idempotency_key`,
`apply`). `derive` must be deterministic and side-effect-free; hashgate
surfaces non-determinism as a `HashMismatch`. `apply` never runs without a
fresh policy check, a hash match and an atomic claim.

**Deterministic vs. frozen payloads.** The default mode re-derives at accept
time — the strongest guarantee (the accept binds to a re-computable
derivation). For sources that cannot re-derive deterministically (LLM
output), `FrozenPayloadAction` derives ONCE at preview, freezes the payload,
and accept binds to the stored bytes (re-hash tamper check; unknown hash →
`PreviewNotFound`). The trade-off is explicit: frozen binds to stored bytes,
not to a re-computable derivation.

**Fail-closed policy.** Flags default off, per-action policies default deny,
a broken policy source is a deny, and an allow is never blank — it is
`allow_with_gates`: hash match, validation and the idempotency claim still
stand between the policy and any effect.

**Ownership.** Resources owned by another operator are never silently resumed
or forked. Takeover is explicit and bound to the expected owner AND expected
state (`OwnershipViolation` and `StateDrift` are distinct errors); it mutates
only the owner, plus one audit event.

**Idempotency.** `Store.try_claim_idempotency` must be atomic (the reference
SQLAlchemy adapter claims via a unique-constraint INSERT; race-tested:
N concurrent claims, exactly one winner). A replayed accept is either an
`AlreadyApplied` error (HTTP 409) or an `ALREADY_APPLIED` result — per action.

**Evidence bundles.** Every flow leaves a linked audit chain (preview is the
chain root; every event carries `chain_id` + `prev_event_id`). Chains export
as self-contained, sealed bundles — **refusal chains too**, because "the
agent tried, the gate prevented it" is a central evidence case. Receivers
verify with `verify_bundle` (seal integrity, gap-free linkage, chronology)
without needing hashgate's store. A refusal bundle, trimmed:

```jsonc
{
  "bundle_format": "hashgate-oversight-bundle-v1",
  "canon_version": "hashgate-canon-v1",
  "chain_id": "229c74985ac6…",
  "action_type": "pr_merge",
  "outcome": "hash_mismatch",
  "event_count": 2,
  "events": [
    { "kind": "preview", "event_id": "229c74985ac6…", "prev_event_id": null,
      "operator_id": "operator:alex", "reason": "reviewed diff, 3 files, tests green",
      "channel": "cockpit-ui", "payload_hash": "916c06d12821…",
      "at": "2026-07-02T10:57:19.324404+00:00" },
    { "kind": "hash_mismatch", "event_id": "8018e433ece1…", "prev_event_id": "229c74985ac6…",
      "operator_id": "operator:alex",
      "expected_hash": "916c06d12821…",   // what the operator approved
      "derived_hash": "3e18f93f2f9f…",    // what the server re-derived
      "at": "2026-07-02T10:57:19.324424+00:00" }
  ],
  "bundle_hash": "40a46ac5905df423…"      // canonical hash over the bundle itself
}
```

And a happy-path bundle ends in `"outcome": "applied"` with the effects
summary on the `applied` event:

```jsonc
{
  "outcome": "applied", "event_count": 2,
  "events": [
    { "kind": "preview", "payload_hash": "916c06d12821…", "…": "…" },
    { "kind": "applied", "payload_hash": "916c06d12821…",
      "idempotency_key": "merge:acme/api:9fceb02d0ae5…",
      "feature_flag": "pr_merge_enabled", "policy_decision": "allow_with_gates",
      "effects": { "merged_sha": "9fceb02d0ae5…" } }
  ],
  "bundle_hash": "aa94c3472b30…"
}
```

Events carry IDs, hashes, operator identity/reason/channel, timestamps and
redacted effect summaries — never payload bodies, never secrets (allowlist-
first redaction is built in). Signatures are a hook (`BundleSigner`); no
cryptography ships in v0.1.

## Claude Code integration (first real consumer)

`hashgate[server]` ships a local gate server + operator CLI that hooks into
Claude Code's PreToolUse event: `git push` / `git merge` issued by the agent
are denied until the operator approves them — hash-bound to the repository's
**current HEAD SHA, the remote-tracking state and the full transported commit
list**, single-use, expiring. If the agent commits again after the approval
(or the remote moves), the next attempt re-derives a different hash and the
stale approval never fires. This holds for **subagents too** — confirmed
end-to-end: delegated subagent tool calls are gated the same way, and their
provenance is recorded in the evidence chain. The recommended wiring is a
**fail-closed command-hook wrapper**: Claude Code's own hook transport is
fail-open on errors; the wrapper turns "gate server down" into "gated action
blocked" (exit 2) while harmless commands keep flowing. Agent-issued
`hashgate accept` commands are always denied (self-approval guard).
Setup: [`docs/claude_code_setup.md`](docs/claude_code_setup.md).

## Canonical serialization

Every guarantee hangs on the hash, so the serialization is specified
normatively and versioned: JSON, sorted keys, compact separators, real UTF-8,
version prefix `hashgate-canon-v1:`, SHA-256. **Floats are rejected.** A
format change is a new canon version, never a silent edit — golden fixtures
enforce it. Read [`docs/SPEC_canonical.md`](docs/SPEC_canonical.md).

## Design decisions (v0.1)

- **Async-first, sync wrapper on demand.** The store protocol and gate are
  `async` (the reference adapter is async SQLAlchemy). No sync wrapper ships
  in v0.1 — one will be added when a real sync consumer needs it.
- **Dependency-free core** (Python ≥ 3.11); SQLAlchemy only as the optional
  `hashgate[sqlalchemy]` extra.
- **No auto-accept, no scheduler** in the core — deliberately out of scope.
- **Refusals are audited.** Policy denials and hash mismatches produce chain
  events (with both hashes), not silence.
- Extracted from a production agent-runtime project where the pattern ran
  end-to-end (goal → plan → artifacts → completion, including recovery and
  cross-operator takeover).

## Regulatory context

hashgate supports the technical implementation of oversight and logging
requirements (for example those described in EU AI Act Articles 12 and 14):
enforced pre-effect human approval, cryptographic binding between what was
reviewed and what executes, and exportable, verifiable evidence of both
approvals and refusals. It does not, by itself, make any system compliant
with any regulation; legal assessment remains the responsibility of the
operator.

## Status / roadmap

v0.1 (this repo): canonical spec + golden fixtures, Gate/GatedAction with the
structurally pinned accept order, frozen payloads, fail-closed policy engine,
atomic idempotency store (in-memory + async SQLAlchemy), ownership guard,
allowlist-first redaction, audit chains + verifiable oversight bundles,
PR-merge reference example, Claude Code hook integration (gate server +
operator CLI + fail-closed wrapper).

Deliberately NOT in v0.1 (roadmap candidates): sync wrapper, real signature
implementations, framework middleware (FastAPI request-level), further
agent-tool integrations, retention/export tooling.

## License

Apache-2.0 — see [LICENSE](LICENSE). Contributions: see
[CONTRIBUTING.md](CONTRIBUTING.md).
