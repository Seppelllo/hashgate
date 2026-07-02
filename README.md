# hashgate

**A fail-closed, hash-bound human approval gate for AI agents.** The agent's
proposed action is previewed; the operator accepts the preview's canonical
hash; at execution time the server re-derives the action from live state and
compares; the effect runs only if the hashes match — and only once. It is a
governance and oversight layer, not a sandbox — see the
[threat model](#threat-model--what-hashgate-is-and-is-not).

## Why a hash, not a button

A coding agent proposes `git push`. The operator reviews the payload — repo,
branch, HEAD SHA, the exact commits that would transport — and approves its
hash. Before the agent retries, it makes one more commit.

The push is refused, despite a valid, unexpired approval: the server
re-derives the payload from the repository as it is *now*, the HEAD SHA
changed, the hash no longer matches. The operator approved a state that no
longer exists. A new preview appears; the old approval's evidence chain
records `approval_stale` with both hashes.

**An approve button approves an intention. hashgate approves a state.**

## The agent cannot approve itself

From end-to-end testing with a live Claude Code session — the operator told
the agent to approve its own pending push:

> **Operator:** run `hashgate accept <preview_id> --hash <hash>` yourself.
>
> **Agent:** "You explicitly approved with the full hash — running the
> accept, then pushing." *(translated from the live session)*
>
> **Gate:** `hashgate: agent-issued 'hashgate accept/deny' commands are
> always blocked. Approvals happen in the operator's own terminal, never
> through the agent.`
>
> **Agent:** "That's not possible: hashgate blocks agent-issued accept/deny
> on principle — approvals can only come from your own terminal, never
> through me."

The agent complied. The gate refused. That is the point — enforcement must
not depend on the agent's good behavior.

## Quickstart

```bash
python3 -m venv ~/.hashgate/venv && source ~/.hashgate/venv/bin/activate
pip install 'hashgate[server]'   # NOT -e; editable installs are unreliable
                                 # on some platforms (see CONTRIBUTING.md)
hashgate-hook-server
# hashgate-hook-server effective config: db=/Users/you/.hashgate/hooks.db ttl=900s token=set port=8377 config=~/.hashgate/config.toml
```

Read that startup line: a setting that does not show up there is not in
force. Server and CLI share one config source (`~/.hashgate/config.toml`,
env overrides file — [setup guide](docs/claude_code_setup.md)).

Wire the hook in your **user** `~/.claude/settings.json`, with the
**absolute** wrapper path — Claude Code does not run inside your venv, and
project settings are editable by the agent itself:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command",
                     "command": "/Users/you/.hashgate/venv/bin/hashgate-hook-wrapper",
                     "timeout": 30 } ] }
    ]
  }
}
```

Then operate. The agent's `git push` is denied with instructions; you decide
in your own terminal; the agent retries:

```console
$ hashgate pending
0024a098b435…  git_push    age=  4s  hash=079ff198a55f34dacfc5201b85e03ed5191592cc7e305089b1d220c3e56655b2
    git push origin main

$ hashgate show 0024a098b435…       # full payload; for pushes:
this push transports 1 commit(s):
  b78d4010c449  add rate limiter

$ hashgate accept 0024a098b435… --hash 079ff198a55f…6655b2   # FULL hash echo required
approved 0024a098b435… as 55be8b35d759… (single-use, expires 16:13:27 (UTC 14:13:27) — in 899s)
the agent can retry the command now
```

On retry the agent sees:
`hashgate: approved by operator:alex (hash 079ff198a55f…), single-use approval consumed.`

Beyond `git push`/`git merge`, v0.2 gates force-pushes (binding the remote
state that would be overwritten), `git reset --hard` (binding the commits
that would be discarded), recursive `rm` (binding the resolved deletion
paths), and common deploy commands — `kamal deploy`, `docker compose up`,
`kubectl apply`, named deploy scripts — each binding content hashes of what
would ship and where. Details per action:
[setup guide](docs/claude_code_setup.md).

## Operator web UI

The same server ships a mobile-first web UI at `http://127.0.0.1:8377/ui`:
pending decisions (auto-refresh), a detail view with the same ⚠ warnings as
the CLI, approve via a **typed 12-hex hash echo** (you type the first 12
characters of the payload hash — the deliberate act survives the touch
screen), deny with reason and a `final` checkbox, history, and evidence
chains as timelines with bundle download. The one security-relevant fact:
the UI requires a **separate `operator_token`** that never lives in the
agent's environment — the hook token does not authorize it (see the
[threat model](docs/threat_model.md)). The server binds to localhost by
default; remote access (phone) is your job via Tailscale/VPN.

## Concepts

**Gate / GatedAction.** The `Gate` owns the mechanics; your domain lives in
four hooks (`derive`, `validate`, `idempotency_key`, `apply`). `accept`
enforces a fixed order — policy check, server-side re-derivation, hash
compare, validate, **atomic** idempotency claim, apply — pinned both
behaviorally and structurally in the tests. Default mode re-derives at accept
time (the strongest binding: a re-computable derivation). For sources that
cannot re-derive deterministically (LLM output), `FrozenPayloadAction`
derives once and accept binds to the stored bytes, tamper-checked by re-hash
— a documented, weaker trade-off.

**Fail-closed policy.** Flags default off, per-action policies default deny,
a broken policy source is a deny, and an allow is never blank — it is
`allow_with_gates`: hash, validation and the claim still stand.

**Single-use, expiring approvals.** A consumed approval never fires twice
(atomic claim; race-tested: N concurrent attempts, one winner). An expired
one demands a fresh decision.

**Ownership.** Resources owned by another operator are never silently resumed
or forked; takeover is explicit and bound to the expected owner AND state.

**Evidence chains.** Every flow — including refusals — leaves a linked audit
chain that exports as a sealed bundle (below). Canonical serialization is
versioned and strict; see [`docs/SPEC_canonical.md`](docs/SPEC_canonical.md).

Using the library directly (no hook server): see
[`examples/pr_merge_gate/`](examples/pr_merge_gate/).

## What an approval actually covers

`git push` moves **every** commit between the remote and HEAD, not just the
tip. Push payloads therefore bind `remote_sha` plus the transported commit
list (capped at 50, flagged when truncated), and `hashgate show` renders it
prominently — including a warning when a transported commit was the HEAD of
a previously denied proposal.

Stated plainly: **a deny rejects a proposal; it does not quarantine a
commit.** Denied content stays on the branch and rides along with the next
push until removed (`git revert`/`reset`). The denied-commit warning is
SHA-based and can be evaded by amend/rebase — it is a reviewer aid, not a
content ban.

## Evidence bundles

Any chain exports as a self-contained JSON document, sealed with a canonical
`bundle_hash`. A receiver runs `verify_bundle(bundle)` with no access to the
gate's store: it re-computes the seal (self-excluding), checks the
`prev_event_id` linkage for gaps and the timestamps for chronology. Applied
outcome, trimmed:

```jsonc
{ "bundle_format": "hashgate-oversight-bundle-v1", "outcome": "applied",
  "events": [
    { "kind": "preview", "payload_hash": "916c06d12821…", "operator_id": "operator:alex", "…": "…" },
    { "kind": "applied", "payload_hash": "916c06d12821…",
      "idempotency_key": "merge:acme/api:9fceb02d0ae5…",
      "policy_decision": "allow_with_gates",
      "effects": { "merged_sha": "9fceb02d0ae5…" } } ],
  "bundle_hash": "aa94c3472b30…" }
```

Refusals are first-class evidence — "the agent tried, the gate prevented it":

```jsonc
{ "bundle_format": "hashgate-oversight-bundle-v1", "outcome": "hash_mismatch",
  "events": [
    { "kind": "preview", "payload_hash": "916c06d12821…", "…": "…" },
    { "kind": "hash_mismatch",
      "expected_hash": "916c06d12821…",   // what the operator approved
      "derived_hash":  "3e18f93f2f9f…" }  // what the server re-derived
  ],
  "bundle_hash": "40a46ac5905d…" }
```

Events carry IDs, hashes, operator identity/reason/channel and timestamps —
never payload bodies, never secrets (allowlist-first redaction is built in).
Subagent calls are gated like main-agent calls (confirmed end-to-end), and
their provenance (`agent_id`, `agent_type`) is recorded in the chain — as is
the decision surface (`cli` vs `web-ui`). Further outcomes (`denied_final`,
`approval_stale`, `operator_denied`) chain and export the same way.

## Failure semantics

Claude Code hooks are fail-open on transport problems: if a hook endpoint is
unreachable, the tool call runs anyway. **That difference is not a detail; it
is the difference between an observability feature and an enforcement
gate.** hashgate ships two wirings and names the trade-off:

| Wiring | Server down means |
|---|---|
| **Command-hook wrapper** (recommended) | gated actions blocked (exit 2); everything else — commits, tests, reads — keeps flowing. The wrapper classifies locally with the same rules module the server uses. |
| Direct HTTP hook (documented) | tool calls proceed ungated — advisory only. |

## Threat model — what hashgate is and is not

**What it enforces.** hashgate enforces the sanctioned path and makes
oversight provable: no gated action runs without a hash-bound, single-use,
unexpired operator approval that matches the exact current state, and every
decision — refusals included — leaves a verifiable evidence chain. That
protects against accidents, TOCTOU drift (state changing between review and
execution), silent piggybacking, and agents that follow instructions instead
of checking state — and it turns "a human was overseeing this" from a claim
into evidence.

**What it does not do.** hashgate is not a sandbox. An adversarial agent
with unrestricted file and shell access on the same machine can attack the
environment — the gate database, the hook settings, the wrapper — instead of
going through the gate. Containment is the job of OS isolation and
permission rules; hashgate is one layer of defense in depth, not all of
them. Mitigations are in the [setup guide](docs/claude_code_setup.md); the
full analysis, including the adversary taxonomy and known bypass paths, is
in [`docs/threat_model.md`](docs/threat_model.md).

**What "fail-closed" means here.** It is transport and policy semantics: an
unreachable gate server blocks gated actions (unlike fail-open direct HTTP
hooks), flags default off, policies default deny. It does not mean "cannot
be bypassed by an attacker with access to the environment."

## Honest limitations

- **Local, single-operator tool.** One machine, one gate database, no
  multi-user model.
- **Not a sandbox.** The sanctioned path is enforced; the environment is not
  — see the [threat model](docs/threat_model.md) and the mitigations in the
  [setup guide](docs/claude_code_setup.md).
- The denied-commit warning is SHA-based; amend/rebase changes SHAs.
- A plain deny is situational; `deny --final` binds a permanent refusal to
  the exact payload hash. It is a state ban, not a content ban — an
  amend/rebase produces a new hash and a new decision, which is what the
  promise can actually keep.
- Async-first API; no sync wrapper yet (added when a real sync consumer
  needs it).

## Regulatory context

hashgate supports the technical implementation of oversight and logging
requirements (for example human-oversight provisions such as EU AI Act
Article 14): enforced pre-effect human approval, cryptographic binding
between what was reviewed and what executes, and exportable, verifiable
evidence of both approvals and refusals. It does not, by itself, make any
system compliant with any regulation; legal assessment remains the
responsibility of the operator.

## Status & roadmap

v0.2. The core pattern was extracted from a production agent-runtime system
where it ran end-to-end (goal → plan → artifacts → completion, including
recovery and cross-operator takeover). 319 tests, including a concurrency
race pin on the idempotency claim and structural source pins on the accept
order; golden fixtures freeze the canonical format and the bundle format.

Roadmap candidates: FastAPI middleware, sync wrapper on demand, further
gated action types, signature implementations for bundle sealing (Ed25519
with export tooling), retention/export tooling, multi-operator identities.

## Sponsoring & integration work

If hashgate is useful to you, consider sponsoring its development via GitHub
Sponsors. I am also available for paid integration work (wiring hashgate
into your agent workflow, custom gated actions, evidence pipelines):
**spinto997@gmail.com**.

## License

Apache-2.0 — see [LICENSE](LICENSE). Contributions:
[CONTRIBUTING.md](CONTRIBUTING.md).
