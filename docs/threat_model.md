# hashgate threat model

hashgate is a governance and oversight layer: it enforces a hash-bound human
approval on a **sanctioned path** and produces verifiable evidence of every
decision. It is not a sandbox and does not claim containment of an
adversarial process. This document states precisely what is enforced,
against whom, and where the boundary runs.

## What hashgate enforces

On the sanctioned path, no gated action executes unless an operator approval
exists that is:

- **hash-bound** — the approval echoes the canonical hash of the exact
  payload the operator reviewed, and the server re-derives that payload from
  live state at execution time; any drift refuses,
- **single-use** — consumed atomically, a replay never fires twice,
- **unexpired** — approvals age out (default 15 minutes).

Every decision — previews, approvals, denials, refusals such as hash
mismatches and stale approvals — appends to a linked evidence chain that
exports as a sealed bundle a third party can verify offline
(`verify_bundle`: seal integrity, gap-free linkage, chronology).

## Adversary taxonomy

**1. The cooperative agent.** Does what it is told, retries on deny, waits
for approval. hashgate's gates are simply the workflow.

**2. The misguided but not malicious agent — the main case.** Follows
instructions instead of checking state: pushes again after the operator
reviewed, transports commits nobody looked at, acts on a stale view, or
obligingly runs `hashgate accept` itself when asked to. This is the
adversary hashgate is built for, and the one observed in practice. The
mechanism (server-side re-derivation against live state, transported-commit
binding, the self-approval block) refuses these actions without relying on
the agent's judgment.

**3. The adversarial agent with environment access.** A process with
unrestricted file and shell access on the gate's machine is **outside this
threat model**. It does not need to defeat the gate; it can attack the
environment instead (see the bypass table below). Defending against it is
the job of OS-level isolation (containers, VMs, separate users), permission
systems, and the agent runtime's own rules — hashgate is one layer of
defense in depth, not a substitute for isolation.

## Known bypass paths and mitigations

All of these require environment access (adversary 3); none defeats the
gate on the sanctioned path itself.

| Bypass | Mitigation |
|---|---|
| Direct manipulation of the gate database (e.g. `sqlite3 ~/.hashgate/hooks.db`) | Deny rules keeping the agent away from `~/.hashgate/**` (incl. `Bash(sqlite3*)`); run the gate under a different OS user for hard separation |
| Editing hook settings to unhook the gate | Put the hook in **user-/managed-level** settings, never in project settings the agent can edit; deny rules on the settings file |
| Deleting the gate database | Same placement + deny rules; a missing DB stops approvals from existing, so gated actions deny — but history is lost (see evidence section) |
| Rewriting SHAs (`commit --amend`, rebase) so a denied commit no longer matches the denied-commit warning | The warning is SHA-based and advisory by design; reliable quarantine of rejected content is `git revert`/`reset`. The rewritten state still needs a fresh approval — content review is the operator's job at `hashgate show` |
| Self-approval via the agent's own shell (`hashgate accept …`) | Blocked at the rules layer (always-deny, command-position matching); this is a speed bump against adversary 2, not a boundary against adversary 3 |
| Self-approval via the operator web UI (`curl http://127.0.0.1:…/ui/accept`) — the agent knows preview id and hash from its own deny reason | All `/ui` routes (read-only included) require the SEPARATE `operator_token`, which is never present in the agent/hook environment; the hook token never authorizes UI routes (pinned by test). Protection assumptions: the operator token stays out of the agent's environment, and the deny rules above keep the agent away from `~/.hashgate/**` — which covers `config.toml`, where both tokens live. Against adversary 2 this holds (it follows instructions, it does not exfiltrate secrets it cannot read); against adversary 3 the usual environment caveat applies |

## What the evidence chain gives you under compromise — and what it does not

Bundles are **tamper-evident, not tamper-proof**. After export, any
modification — edited fields, removed or reordered events, a forged seal —
fails `verify_bundle` for any third party, with no access to the gate's
store required.

Stated honestly: in the single-machine model of v0.1, manipulation of the
local database **before** a bundle is exported is not detectable — the
exporter seals whatever the store contains. If your threat model includes a
compromised gate machine, the evidence store must leave that machine:
signed bundles (the `BundleSigner` hook exists; implementations are on the
roadmap) exported promptly to append-only external storage turn "the
machine was compromised later" into a bounded claim instead of a total one.

## What "fail-closed" means in this project

Transport and policy semantics, precisely:

- gate server unreachable ⇒ the recommended command-hook wrapper **blocks
  gated actions** (exit 2) while letting harmless commands flow — in
  contrast to direct HTTP hooks, which are fail-open on transport errors;
- feature flags default **off**, per-action policies default **deny**, a
  broken policy source is a deny, an allow is never blank
  (`allow_with_gates`).

It does **not** mean "cannot be bypassed by an attacker with access to the
environment" — that boundary is drawn by the adversary taxonomy above.
