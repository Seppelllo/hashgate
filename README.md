# hashgate

**Execution governance for AI agents: cryptographically bound human oversight.**

Preview → canonical hash → operator accept → server-side re-derivation →
hash match → apply. Fail-closed, idempotent, audited.

hashgate executes nothing itself — it *gates*. Others log what your agent did;
hashgate makes it provable that the agent could only do what a human approved
by hash.

> **Status: v0.1 in development.** The core pattern was extracted from a
> production system where it ran end-to-end (goal → plan → artifacts →
> completion, including recovery and cross-operator takeover). This README
> grows with the library; the full worked example (PR-merge gate) and the
> oversight-evidence bundle land with the first release.

## Design decisions (v0.1)

- **Canonical serialization is versioned and strict** — see
  [`docs/SPEC_canonical.md`](docs/SPEC_canonical.md). Floats are rejected;
  any format change is a new canon version, never a silent edit.
- **Async-first, sync wrapper on demand.** The store protocol and gate are
  `async` (the reference adapter is async SQLAlchemy). No sync wrapper ships
  in v0.1 — one will be added when a real sync consumer needs it.
- **Fail-closed everywhere.** Flags default off, policies default deny,
  a broken policy source is a deny, `apply()` never runs without a hash match
  and an atomic idempotency claim.
- **No auto-accept, no scheduler** in the core — deliberately out of scope.
- **Refusals are audited.** A hash mismatch or policy denial produces an audit
  event (with both hashes, never payload bodies).

## Scope note

hashgate supports the *technical* implementation of oversight and logging
requirements (e.g. those described in EU AI Act Articles 12 and 14). It does
not, by itself, make any system compliant with any regulation; legal
assessment remains the responsibility of the operator.

## License

Apache-2.0
