# E2E checklist — hashgate × Claude Code (manual, operator-run)

Goal: prove the full loop on a real machine with a real Claude Code session.
Every step names what to observe. Use a THROWAWAY git repo with a remote you
control (a second local bare repo is enough: `git init --bare /tmp/remote.git`
+ `git remote add origin /tmp/remote.git`).

## Setup

- [ ] 1. `pip install -e '.[server]'` (or the built wheel) in a fresh venv;
      `hashgate --help` and `hashgate-hook-wrapper` resolve on PATH.
- [ ] 2. `export HASHGATE_TOKEN=$(openssl rand -hex 16)` and start
      `hashgate-hook-server` in terminal 1. Expect uvicorn on 127.0.0.1:8377.
- [ ] 3. Add the PreToolUse command hook (Option A snippet from
      `docs/claude_code_setup.md`) to the throwaway repo's
      `.claude/settings.json`; ensure the wrapper inherits `HASHGATE_TOKEN`.
- [ ] 4. Sanity: in the repo, ask Claude Code for something harmless
      (`git status`). Expect: runs normally (empty hook response — normal
      permission machinery untouched).

## Fail-closed proof (do this FIRST — it is the point of the wrapper)

- [ ] 5. STOP the gate server. Ask Claude Code to `git push`.
      Expect: the tool call is BLOCKED (wrapper exit 2), the agent sees the
      fail-closed message. Server down = gate closed.
- [ ] 6. Restart the server.

## Happy path

- [ ] 7. Let Claude Code make a small commit and try `git push`.
      Expect: deny with `Pending as <preview_id> (hash …)`, agent stops/asks.
- [ ] 8. Terminal 2: `hashgate pending` shows the preview; `hashgate show
      <id>` shows repo_root/branch/**head_sha**/command — verify the head_sha
      matches `git rev-parse HEAD` in the repo.
- [ ] 9. `hashgate accept <id> --hash <FULL hash>` (copy from `show`).
      Try a truncated hash first — expect a "hash echo mismatch" error.
- [ ] 10. Tell the agent to retry the push. Expect: allow with
      "approved by …, single-use approval consumed", push actually lands on
      the remote.
- [ ] 11. Ask the agent to push again immediately (same state).
      Expect: deny — the fresh attempt derives the same hash, but the
      approval is consumed (`already consumed`); a new preview/approval cycle
      would be needed.

## Scenario B — the pitch (state drift after approval)

- [ ] 12. Have the agent commit, try `git push` (deny/pending), approve it
      in terminal 2 — but BEFORE the retry, let the agent make ONE more
      commit. Then retry the push.
      Expect: deny with a NEW pending preview (new hash). `hashgate bundle`
      of the OLD chain shows `preview → operator_approved → approval_stale`
      with expected_hash ≠ derived_hash.

## Refusal / expiry / evidence

- [ ] 13. `hashgate deny <id> --reason "not now"` on a fresh pending push;
      agent retry → deny showing your reason verbatim.
- [ ] 14. Approve one with `--ttl 5`, wait >5s, retry → deny "expired".
- [ ] 15. `hashgate bundle <chain_id> --out bundle.json` for the happy-path
      chain: events `preview → operator_approved → applied`; for the denied
      chain: `… → operator_denied`. Spot-check: no command text inside the
      bundle, only hashes/metadata.
- [ ] 16. Self-approval guard: ask Claude Code to run
      `hashgate accept <id> --hash <hash>` itself.
      Expect: always-deny ("operator's own terminal").

## Ergonomics notes to collect while testing (for the iteration round)

- How disruptive is the deny→approve→retry loop in a real session?
- Is the deny reason enough for the agent to behave (retry vs. giving up)?
- Anything annoying about `hashgate pending`/`show` output formatting?
- Does the 15-minute default TTL fit your review pace?
