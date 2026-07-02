# E2E checklist — hashgate × Claude Code (manual release protocol)

A reusable manual release protocol: run once per release on a real machine
with a real Claude Code session. Every step names what to observe. Use a
THROWAWAY git repo with a remote you control (a second local bare repo is
enough: `git init --bare /tmp/remote.git` +
`git remote add origin /tmp/remote.git`).

**History:** Round 1 passed the core path (fail-closed proof, happy path,
scenario B with stale bundle, deny, idempotency); its findings drove an
iteration round. Round 2 (2026-07-02) passed all re-tests marked ⟲ below —
TTL/expiry via the shared config, wrapper blast radius, stale reason,
`history`, the denied-commit warning, the self-approval guard live, and
subagent gating with `agent_context`. The ⟲ markers remain as flags for the
historically tricky spots.

## Setup

- [ ] 1. Fresh venv, **non-editable** install: `pip install '.[server]'`
      (NOT `-e` — editable installs are known-broken on some environments;
      observed on macOS CPython 3.12/3.14, see CONTRIBUTING.md).
      `hashgate --help` and `hashgate-hook-wrapper` resolve.
      ⟲ Editable-fix verification: run `bash scripts/verify_install.sh` — must
      print "install verification PASSED".
- [ ] 2. **Every terminal you use below: activate the venv first.**
- [ ] 3. Create `~/.hashgate/config.toml` (see setup doc §2) with
      `ttl_seconds = 900` and a `token`. Start `hashgate-hook-server` in
      terminal 1 and CHECK the startup line shows YOUR values
      (`ttl=900s token=set`).
- [ ] 4. Add the PreToolUse command hook to your **user**
      `~/.claude/settings.json` with the ABSOLUTE wrapper path (setup doc §3).
- [ ] 5. Sanity: something harmless (`git status`) runs normally.

## Fail-closed proof (with the corrected blast radius)

- [ ] 6. STOP the gate server. Ask Claude Code to `git push`.
      Expect: BLOCKED with "gate server unreachable — gated action (git_push)
      blocked".
- [ ] 7. ⟲ Server still stopped: let the agent run `git commit` / `ls` /
      tests. Expect: all pass through normally (the agent is NOT paralyzed —
      the round-1 finding is fixed).
- [ ] 8. Restart the server.

## Happy path

- [ ] 9. Let Claude Code make a small commit and try `git push`.
      Expect: deny with `Pending as <preview_id> (hash …)`.
- [ ] 10. Terminal 2: `hashgate pending`; `hashgate show <id>` shows
      repo_root/branch/head_sha AND ⟲ the transported-commit list
      ("this push transports N commit(s)"); head_sha matches
      `git rev-parse HEAD`.
- [ ] 11. `hashgate accept <id> --hash <FULL hash>`. Try a truncated hash
      first — expect the error naming "FULL 64-character" and where to find
      it. The accept output shows local time + countdown ("— in 900s").
- [ ] 12. ⟲ Accept the same preview AGAIN: expect exactly the
      "already has an open approval …" notice plus "the agent can retry the
      command now" — never a fresh "approved …" line (round-1 finding fixed).
- [ ] 13. Agent retries the push → allow, push lands on the remote.
- [ ] 14. Immediate second push attempt → deny "already consumed".

## TTL / expiry (⟲ re-test after the config fix)

- [ ] 15. Set `ttl_seconds = 30` in config.toml (or restart the server with
      `HASHGATE_TTL_SECONDS=30` AND use the same value in the accept
      terminal — with config.toml you don't have to think about this).
      RESTART the server, check the startup line says `ttl=30s`.
- [ ] 16. New pending push → accept → `show` displays expires ~30s ahead
      (countdown). Wait >30s, agent retries.
      Expect: deny "approval <id> expired at <ts> — a fresh approval is
      required. Operator: 'hashgate pending'."
- [ ] 17. Reset ttl to 900.

## Scenario B — state drift after approval

- [ ] 18. Pending push → approve — but BEFORE the retry, let the agent make
      ONE more commit. Retry.
      Expect: deny with the ⟲ STALE reason ("a prior approval exists but is
      stale — … approved hash …, current …. A new preview <id> is pending"),
      NOT the generic pending text. `hashgate bundle` of the OLD chain shows
      `preview → operator_approved → approval_stale`.

## Refusal / evidence / history

- [ ] 19. `hashgate deny <id> --reason "not now"` on a fresh pending push;
      agent retry → deny quoting "not now".
- [ ] 20. ⟲ `hashgate history` lists the past proposals with outcomes
      (applied / denied / expired / stale) and the deny reason inline.
- [ ] 21. ⟲ Denied-content warning: after the deny in step 19, let the agent
      commit ON TOP and propose a new push. `hashgate show <new-id>` warns
      "⚠ commit <sha> was HEAD of a denied push proposal — reason: 'not
      now'…". The agent's deny reason does NOT mention the history.
- [ ] 22. `hashgate bundle <chain_id> --out bundle.json`: happy chain
      `preview → operator_approved → applied`; denied chain ends
      `operator_denied`. No command text inside bundles.
- [ ] 23. Self-approval guard (still open from round 1): ask Claude Code to
      run `hashgate accept <id> --hash <hash>` itself.
      Expect: always-deny ("operator's own terminal").
- [ ] 24. ⟲ Subagent: let a subagent (Task tool) attempt the push. Expect:
      gated as usual; the preview chain carries an `agent_context` event with
      agent_id/agent_type (visible in the bundle).

## v0.2: operator web UI

- [ ] 25. Ensure `operator_token` is set in config.toml; restart the server
      (startup line shows `operator_token=set`). Open
      `http://127.0.0.1:8377/ui` — login page. WRONG token first ⇒ rejected
      ("wrong operator token"); correct token ⇒ pending list.
- [ ] 26. With a pending push open: the browser detail view shows the SAME
      ⚠ lines as `hashgate show` (compare directly).
- [ ] 27. 12-hex echo: type a WRONG prefix first ⇒ "hash echo mismatch", no
      approval; then the correct first 12 characters ⇒ approved with
      countdown; agent retry ⇒ allow. `hashgate bundle <chain>` (or the UI
      timeline) shows the decision with `channel: web-ui`.
- [ ] 28. Deny with the `final` checkbox via UI; agent retry on the
      IDENTICAL state ⇒ "FINALLY denied this exact state …"; one new commit
      ⇒ a normal new pending request.
- [ ] 29. Token separation, live: from the agent's terminal,
      `curl -H "X-Hashgate-Operator-Token: <HOOK token>"
      http://127.0.0.1:8377/ui/api/pending` ⇒ 403 — the proof that the new
      path is closed to the hook credential.

## v0.2: new gated actions

- [ ] 30. Force-push: let the agent try `git push --force`. Expect: its own
      pending (kind `git_force_push`); `show` displays "⚠ force-push …
      overwrites <sha> on <ref>".
- [ ] 31. `git reset --hard HEAD~1`: pending; `show` lists the discarded
      commit(s) and the current HEAD.
- [ ] 32. `rm -rf <dir-with-a-tracked-file>`: pending; `show` lists resolved
      paths and warns "⚠ affects files tracked by git".
- [ ] 33. One deploy action of your choice — `./deploy.sh` needs no extra
      tools (create a two-line script, commit it). Expect: pending with the
      artifact hash + HEAD in `show`; edit the script ⇒ retry derives a NEW
      hash (stale/new pending).
- [ ] 34. (Optional/external — requires Tailscale or similar:) open the UI
      from your phone, approve one action via typed echo. Ergonomics note:
      is typing 12 hex characters on a phone keyboard acceptable?

## Ergonomics notes to collect (for the next iteration)

- Deny→approve→retry loop friction in a real session?
- Are the case-specific deny reasons (pending/stale/expired/denied) enough
  for the agent to behave sensibly?
- `history` output: missing columns?
- TTL default 900s: fits your review pace?
