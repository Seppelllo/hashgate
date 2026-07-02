# hashgate × Claude Code — setup

Gate dangerous tool calls (v0.1: `git push` / `git merge` in Bash) behind a
hash-bound operator approval. The agent's call is denied until you approve it
in your own terminal; the approval is bound to the repository's **current
HEAD SHA**, single-use and expiring.

## 1. Install and start the gate server

```bash
pip install 'hashgate[server]'          # or: uv tool install 'hashgate[server]'

export HASHGATE_TOKEN="$(openssl rand -hex 16)"   # shared secret (recommended)
hashgate-hook-server                               # binds 127.0.0.1:8377
```

Configuration (env): `HASHGATE_DB` (default `~/.hashgate/hooks.db`),
`HASHGATE_TOKEN` (optional but recommended), `HASHGATE_TTL_SECONDS` (approval
lifetime, default 900), `HASHGATE_PORT` (default 8377). The server only ever
binds to `127.0.0.1`.

## 2. Wire the hook — two options with OPPOSITE failure semantics

### Option A (recommended): fail-closed command-hook wrapper

Claude Code hooks are **fail-open on transport problems**: if an HTTP hook
endpoint is unreachable or answers non-2xx, Claude Code logs a non-blocking
error and the tool call **runs anyway**. For a governance gate that is
unacceptable as the only wire. The wrapper inverts this: it exits with code 2
(= block) whenever the gate server cannot be reached — **server down means
gate closed, not gate open.**

`~/.claude/settings.json` (or the project's `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "hashgate-hook-wrapper",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

Make sure `hashgate-hook-wrapper` is on the PATH Claude Code uses (or put the
absolute path into `command`), and that `HASHGATE_TOKEN` is present in the
environment Claude Code inherits.

### Option B (documented, NOT recommended as the only wire): direct HTTP hook

Point a PreToolUse HTTP hook at `http://127.0.0.1:8377/hooks/pretooluse`
directly (consult the Claude Code hooks documentation for the exact config
shape of HTTP endpoints in your version). Simpler — but **fail-open**: if the
server is down, tool calls proceed ungated. That difference is not a detail;
it is the difference between an observability feature and an enforcement
gate. If you use Option B, treat the gate as advisory.

## 3. Operate

```bash
hashgate pending                      # list previews awaiting your decision
hashgate show <preview_id>            # the exact payload you are approving
hashgate accept <preview_id> --hash <FULL-payload-hash>   # hash echo is mandatory
hashgate deny <preview_id> --reason "…"
hashgate bundle <chain_id|preview_id> [--out bundle.json] # evidence export
```

The deny reason the agent sees names the preview id and the operator commands
— the agent retries after you approved. There is deliberately no blind
`accept <id>`: the hash echo is your cryptographic statement of what you
reviewed.

## 4. Semantics worth knowing

- **The hook never waits for you.** It answers immediately (deny with
  instructions); approval happens out-of-band in your terminal; the agent
  retries. No long-polling — hook timeouts stay ordinary.
- **A deny here does not replace Claude Code's permission machinery** — it
  sits in front of it. Non-gated calls get an empty hook response (no
  decision), so your normal allow/ask/deny rules apply unchanged. hashgate
  never actively allows anything it does not gate.
- **Approvals bind the repo state.** The payload contains repo root, branch
  and HEAD SHA. If the agent commits again after your approval, the next
  attempt re-derives a different hash: deny, new preview, and the old
  approval's chain records an `approval_stale` event.
- **Single-use + expiry.** A consumed approval never allows a second call;
  an expired one (default 15 min) demands a fresh decision.
- **Agent self-approval is blocked.** `hashgate accept`/`deny` issued through
  the agent's Bash tool is always denied. Honest limitation: an unrestricted
  agent with full Bash could still attack the local database file directly
  (e.g. via sqlite3) — the gate constrains the sanctioned path. Combine it
  with Claude Code's own permission rules (defense in depth) and keep the
  database out of the workspace you let the agent write to.
- The preview payload stores the exact command (that is what you review), so
  the local gate database contains raw commands. Evidence bundles carry
  hashes and metadata only.
