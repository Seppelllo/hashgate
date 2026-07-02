# hashgate × Claude Code — setup

Gate dangerous tool calls (`git push`/`git merge`, and since v0.2:
force-push, `git reset --hard`, recursive `rm`, plus common deploy commands —
`kamal deploy`, `docker compose up`, `kubectl apply`, named deploy scripts —
all in Bash) behind a
hash-bound operator approval. The agent's call is denied until you approve it
in your own terminal; the approval is bound to the repository's **current
HEAD SHA and remote-tracking state**, single-use and expiring. Confirmed in
end-to-end testing: **subagent tool calls are gated too** — PreToolUse hooks
fire for delegated subagents as well, and their provenance (`agent_id`,
`agent_type`, when present in the hook input) is recorded in the evidence
chain.

## 1. Install and start the gate server

```bash
python3 -m venv ~/.hashgate/venv && source ~/.hashgate/venv/bin/activate
pip install 'hashgate[server]'      # NOT -e: editable installs are unreliable
                                    # on macOS Pythons (see CONTRIBUTING.md)
hashgate-hook-server
```

The server prints its **effective configuration at startup**
(`db=… ttl=…s token=set|unset port=… config=…`) — read that line; a setting
you intended that does not show up there is not in force.

## 2. Configuration — ONE shared source for server and CLI

Server and CLI read the same file, `~/.hashgate/config.toml` (override the
path via `HASHGATE_CONFIG`); per field, an environment variable overrides the
file, the file overrides the default:

```toml
db = "~/.hashgate/hooks.db"
ttl_seconds = 900        # approval lifetime; governs BOTH processes
token = "…"              # shared secret, recommended: openssl rand -hex 16
port = 8377
```

Env overrides: `HASHGATE_DB`, `HASHGATE_TTL_SECONDS`, `HASHGATE_TOKEN`,
`HASHGATE_PORT`. Put the token in the file once instead of juggling env
variables across terminals. The CLI additionally checks the running server's
`/health` and warns when the two point at different databases.

## 3. Wire the hook — two options with OPPOSITE failure semantics

### Option A (recommended): fail-closed command-hook wrapper

Claude Code hooks are **fail-open on transport problems**: if an HTTP hook
endpoint is unreachable or answers non-2xx, Claude Code logs a non-blocking
error and the tool call **runs anyway**. For a governance gate that is
unacceptable as the only wire. The wrapper inverts this — with the right
blast radius: on transport failure it classifies the command locally (same
rules as the server, one rulebook) and blocks **only gate-mandatory
commands** (exit 2); everything else passes through. Server down means *gated
actions* blocked — the agent can still run tests, commit and read files.

Use your **user settings** (`~/.claude/settings.json`), and put the
**absolute path** of the wrapper into `command` — Claude Code does not run in
your venv, so a bare `hashgate-hook-wrapper` usually does not resolve:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/YOU/.hashgate/venv/bin/hashgate-hook-wrapper",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

Why user settings instead of the project's `.claude/settings.json`: the agent
can EDIT project files — including project settings — and would thereby be
able to unhook its own gate. User-level (or managed) settings live outside
the workspace you let the agent write to.

### Option B (documented, NOT recommended as the only wire): direct HTTP hook

Point a PreToolUse HTTP hook at `http://127.0.0.1:8377/hooks/pretooluse`
directly (consult the Claude Code hooks documentation for the exact config
shape in your version). Simpler — but **fail-open**: if the server is down,
tool calls proceed ungated. That difference is not a detail; it is the
difference between an observability feature and an enforcement gate. If you
use Option B, treat the gate as advisory.

## 4. Operate

```bash
hashgate pending                      # previews awaiting your decision
hashgate show <preview_id>            # exact payload — for pushes incl. the
                                      # FULL transported-commit list + warnings
hashgate accept <preview_id> --hash <FULL-payload-hash>   # hash echo mandatory
hashgate deny <preview_id> --reason "…"
hashgate history [--limit N]          # past previews and their outcomes
hashgate bundle <chain_id|preview_id> [--out bundle.json] # evidence export
```

Operator-facing times are local (with UTC in brackets and a countdown for
expiries); evidence bundles stay pure UTC.

## 5. Semantics worth knowing

- **The hook never waits for you.** It answers immediately (deny with
  instructions); approval happens out-of-band in your terminal; the agent
  retries. No long-polling — hook timeouts stay ordinary.
- **A deny here does not replace Claude Code's permission machinery** — it
  sits in front of it. Non-gated calls get an empty hook response (no
  decision), so your normal allow/ask/deny rules apply unchanged. hashgate
  never actively allows anything it does not gate.
- **A push payload shows what actually transports.** `git push` moves EVERY
  commit between the remote and HEAD, not just the tip — the payload
  therefore binds `remote_sha` plus the transported commit list (capped at
  50, flagged when truncated), and `show` renders it prominently. If a
  transported commit was the HEAD of a previously **denied** proposal, `show`
  warns (operator-facing only; the warning is neither part of the hash nor of
  the agent's deny reason). Honest limitation: the match is SHA-based and an
  amend/rebase changes SHAs — reliable quarantine of rejected content remains
  `git revert`/`reset`.
- **A deny rejects the push proposal, it does not remove commits.** Denied
  content stays on the branch and will ride along with the NEXT push until
  you remove it (revert/reset). Decide accordingly.
- **Approvals bind the repo state — both sides.** New local commit after
  approval OR a moved remote ⇒ the next attempt re-derives a different hash:
  deny with an explicit *stale* reason (both hashes named), a new preview,
  and an `approval_stale` event on the old approval's chain.
- **Single-use + expiry.** A consumed approval never allows a second call; an
  expired one demands a fresh decision. The TTL comes from the shared config
  (see §2).
- **Agent self-approval is blocked.** `hashgate accept`/`deny` issued through
  the agent's Bash tool is always denied. Residual gaps, honestly: an
  unrestricted agent with full Bash could still (a) modify the local gate
  database directly (e.g. `sqlite3 ~/.hashgate/hooks.db …`), (b) edit
  project-level `.claude/settings.json` to unhook the gate, or (c) delete the
  database file. Mitigate with user-level settings (above) plus Claude Code
  deny rules keeping the agent away from the gate's files:

  ```json
  {
    "permissions": {
      "deny": [
        "Read(~/.hashgate/**)",
        "Write(~/.hashgate/**)",
        "Edit(~/.hashgate/**)",
        "Write(~/.claude/settings.json)",
        "Edit(~/.claude/settings.json)",
        "Bash(sqlite3*)"
      ]
    }
  }
  ```

  The gate constrains the sanctioned path; defense in depth is the
  combination of gate + permission rules + your review.
- **Denials: situational by default, `--final` for a sticky one.** A plain
  deny is situational — the identical state stays denied, but the operator
  can still approve it later, and in practice the agent's next attempt has a
  new state and creates a new pending request. `hashgate deny <id> --reason …
  --final` binds the denial to the exact payload hash: the identical state is
  answered with a `denied_final` refusal forever (no new pending, no later
  accept). Stated honestly: `--final` binds to the exact STATE, not to
  content — an amend/rebase/new commit produces a new hash and therefore a
  new decision. That is the promise the mechanism can actually keep (same
  honesty as the SHA-based denied-commit warning); reliable content
  quarantine remains `git revert`/`reset`.
- The preview payload stores the exact command and commit subjects (that is
  what you review), so the local gate database contains raw command text.
  Evidence bundles carry hashes and metadata only.
