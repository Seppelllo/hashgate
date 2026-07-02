# SPDX-License-Identifier: Apache-2.0
"""Local gate server for Claude Code PreToolUse hooks.

One endpoint: ``POST /hooks/pretooluse``. The response is Claude Code hook
JSON:

- **not gate-mandatory** -> ``{}`` (NO decision field — Claude Code's normal
  permission machinery continues untouched; hashgate never actively allows
  what it does not gate),
- **gated, no valid approval** -> ``permissionDecision: "deny"`` with a
  precise reason naming the preview id, the hash and the operator's next
  step (the reason text is what the agent reads — vague denials cause agent
  loops),
- **gated, matching approval** -> the approval is consumed atomically
  (single-use) and the answer is ``permissionDecision: "allow"``.

The hook never waits for the operator: it answers immediately; the agent
retries after the operator approved in their own terminal.

Binds to 127.0.0.1 only. Optional shared-secret token
(``HASHGATE_TOKEN``) between wrapper and server.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "the Claude Code gate server needs the 'server' extra: "
        "pip install 'hashgate[server]'"
    ) from exc

import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hashgate.adapters.sqlalchemy_store import SQLAlchemyStore
from hashgate.adapters.sqlalchemy_store import create_all as create_core_tables
from hashgate.canonical import canonical_hash
from hashgate.errors import AlreadyApplied, HashMismatch, ValidationFailed
from hashgate.gate import Gate
from hashgate.integrations.claude_code.actions import ACTIONS, GitCommandContext
from hashgate.integrations.claude_code.approvals import (
    DECISION_APPROVED,
    DECISION_DENIED,
    ApprovalService,
    ClaudeCodeBase,
    append_chain_event,
    is_expired,
)
from hashgate.integrations.claude_code.rules import KIND_SELF_APPROVAL, classify
from hashgate.policy import MappingPolicySource, PolicyEngine
from hashgate.types import OperatorContext

DEFAULT_PORT = 8377
DEFAULT_DB_PATH = "~/.hashgate/hooks.db"


@dataclass
class ServerConfig:
    db_path: str = DEFAULT_DB_PATH
    token: str | None = None
    ttl_seconds: int = 900
    port: int = DEFAULT_PORT
    host: str = "127.0.0.1"  # never bind beyond localhost

    @classmethod
    def from_env(cls) -> ServerConfig:
        return cls(
            db_path=os.environ.get("HASHGATE_DB", DEFAULT_DB_PATH),
            token=os.environ.get("HASHGATE_TOKEN") or None,
            ttl_seconds=int(os.environ.get("HASHGATE_TTL_SECONDS", "900")),
            port=int(os.environ.get("HASHGATE_PORT", str(DEFAULT_PORT))),
        )


@dataclass
class _State:
    config: ServerConfig
    store: SQLAlchemyStore | None = None
    gate: Gate | None = None
    approvals: ApprovalService | None = None
    _initialized: bool = False
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def ensure_init(self) -> None:
        async with self._lock:
            if self._initialized:
                return
            db_file = Path(self.config.db_path).expanduser()
            db_file.parent.mkdir(parents=True, exist_ok=True)
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
            await create_core_tables(engine)
            async with engine.begin() as conn:
                await conn.run_sync(ClaudeCodeBase.metadata.create_all)
            sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
            self.store = SQLAlchemyStore(sessionmaker)
            # the server exists to gate exactly these actions — its engine
            # enables them; everything unknown stays deny by default
            self.gate = Gate(
                store=self.store,
                policy=PolicyEngine(source=MappingPolicySource(
                    flags={a.feature_flag: True for a in
                           (cls() for cls in ACTIONS.values())},
                    policies={name: "allow" for name in ACTIONS},
                )),
            )
            self.approvals = ApprovalService(
                sessionmaker, self.store, ttl_seconds=self.config.ttl_seconds)
            self._initialized = True


def _decision(decision: str, reason: str) -> JSONResponse:
    return JSONResponse({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })


def _deny(reason: str) -> JSONResponse:
    return _decision("deny", reason)


def _allow(reason: str) -> JSONResponse:
    return _decision("allow", reason)


def create_app(config: ServerConfig | None = None) -> FastAPI:
    app = FastAPI(title="hashgate Claude Code gate", docs_url=None, redoc_url=None)
    state = _State(config=config or ServerConfig.from_env())
    app.state.hashgate = state

    @app.post("/hooks/pretooluse")
    async def pretooluse(request: Request) -> JSONResponse:  # noqa: C901
        if state.config.token:
            if request.headers.get("x-hashgate-token") != state.config.token:
                return JSONResponse({"error": "invalid or missing token"}, status_code=401)
        await state.ensure_init()
        body: dict[str, Any] = await request.json()
        tool_name = str(body.get("tool_name") or "")
        tool_input = body.get("tool_input") or {}

        cls = classify(tool_name, tool_input)
        if not cls.gated:
            return JSONResponse({})  # no decision: normal permissions apply
        if cls.kind == KIND_SELF_APPROVAL:
            return _deny(
                "hashgate: agent-issued 'hashgate accept/deny' commands are always "
                "blocked. Approvals happen in the operator's own terminal, never "
                "through the agent."
            )

        action = ACTIONS[cls.kind]()
        ctx = GitCommandContext(
            cwd=str(body.get("cwd") or "."),
            command=str(tool_input.get("command") or ""),
            session_id=str(body.get("session_id") or ""),
        )

        # fresh server-side derivation — the repo state RIGHT NOW
        try:
            payload = await action.derive(ctx)
        except ValidationFailed as exc:
            return _deny(f"hashgate: cannot derive repository state "
                         f"({exc.code}) — fail-closed deny.")
        payload_hash = canonical_hash(payload)

        approval = await state.approvals.latest_for_hash(action.action_type, payload_hash)

        if approval is not None and approval.decision == DECISION_DENIED:
            return _deny(f"hashgate: operator denied this action: {approval.reason}")

        if approval is not None and approval.decision == DECISION_APPROVED:
            if approval.consumed_at:
                return _deny(
                    f"hashgate: approval {approval.id} was already consumed "
                    "(single-use). A new operator approval is required."
                )
            if is_expired(approval):
                return _deny(
                    f"hashgate: approval {approval.id} expired at {approval.expires_at}. "
                    "A fresh operator approval is required ('hashgate pending')."
                )
            ctx.approval_id = approval.id
            try:
                await state.gate.accept(action, ctx, OperatorContext(
                    operator_id=approval.operator_id,
                    reason=approval.reason,
                    channel="claude-code-hook",
                ), expected_hash=payload_hash)
            except HashMismatch:
                # repo state moved within this request — approval survives
                return _deny(
                    "hashgate: repository state changed while processing "
                    "(hash mismatch) — retry."
                )
            except AlreadyApplied:
                return _deny(
                    f"hashgate: approval {approval.id} was already consumed "
                    "(single-use). A new operator approval is required."
                )
            await state.approvals.mark_consumed(approval.id)
            return _allow(
                f"hashgate: approved by {approval.operator_id} "
                f"(hash {payload_hash[:12]}…), single-use approval consumed."
            )

        # no approval for the CURRENT state: pending (idempotent per hash)
        preview = await state.store.find_preview_by_hash(action.action_type, payload_hash)
        if preview is None:
            preview = await state.gate.preview(action, ctx, OperatorContext(
                operator_id=f"agent:{ctx.session_id[:12] or 'unknown'}",
                reason=payload["command"][:200],
                channel="claude-code-hook",
            ))
            # did the repo move away from an earlier approved state? record it
            for stale in await state.approvals.open_approvals_for_action(action.action_type):
                if stale.payload_hash != payload_hash and stale.chain_id:
                    await append_chain_event(
                        state.store, stale.chain_id, "approval_stale",
                        approval_id=stale.id,
                        expected_hash=stale.payload_hash,
                        derived_hash=payload_hash,
                    )
        return _deny(
            f"hashgate: {action.action_type} requires operator approval. "
            f"Pending as {preview.preview_id} (hash {payload_hash[:12]}…). "
            f"Operator: run 'hashgate pending' in a separate terminal, then "
            f"'hashgate accept {preview.preview_id} --hash <full-hash>'. "
            f"Retry this command after approval."
        )

    return app


def main() -> None:  # pragma: no cover — thin uvicorn launcher
    try:
        import uvicorn
    except ModuleNotFoundError:
        raise SystemExit("hashgate-hook-server needs: pip install 'hashgate[server]'") from None
    config = ServerConfig.from_env()
    uvicorn.run(create_app(config), host=config.host, port=config.port)


if __name__ == "__main__":  # pragma: no cover
    main()
