# SPDX-License-Identifier: Apache-2.0
"""Local gate server for Claude Code PreToolUse hooks.

Endpoints:

- ``POST /hooks/pretooluse`` — the gate. Response is Claude Code hook JSON:
  not gate-mandatory -> ``{}`` (no decision — normal permission machinery
  untouched; hashgate never actively allows what it does not gate); gated
  without a valid approval -> ``permissionDecision: "deny"`` with a precise,
  case-specific reason (pending / stale / expired / consumed / operator-
  denied — the reason text is what the agent reads); gated with a matching
  approval -> atomic single-use consume, ``permissionDecision: "allow"``.
- ``GET /health`` — effective db/ttl/port, used by the CLI to warn when the
  two processes point at different databases.

The hook never waits for the operator: it answers immediately; the agent
retries after the operator approved in their own terminal.

Configuration comes from the SHARED source (env > ~/.hashgate/config.toml >
default — see ``config.py``); the effective values are logged at startup.
Binds to 127.0.0.1 only.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hashgate.canonical import canonical_hash
from hashgate.errors import AlreadyApplied, HashMismatch, ValidationFailed
from hashgate.gate import Gate
from hashgate.integrations.claude_code.actions import ACTIONS, GitCommandContext
from hashgate.integrations.claude_code.config import GateConfig, load_config
from hashgate.integrations.claude_code.rules import KIND_SELF_APPROVAL, classify
from hashgate.policy import MappingPolicySource, PolicyEngine
from hashgate.types import OperatorContext, Preview

# The console script is installed even without the 'server' extra; die with
# instructions instead of a raw ImportError traceback (checked in main() and
# create_app()).
_EXTRA_HINT = ("hashgate: this command requires the server extra — "
               "install with: pip install 'hashgate[server]'")
try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from hashgate.adapters.sqlalchemy_store import SQLAlchemyStore
    from hashgate.adapters.sqlalchemy_store import create_all as create_core_tables
    from hashgate.integrations.claude_code.approvals import (
        DECISION_APPROVED,
        DECISION_DENIED,
        DECISION_DENIED_FINAL,
        ApprovalService,
        ClaudeCodeBase,
        HookApprovalRow,
        append_chain_event,
        is_expired,
    )
    from hashgate.integrations.claude_code.ui import register_ui
    _IMPORT_ERROR: ModuleNotFoundError | None = None
except ModuleNotFoundError as exc:
    _IMPORT_ERROR = exc

#: kept as the public name; the shared GateConfig IS the server config
ServerConfig = GateConfig


@dataclass
class _State:
    config: GateConfig
    store: SQLAlchemyStore | None = None
    gate: Gate | None = None
    approvals: ApprovalService | None = None
    sessionmaker: Any = None
    _initialized: bool = False
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def ensure_init(self) -> None:
        async with self._lock:
            if self._initialized:
                return
            db_file = Path(self.config.resolved_db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
            await create_core_tables(engine)
            async with engine.begin() as conn:
                await conn.run_sync(ClaudeCodeBase.metadata.create_all)
            sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
            self.sessionmaker = sessionmaker
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


def _agent_operator(body: dict[str, Any], session_id: str) -> OperatorContext:
    agent_id = str(body.get("agent_id") or "").strip()
    ident = agent_id or session_id[:12] or "unknown"
    return OperatorContext(
        operator_id=f"agent:{ident}",
        reason="placeholder",  # replaced per call site
        channel="claude-code-hook",
    )


def create_app(config: GateConfig | None = None) -> FastAPI:
    if _IMPORT_ERROR is not None:
        raise ModuleNotFoundError(_EXTRA_HINT) from _IMPORT_ERROR
    app = FastAPI(title="hashgate Claude Code gate", docs_url=None, redoc_url=None)
    state = _State(config=config or load_config())
    app.state.hashgate = state

    @app.get("/health")
    async def health() -> JSONResponse:
        return JSONResponse({
            "service": "hashgate-hook-server",
            "db": state.config.resolved_db_path,
            "ttl_seconds": state.config.ttl_seconds,
            "port": state.config.port,
        })

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
        session_id = str(body.get("session_id") or "")
        ctx = GitCommandContext(
            cwd=str(body.get("cwd") or "."),
            command=str(tool_input.get("command") or ""),
            session_id=session_id,
        )

        # fresh server-side derivation — the repo state RIGHT NOW
        try:
            payload = await action.derive(ctx)
        except ValidationFailed as exc:
            return _deny(f"hashgate: cannot derive repository state "
                         f"({exc.code}) — fail-closed deny.")
        payload_hash = canonical_hash(payload)

        approval = await state.approvals.latest_for_hash(action.action_type, payload_hash)

        if approval is not None and approval.decision == DECISION_DENIED_FINAL:
            return _deny(
                f"hashgate: operator FINALLY denied this exact state "
                f"(hash {payload_hash[:12]}…) at {approval.created_at}: "
                f"{approval.reason}. This exact state will never be approved; "
                "a changed state (new commit/amend/other target) is a new decision."
            )
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
                    f"hashgate: approval {approval.id} expired at "
                    f"{approval.expires_at} — a fresh approval is required. "
                    "Operator: 'hashgate pending'."
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

        # no approval for the CURRENT state: pending (idempotent per hash).
        # Tell the agent everything the server knows — a stale prior approval
        # is a different situation than "never asked".
        stale = [a for a in await state.approvals.open_approvals_for_action(action.action_type)
                 if a.payload_hash != payload_hash]
        preview = await state.store.find_preview_by_hash(action.action_type, payload_hash)
        if preview is None:
            preview = await _create_pending_preview(state, action, ctx, body,
                                                    session_id, stale, payload_hash)
        if stale:
            return _deny(
                f"hashgate: a prior approval exists but is stale — repository "
                f"state changed since approval (approved hash "
                f"{stale[0].payload_hash[:12]}…, current {payload_hash[:12]}…). "
                f"A new preview {preview.preview_id} is pending; operator: "
                f"'hashgate show {preview.preview_id}'. Retry after approval."
            )
        return _deny(
            f"hashgate: {action.action_type} requires operator approval. "
            f"Pending as {preview.preview_id} (hash {payload_hash[:12]}…). "
            f"Operator: run 'hashgate pending' in a separate terminal, then "
            f"'hashgate accept {preview.preview_id} --hash <full-hash>'. "
            f"Retry this command after approval."
        )

    register_ui(app, state)  # operator web UI under /ui (separate token)
    return app


async def _create_pending_preview(
    state: _State,
    action: Any,
    ctx: GitCommandContext,
    body: dict[str, Any],
    session_id: str,
    stale: list[HookApprovalRow],
    payload_hash: str,
) -> Preview:
    operator = _agent_operator(body, session_id)
    operator = OperatorContext(
        operator_id=operator.operator_id,
        reason=f"agent requested {action.action_type} via PreToolUse hook",
        channel=operator.channel,
    )
    preview = await state.gate.preview(action, ctx, operator)
    # subagent provenance: record who asked, if the hook input says so
    agent_id = str(body.get("agent_id") or "").strip()
    agent_type = str(body.get("agent_type") or "").strip()
    if agent_id or agent_type:
        await append_chain_event(
            state.store, preview.chain_id, "agent_context",
            action_type=action.action_type,
            operator_id=operator.operator_id,
            channel="claude-code-hook",
            agent_id=agent_id or None,
            agent_type=agent_type or None,
            session_id=session_id or None,
        )
    # did the repo move away from an earlier approved state? record it on
    # the OLD approval's chain (once, when the new preview appears)
    for stale_approval in stale:
        if stale_approval.chain_id:
            await append_chain_event(
                state.store, stale_approval.chain_id, "approval_stale",
                action_type=action.action_type,
                operator_id="system:hashgate-server",
                reason="repository state changed after approval",
                channel="server",
                approval_id=stale_approval.id,
                expected_hash=stale_approval.payload_hash,
                derived_hash=payload_hash,
            )
    return preview


def main() -> None:  # pragma: no cover — thin uvicorn launcher
    import sys

    from hashgate.integrations.claude_code.config import GateConfigError

    if _IMPORT_ERROR is not None:
        print(_EXTRA_HINT, file=sys.stderr)
        sys.exit(1)
    try:
        import uvicorn
    except ModuleNotFoundError:
        print(_EXTRA_HINT, file=sys.stderr)
        sys.exit(1)
    try:
        config = load_config()
    except GateConfigError as exc:
        print(f"hashgate-hook-server: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"hashgate-hook-server effective config: {config.summary()}", flush=True)
    uvicorn.run(create_app(config), host="127.0.0.1", port=config.port)


if __name__ == "__main__":  # pragma: no cover
    main()
