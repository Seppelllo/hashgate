# SPDX-License-Identifier: Apache-2.0
"""Gate server — full flow over the ASGI app (no real network, tmp SQLite,
real git repo). Covers: passthrough, pending deny, accept -> allow with
atomic consume, replay deny, expiry deny, post-approval commit -> stale
approval + new pending, operator deny, self-approval block, token auth."""
from __future__ import annotations

import subprocess

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from hashgate.adapters.sqlalchemy_store import SQLAlchemyStore
from hashgate.evidence import EvidenceExporter, verify_bundle
from hashgate.integrations.claude_code.approvals import (
    ApprovalService,
    ClaudeCodeBase,
    HookApprovalRow,
)
from hashgate.integrations.claude_code.server import ServerConfig, create_app
from hashgate.store import utcnow

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    "HOME": "/tmp",
    # adversarial default: ubuntu-latest resolves init.defaultBranch to
    # master under isolated config while Apple Git defaults to main —
    # pin the CI-like value so macOS runs exercise the same case as CI
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "init.defaultBranch",
    "GIT_CONFIG_VALUE_0": "master",
}


def _git(cwd, *args) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True, env=_GIT_ENV).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True,
                   capture_output=True, env=_GIT_ENV)
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "first")
    return repo


class Harness:
    def __init__(self, tmp_path, token=None, ttl=900):
        self.db_path = str(tmp_path / "hooks.db")
        self.config = ServerConfig(db_path=self.db_path, token=token, ttl_seconds=ttl)
        self.app = create_app(self.config)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://gate")

    async def services(self):
        engine = create_async_engine(f"sqlite+aiosqlite:///{self.db_path}")
        async with engine.begin() as conn:
            await conn.run_sync(ClaudeCodeBase.metadata.create_all)
        sm = async_sessionmaker(engine, expire_on_commit=False)
        store = SQLAlchemyStore(sm)
        return sm, store, ApprovalService(sm, store)


def _event(repo, command: str) -> dict:
    return {"session_id": "sess-1", "cwd": str(repo), "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}}


def _decision(response) -> tuple[str | None, str]:
    body = response.json()
    out = body.get("hookSpecificOutput") or {}
    return out.get("permissionDecision"), out.get("permissionDecisionReason", "")


async def _approve(harness: Harness, reason_text: str, ttl=None) -> str:
    """Operator-side approval for the preview named in a deny reason."""
    preview_id = reason_text.split("Pending as ")[1].split(" ")[0]
    sm, store, approvals = await harness.services()
    preview = await store.load_preview(preview_id)
    row = await approvals.decide(
        preview_id=preview.preview_id, chain_id=preview.chain_id,
        action_type=preview.action_type, payload_hash=preview.payload_hash,
        decision="approved", operator_id="operator:tester", reason="looks good",
        ttl_seconds=ttl)
    return row.id


async def test_non_gated_call_returns_no_decision(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        response = await client.post("/hooks/pretooluse",
                                     json=_event(repo, "git status --short"))
    assert response.status_code == 200
    assert response.json() == {}  # untouched permission machinery


async def test_first_attempt_denies_with_pending_preview(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        decision, reason = _decision(await client.post(
            "/hooks/pretooluse", json=_event(repo, "git push origin main")))
    assert decision == "deny"
    assert "requires operator approval" in reason
    assert "Pending as" in reason and "hashgate pending" in reason
    assert "Retry" in reason


async def test_pending_is_idempotent_per_hash(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        _, r1 = _decision(await client.post("/hooks/pretooluse",
                                            json=_event(repo, "git push")))
        _, r2 = _decision(await client.post("/hooks/pretooluse",
                                            json=_event(repo, "git push")))
    assert r1.split("Pending as ")[1] == r2.split("Pending as ")[1]  # same preview


async def test_approve_then_retry_allows_and_consumes_single_use(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        _, reason = _decision(await client.post("/hooks/pretooluse",
                                                json=_event(repo, "git push")))
        approval_id = await _approve(harness, reason)
        decision, allow_reason = _decision(await client.post(
            "/hooks/pretooluse", json=_event(repo, "git push")))
        assert decision == "allow"
        assert "operator:tester" in allow_reason and "single-use" in allow_reason
        # replay: the same approval must not work twice
        decision2, reason2 = _decision(await client.post(
            "/hooks/pretooluse", json=_event(repo, "git push")))
    assert decision2 == "deny"
    assert "already consumed" in reason2
    sm, _store, _approvals = await harness.services()
    async with sm() as session:
        row = await session.get(HookApprovalRow, approval_id)
    assert row.consumed_at is not None


async def test_expired_approval_denies(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        _, reason = _decision(await client.post("/hooks/pretooluse",
                                                json=_event(repo, "git push")))
        approval_id = await _approve(harness, reason)
        sm, _store, _approvals = await harness.services()
        async with sm() as session:  # force expiry in the past
            row = await session.get(HookApprovalRow, approval_id)
            row.expires_at = utcnow().replace(year=2000).isoformat()
            await session.commit()
        decision, deny_reason = _decision(await client.post(
            "/hooks/pretooluse", json=_event(repo, "git push")))
    assert decision == "deny"
    # golden substrings: the reason must say WHICH approval expired WHEN and
    # what the operator does next
    assert f"approval {approval_id} expired at" in deny_reason
    assert "a fresh approval is required" in deny_reason
    assert "hashgate pending" in deny_reason


async def test_commit_after_approval_denies_and_marks_stale(tmp_path, repo) -> None:
    # scenario B live: the agent keeps committing after the operator approved
    harness = Harness(tmp_path)
    async with harness.client() as client:
        _, reason = _decision(await client.post("/hooks/pretooluse",
                                                json=_event(repo, "git push")))
        await _approve(harness, reason)
        (repo / "a.txt").write_text("two\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-m", "agent kept working")
        decision, deny_reason = _decision(await client.post(
            "/hooks/pretooluse", json=_event(repo, "git push")))
    assert decision == "deny"
    # golden substrings: the agent learns the WHOLE situation — a stale prior
    # approval, both hashes, and the new pending preview
    assert "a prior approval exists but is stale" in deny_reason
    assert "repository state changed since approval" in deny_reason
    assert "approved hash" in deny_reason and "current" in deny_reason
    assert "A new preview" in deny_reason and "hashgate show" in deny_reason
    # the old approval's chain records that its state went stale
    sm, store, approvals = await harness.services()
    stale = (await approvals.open_approvals_for_action("git_push"))[0]
    events = await store.list_chain_events(stale.chain_id)
    kinds = [e["kind"] for e in events]
    assert kinds == ["preview", "operator_approved", "approval_stale"]
    stale_event = events[-1]
    assert stale_event["expected_hash"] == stale.payload_hash
    assert stale_event["derived_hash"] != stale.payload_hash
    # no reasonless nulls in core fields of integration events
    assert stale_event["channel"] == "server"
    assert stale_event["action_type"] == "git_push"
    assert stale_event["operator_id"] == "system:hashgate-server"
    approved_event = events[1]
    assert approved_event["channel"] == "cli"
    assert approved_event["action_type"] == "git_push"
    bundle = await EvidenceExporter(store=store) \
        .export_oversight_bundle_by_chain(stale.chain_id)
    assert bundle["outcome"] == "approval_stale"
    assert verify_bundle(bundle).valid


async def test_operator_denial_is_reported(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        _, reason = _decision(await client.post("/hooks/pretooluse",
                                                json=_event(repo, "git push")))
        preview_id = reason.split("Pending as ")[1].split(" ")[0]
        sm, store, approvals = await harness.services()
        preview = await store.load_preview(preview_id)
        await approvals.decide(
            preview_id=preview.preview_id, chain_id=preview.chain_id,
            action_type=preview.action_type, payload_hash=preview.payload_hash,
            decision="denied", operator_id="operator:tester",
            reason="not on a Friday")
        decision, deny_reason = _decision(await client.post(
            "/hooks/pretooluse", json=_event(repo, "git push")))
    assert decision == "deny"
    assert "operator denied" in deny_reason and "not on a Friday" in deny_reason


async def test_agent_self_approval_is_blocked(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        decision, reason = _decision(await client.post(
            "/hooks/pretooluse",
            json=_event(repo, "hashgate accept abc --hash ffff")))
    assert decision == "deny"
    assert "operator's own terminal" in reason


async def test_non_repo_cwd_fails_closed(tmp_path) -> None:
    harness = Harness(tmp_path)
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    async with harness.client() as client:
        decision, reason = _decision(await client.post(
            "/hooks/pretooluse", json=_event(outside, "git push")))
    assert decision == "deny"
    assert "fail-closed" in reason


async def test_token_auth_when_configured(tmp_path, repo) -> None:
    harness = Harness(tmp_path, token="s3cret")
    async with harness.client() as client:
        unauthorized = await client.post("/hooks/pretooluse",
                                         json=_event(repo, "git status"))
        assert unauthorized.status_code == 401
        ok = await client.post("/hooks/pretooluse", json=_event(repo, "git status"),
                               headers={"X-Hashgate-Token": "s3cret"})
    assert ok.status_code == 200


async def test_full_chain_evidence_for_the_happy_path(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        _, reason = _decision(await client.post("/hooks/pretooluse",
                                                json=_event(repo, "git push")))
        await _approve(harness, reason)
        await client.post("/hooks/pretooluse", json=_event(repo, "git push"))
    preview_id = reason.split("Pending as ")[1].split(" ")[0]
    sm, store, _approvals = await harness.services()
    preview = await store.load_preview(preview_id)
    bundle = await EvidenceExporter(store=store) \
        .export_oversight_bundle_by_chain(preview.chain_id)
    assert [e["kind"] for e in bundle["events"]] == \
        ["preview", "operator_approved", "applied"]
    assert bundle["outcome"] == "applied"
    assert verify_bundle(bundle).valid
    # payload bodies (the command) never leak into evidence — the preview
    # event's reason is descriptive, not the raw command
    assert "origin" not in str(bundle)
    assert bundle["events"][0]["reason"] == \
        "agent requested git_push via PreToolUse hook"


async def test_subagent_provenance_lands_in_the_chain(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    event = _event(repo, "git push")
    event["agent_id"] = "sub-42"
    event["agent_type"] = "code-writer"
    async with harness.client() as client:
        _, reason = _decision(await client.post("/hooks/pretooluse", json=event))
    preview_id = reason.split("Pending as ")[1].split(" ")[0]
    sm, store, _approvals = await harness.services()
    preview = await store.load_preview(preview_id)
    assert preview.operator.operator_id == "agent:sub-42"
    events = await store.list_chain_events(preview.chain_id)
    assert [e["kind"] for e in events] == ["preview", "agent_context"]
    context = events[1]
    assert context["agent_id"] == "sub-42"
    assert context["agent_type"] == "code-writer"
    assert context["session_id"] == "sess-1"
    bundle = await EvidenceExporter(store=store) \
        .export_oversight_bundle_by_chain(preview.chain_id)
    assert verify_bundle(bundle).valid
    assert any(e.get("agent_id") == "sub-42" for e in bundle["events"])


async def test_main_agent_without_subagent_fields_gets_no_context_event(
        tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        _, reason = _decision(await client.post("/hooks/pretooluse",
                                                json=_event(repo, "git push")))
    preview_id = reason.split("Pending as ")[1].split(" ")[0]
    sm, store, _approvals = await harness.services()
    preview = await store.load_preview(preview_id)
    assert preview.operator.operator_id == "agent:sess-1"  # nothing invented
    assert [e["kind"] for e in await store.list_chain_events(preview.chain_id)] \
        == ["preview"]


async def test_health_endpoint_reports_effective_config(tmp_path) -> None:
    harness = Harness(tmp_path, ttl=123)
    async with harness.client() as client:
        response = await client.get("/health")
    info = response.json()
    assert info["db"] == harness.db_path
    assert info["ttl_seconds"] == 123
