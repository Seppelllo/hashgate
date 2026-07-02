# SPDX-License-Identifier: Apache-2.0
"""Operator web UI — auth boundaries (separate operator token, hook token
never authorizes), typed 12-hex echo, CLI-identical decision semantics,
shared rendering truth, and the token-leak grep."""
from __future__ import annotations

import subprocess

import httpx
import pytest

from hashgate.integrations.claude_code.approvals import HookApprovalRow
from hashgate.integrations.claude_code.server import ServerConfig, create_app

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    "HOME": "/tmp",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "init.defaultBranch",
    "GIT_CONFIG_VALUE_0": "master",
}

HOOK_TOKEN = "hook-secret-abc"
OPERATOR_TOKEN = "operator-secret-xyz"


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
    _git(repo, "commit", "-m", "first commit")
    return repo


class Harness:
    def __init__(self, tmp_path, operator_token=OPERATOR_TOKEN):
        self.db_path = str(tmp_path / "hooks.db")
        self.app = create_app(ServerConfig(
            db_path=self.db_path, token=HOOK_TOKEN, operator_token=operator_token))

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://gate")


async def _pending_preview(client, repo) -> tuple[str, str]:
    response = await client.post("/hooks/pretooluse", json={
        "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
        "tool_input": {"command": "git push origin main"}},
        headers={"X-Hashgate-Token": HOOK_TOKEN})
    reason = response.json()["hookSpecificOutput"]["permissionDecisionReason"]
    preview_id = reason.split("Pending as ")[1].split(" ")[0]
    return preview_id, reason


async def _login(client) -> str:
    """Log in; returns the CSRF token scraped from a rendered page."""
    response = await client.post("/ui/login", data={"token": OPERATOR_TOKEN},
                                 follow_redirects=False)
    assert response.status_code == 303
    page = await client.get("/ui")
    assert page.status_code == 200
    return page.text.split('name="csrf" value="')[1].split('"')[0]


# --- auth boundaries ------------------------------------------------------------
async def test_no_operator_token_configured_means_403_everywhere(tmp_path, repo) -> None:
    harness = Harness(tmp_path, operator_token=None)
    async with harness.client() as client:
        for path in ("/ui", "/ui/login", "/ui/history", "/ui/bundle/x",
                     "/ui/preview/x", "/ui/api/pending"):
            response = await client.get(path)
            assert response.status_code == 403, path
            assert "operator_token" in response.text  # setup hint, fail-closed
        for path in ("/ui/accept", "/ui/deny"):
            response = await client.post(path, data={})
            assert response.status_code == 403, path


async def test_all_routes_reject_without_auth_including_readonly(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        for path in ("/ui/history", f"/ui/preview/{preview_id}",
                     f"/ui/bundle/{preview_id}", "/ui/partial/pending"):
            response = await client.get(path, follow_redirects=False)
            assert response.status_code in (303, 403), path  # redirect to login
        api = await client.get("/ui/api/pending")
        assert api.status_code == 403


async def test_hook_token_never_authorizes_ui_routes(tmp_path, repo) -> None:
    # THE separation pin: the hook token lives in the agent-visible
    # environment and must not open the operator surface
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        for headers in (
            {"X-Hashgate-Operator-Token": HOOK_TOKEN},   # wrong secret
            {"X-Hashgate-Token": HOOK_TOKEN},            # wrong header entirely
        ):
            response = await client.get("/ui/api/pending", headers=headers)
            assert response.status_code == 403, headers
        deny = await client.post("/ui/deny", data={
            "preview_id": preview_id, "reason": "x"},
            headers={"X-Hashgate-Operator-Token": HOOK_TOKEN})
        assert deny.status_code == 403


async def test_cookie_alone_never_mutates_csrf_pinned(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        await _login(client)  # session cookie now set on the client
        response = await client.post("/ui/deny", data={
            "preview_id": preview_id, "reason": "no csrf"})
        assert response.status_code == 403
        # no approval row was written
        page = await client.get(f"/ui/preview/{preview_id}")
        assert "decision:" not in page.text


async def test_wrong_login_token_is_rejected(tmp_path) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        response = await client.post("/ui/login", data={"token": "wrong"})
        assert response.status_code == 403
        assert "wrong operator token" in response.text


async def test_operator_token_appears_in_no_response(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        csrf = await _login(client)
        responses = [
            await client.get("/ui"),
            await client.get(f"/ui/preview/{preview_id}"),
            await client.get("/ui/history"),
            await client.get("/ui/login"),
            await client.post("/ui/accept", data={
                "preview_id": preview_id, "hash_prefix": "0" * 12,
                "csrf": csrf}, follow_redirects=True),
        ]
        for response in responses:
            blob = response.text + str(response.headers)
            assert OPERATOR_TOKEN not in blob  # never echoed, not even in Set-Cookie


# --- rendering: one truth with the CLI -------------------------------------------
async def test_pending_and_detail_render_shared_warnings(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        # a force-push pending: carries the shared ⚠ warning line
        response = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": "git push --force origin main"}},
            headers={"X-Hashgate-Token": HOOK_TOKEN})
        reason = response.json()["hookSpecificOutput"]["permissionDecisionReason"]
        preview_id = reason.split("Pending as ")[1].split(" ")[0]
        await _login(client)
        pending = await client.get("/ui")
        assert "git_force_push" in pending.text
        assert "⚠ force-push" in pending.text  # first warning on the list card
        detail = await client.get(f"/ui/preview/{preview_id}")
        assert "⚠ force-push" in detail.text and "overwrites" in detail.text
        # the FULL hash is visible on the detail page
        from hashgate.integrations.claude_code.server import _State  # noqa: F401
        assert "payload hash (canonical)" in detail.text


# --- accept: typed 12-hex echo -----------------------------------------------------
async def test_accept_with_correct_prefix_matches_cli_semantics(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        csrf = await _login(client)
        detail = await client.get(f"/ui/preview/{preview_id}")
        full_hash = detail.text.split('id="full-hash">')[1].split("</code>")[0]
        full_hash = full_hash.replace('<span class="hash-rest">', "") \
                             .replace("</span>", "").strip()
        assert len(full_hash) == 64
        response = await client.post("/ui/accept", data={
            "preview_id": preview_id, "hash_prefix": full_hash[:12],
            "reason": "looks good", "csrf": csrf}, follow_redirects=True)
        assert response.status_code == 200
        assert "approved as" in response.text and "single-use" in response.text
        assert "expires" in response.text
        # identical semantics as CLI: retry consumes single-use approval
        allow = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"}},
            headers={"X-Hashgate-Token": HOOK_TOKEN})
        assert allow.json()["hookSpecificOutput"]["permissionDecision"] == "allow"
        replay = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"}},
            headers={"X-Hashgate-Token": HOOK_TOKEN})
        assert "already consumed" in \
            replay.json()["hookSpecificOutput"]["permissionDecisionReason"]
        # chain event identical to the CLI path
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from hashgate.adapters.sqlalchemy_store import SQLAlchemyStore
        engine = create_async_engine(f"sqlite+aiosqlite:///{harness.db_path}")
        store = SQLAlchemyStore(async_sessionmaker(engine, expire_on_commit=False))
        preview = await store.load_preview(preview_id)
        events = await store.list_chain_events(preview.chain_id)
        assert [e["kind"] for e in events] == \
            ["preview", "operator_approved", "applied"]
        assert events[1]["channel"] == "web-ui"  # provenance: decided via UI
        assert events[1]["operator_id"] == "operator:web-ui"


@pytest.mark.parametrize("prefix", [
    "0" * 12,          # wrong prefix
    "abc",             # too short
    "",                # empty
    "g" * 12,          # not hex
])
async def test_wrong_prefix_approves_nothing(tmp_path, repo, prefix) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        csrf = await _login(client)
        response = await client.post("/ui/accept", data={
            "preview_id": preview_id, "hash_prefix": prefix, "csrf": csrf},
            follow_redirects=True)
        assert "hash echo mismatch" in response.text
        from sqlalchemy import func, select
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        engine = create_async_engine(f"sqlite+aiosqlite:///{harness.db_path}")
        sm = async_sessionmaker(engine, expire_on_commit=False)
        async with sm() as session:
            count = (await session.execute(
                select(func.count()).select_from(HookApprovalRow))).scalar()
        assert count == 0  # nothing was approved


async def test_prefix_is_checked_against_the_full_stored_hash(tmp_path, repo) -> None:
    # the prefix must be a PREFIX of the stored 64-char hash — pinned by
    # accepting with hash[:12] and rejecting hash[1:13] (valid hex, wrong slice)
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, reason = await _pending_preview(client, repo)
        short_from_reason = reason.split("(hash ")[1].split("…")[0]
        csrf = await _login(client)
        wrong_slice = short_from_reason[1:] + "0"
        response = await client.post("/ui/accept", data={
            "preview_id": preview_id, "hash_prefix": wrong_slice, "csrf": csrf},
            follow_redirects=True)
        assert "hash echo mismatch" in response.text


# --- deny (+final) -------------------------------------------------------------------
async def test_deny_final_via_ui_matches_cli_semantics(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        csrf = await _login(client)
        response = await client.post("/ui/deny", data={
            "preview_id": preview_id, "reason": "never", "final": "on",
            "csrf": csrf}, follow_redirects=True)
        assert "FINALLY denied" in response.text
        # server refuses the identical state with the denied_final reason
        retry = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"}},
            headers={"X-Hashgate-Token": HOOK_TOKEN})
        assert "FINALLY denied this exact state" in \
            retry.json()["hookSpecificOutput"]["permissionDecisionReason"]
        # dedicated chain event, identical to the CLI path
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from hashgate.adapters.sqlalchemy_store import SQLAlchemyStore
        engine = create_async_engine(f"sqlite+aiosqlite:///{harness.db_path}")
        store = SQLAlchemyStore(async_sessionmaker(engine, expire_on_commit=False))
        preview = await store.load_preview(preview_id)
        events = await store.list_chain_events(preview.chain_id)
        assert [e["kind"] for e in events] == ["preview", "denied_final"]


async def test_deny_requires_reason(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        csrf = await _login(client)
        response = await client.post("/ui/deny", data={
            "preview_id": preview_id, "reason": "  ", "csrf": csrf},
            follow_redirects=True)
        assert "a reason is required" in response.text


# --- history / bundle ------------------------------------------------------------------
async def test_history_and_bundle_views(tmp_path, repo) -> None:
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        csrf = await _login(client)
        await client.post("/ui/deny", data={
            "preview_id": preview_id, "reason": "wrong branch", "final": "on",
            "csrf": csrf})
        history = await client.get("/ui/history")
        assert "denied_final" in history.text
        assert "wrong branch" in history.text
        bundle_page = await client.get(f"/ui/bundle/{preview_id}")
        assert "denied_final" in bundle_page.text  # outcome + timeline event
        assert "Download bundle JSON" in bundle_page.text
        download = await client.get(f"/ui/bundle/{preview_id}?download=1")
        assert download.headers["content-type"].startswith("application/json")
        assert "attachment" in download.headers["content-disposition"]
        import json as _json

        from hashgate.evidence import verify_bundle
        assert verify_bundle(_json.loads(download.text)).valid


async def test_header_token_auth_works_for_tools(tmp_path, repo) -> None:
    # the operator token as a custom header is the tool-friendly path and
    # doubles as CSRF-safe mutation auth (custom headers cannot be set
    # cross-site)
    harness = Harness(tmp_path)
    async with harness.client() as client:
        preview_id, _ = await _pending_preview(client, repo)
        headers = {"X-Hashgate-Operator-Token": OPERATOR_TOKEN}
        api = await client.get("/ui/api/pending", headers=headers)
        assert api.status_code == 200
        assert api.json()["pending"][0]["preview_id"] == preview_id
        deny = await client.post("/ui/deny", data={
            "preview_id": preview_id, "reason": "via header"}, headers=headers,
            follow_redirects=False)
        assert deny.status_code == 303  # accepted without session/CSRF
