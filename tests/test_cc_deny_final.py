# SPDX-License-Identifier: Apache-2.0
"""deny --final: a hash-bound permanent refusal. Identical state => immediate
denied_final (no new pending, no later accept); changed state => a normal new
request. Evidence carries a dedicated denied_final event."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from hashgate.evidence import EvidenceExporter, verify_bundle
from hashgate.integrations.claude_code.server import ServerConfig, create_app

_SRC = str(Path(__file__).parent.parent / "src")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    "HOME": "/tmp",
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


async def _pretooluse(db: str, repo, command="git push origin main") -> dict:
    app = create_app(ServerConfig(db_path=db))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://gate") as client:
        response = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": command}})
    return response.json()["hookSpecificOutput"]


def _cli(args: list[str], db: str):
    import os
    proc = subprocess.run(
        [sys.executable, "-m", "hashgate.integrations.claude_code.cli",
         "--db", db, *args],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": _SRC,
             "HASHGATE_OPERATOR": "operator:tester",
             "HASHGATE_CONFIG": "/nonexistent/config.toml"})
    return proc.returncode, proc.stdout, proc.stderr


async def _pending(db, repo, command="git push origin main") -> str:
    out = await _pretooluse(db, repo, command)
    return out["permissionDecisionReason"].split("Pending as ")[1].split(" ")[0]


async def test_final_deny_blocks_identical_state_without_new_pending(tmp_path, repo) -> None:
    db = str(tmp_path / "hooks.db")
    preview_id = await _pending(db, repo)
    code, out, _ = _cli(["deny", preview_id, "--reason", "never like this",
                         "--final"], db)
    assert code == 0
    assert "FINALLY denied" in out
    assert "will never be approved" in out
    # identical state again: immediate denied_final, naming reason + time
    result = await _pretooluse(db, repo)
    assert result["permissionDecision"] == "deny"
    reason = result["permissionDecisionReason"]
    assert "FINALLY denied this exact state" in reason
    assert "never like this" in reason
    assert " at " in reason
    assert "a changed state" in reason.lower() or "changed state" in reason
    # and no second pending appeared
    code, out, _ = _cli(["pending"], db)
    assert "no pending previews" in out


async def test_changed_state_is_a_new_decision(tmp_path, repo) -> None:
    db = str(tmp_path / "hooks.db")
    preview_id = await _pending(db, repo)
    _cli(["deny", preview_id, "--reason", "no", "--final"], db)
    _git(repo, "commit", "--allow-empty", "-m", "amended intent")  # new hash
    result = await _pretooluse(db, repo)
    assert "requires operator approval" in result["permissionDecisionReason"]
    assert "Pending as" in result["permissionDecisionReason"]  # normal request


async def test_finally_denied_preview_cannot_be_accepted_later(tmp_path, repo) -> None:
    db = str(tmp_path / "hooks.db")
    preview_id = await _pending(db, repo)
    code, out, _ = _cli(["show", preview_id], db)
    import json
    payload_hash = json.loads(out[out.index("{"):])["payload_hash"]
    _cli(["deny", preview_id, "--reason", "no", "--final"], db)
    code, _, err = _cli(["accept", preview_id, "--hash", payload_hash], db)
    assert code == 1
    assert "FINALLY denied" in err
    assert "a changed state" in err


async def test_plain_deny_stays_overridable_by_accept(tmp_path, repo) -> None:
    # the situational deny keeps its v0.1 semantics: the operator may change
    # their mind and approve the same preview later
    db = str(tmp_path / "hooks.db")
    preview_id = await _pending(db, repo)
    code, out, _ = _cli(["show", preview_id], db)
    import json
    payload_hash = json.loads(out[out.index("{"):])["payload_hash"]
    _cli(["deny", preview_id, "--reason", "not yet"], db)
    code, out, _ = _cli(["accept", preview_id, "--hash", payload_hash], db)
    assert code == 0 and "approved" in out


async def test_evidence_chain_and_history_show_denied_final(tmp_path, repo) -> None:
    db = str(tmp_path / "hooks.db")
    preview_id = await _pending(db, repo)
    _cli(["deny", preview_id, "--reason", "hard no", "--final"], db)
    # history outcome
    code, out, _ = _cli(["history"], db)
    assert "denied_final" in out and "hard no" in out
    # dedicated chain event, bundle verifies
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from hashgate.adapters.sqlalchemy_store import SQLAlchemyStore
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    sm = async_sessionmaker(engine, expire_on_commit=False)
    store = SQLAlchemyStore(sm)
    preview = await store.load_preview(preview_id)
    events = await store.list_chain_events(preview.chain_id)
    assert [e["kind"] for e in events] == ["preview", "denied_final"]
    bundle = await EvidenceExporter(store=store) \
        .export_oversight_bundle_by_chain(preview.chain_id)
    assert bundle["outcome"] == "denied_final"
    assert verify_bundle(bundle).valid
