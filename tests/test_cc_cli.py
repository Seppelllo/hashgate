# SPDX-License-Identifier: Apache-2.0
"""Operator CLI — pending/show/accept (hash echo mandatory)/deny/bundle."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from hashgate.integrations.claude_code.server import ServerConfig, create_app

_SRC = str(Path(__file__).parent.parent / "src")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    "HOME": "/tmp",
}


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True,
                   capture_output=True, env=_GIT_ENV)
    (repo / "a.txt").write_text("one\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                   capture_output=True, env=_GIT_ENV)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "first"], check=True,
                   capture_output=True, env=_GIT_ENV)
    return repo


async def _make_pending(tmp_path, repo) -> tuple[str, str, str]:
    """Drive the server once to create a pending preview; returns
    (db_path, preview_id, payload_hash)."""
    db_path = str(tmp_path / "hooks.db")
    app = create_app(ServerConfig(db_path=db_path))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://gate") as client:
        response = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"}})
    reason = response.json()["hookSpecificOutput"]["permissionDecisionReason"]
    preview_id = reason.split("Pending as ")[1].split(" ")[0]
    payload_hash = reason.split("(hash ")[1].split("…")[0]  # truncated in reason
    return db_path, preview_id, payload_hash


def _cli(args: list[str], db: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "hashgate.integrations.claude_code.cli",
         "--db", db, *args],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": _SRC, "HASHGATE_OPERATOR": "operator:tester"},
    )
    return proc.returncode, proc.stdout, proc.stderr


async def test_pending_show_accept_flow(tmp_path, repo, monkeypatch) -> None:
    monkeypatch.setenv("HASHGATE_OPERATOR", "operator:tester")
    db, preview_id, _ = await _make_pending(tmp_path, repo)

    code, out, _ = _cli(["pending"], db)
    assert code == 0 and preview_id in out and "git push origin main" in out

    code, out, _ = _cli(["show", preview_id], db)
    assert code == 0
    shown = json.loads(out)
    full_hash = shown["payload_hash"]
    assert shown["payload"]["command"] == "git push origin main"
    assert shown["approval"] is None

    # blind accept without the FULL hash echo fails
    code, _, err = _cli(["accept", preview_id, "--hash", full_hash[:12]], db)
    assert code == 1 and "hash echo mismatch" in err

    code, out, _ = _cli(["accept", preview_id, "--hash", full_hash], db)
    assert code == 0 and "single-use" in out and "expires" in out

    # now decided -> no longer pending; double-accept refused while open
    code, out, _ = _cli(["pending"], db)
    assert "no pending previews" in out
    code, _, err = _cli(["accept", preview_id, "--hash", full_hash], db)
    assert code == 1 and "already has an open approval" in err


async def test_deny_requires_reason_and_records(tmp_path, repo) -> None:
    db, preview_id, _ = await _make_pending(tmp_path, repo)
    code, out, _ = _cli(["show", preview_id], db)
    full_hash = json.loads(out)["payload_hash"]

    code, _, err = _cli(["deny", preview_id, "--reason", ""], db)
    assert code == 1 and "--reason is required" in err

    code, out, _ = _cli(["deny", preview_id, "--reason", "not today"], db)
    assert code == 0 and "denied" in out

    code, out, _ = _cli(["show", preview_id], db)
    assert json.loads(out)["approval"]["decision"] == "denied"
    assert full_hash  # unchanged by the denial


async def test_bundle_export_accepts_preview_id(tmp_path, repo) -> None:
    db, preview_id, _ = await _make_pending(tmp_path, repo)
    out_file = tmp_path / "bundle.json"
    code, out, _ = _cli(["bundle", preview_id, "--out", str(out_file)], db)
    assert code == 0 and "outcome=preview" in out
    bundle = json.loads(out_file.read_text())
    from hashgate.evidence import verify_bundle
    assert verify_bundle(bundle).valid
    assert bundle["events"][0]["kind"] == "preview"


async def test_unknown_ids_exit_1(tmp_path, repo) -> None:
    db, _, _ = await _make_pending(tmp_path, repo)
    assert _cli(["show", "nope"], db)[0] == 1
    assert _cli(["bundle", "nope"], db)[0] == 1
