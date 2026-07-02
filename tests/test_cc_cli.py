# SPDX-License-Identifier: Apache-2.0
"""Operator CLI — pending/show/accept (hash echo mandatory)/deny/history/bundle."""
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
    _git(repo, "commit", "-m", "first commit")
    return repo


async def _pretooluse(db_path: str, repo, command: str) -> dict:
    app = create_app(ServerConfig(db_path=db_path))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://gate") as client:
        response = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": command}})
    return response.json().get("hookSpecificOutput") or {}


async def _make_pending(tmp_path, repo, command="git push origin main"):
    db_path = str(tmp_path / "hooks.db")
    reason = (await _pretooluse(db_path, repo, command))["permissionDecisionReason"]
    preview_id = reason.split("Pending as ")[1].split(" ")[0]
    return db_path, preview_id


def _cli(args: list[str], db: str, env_extra: dict | None = None):
    proc = subprocess.run(
        [sys.executable, "-m", "hashgate.integrations.claude_code.cli",
         "--db", db, *args],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": _SRC,
             "HASHGATE_OPERATOR": "operator:tester",
             "HASHGATE_CONFIG": "/nonexistent/hashgate-config.toml",
             **(env_extra or {})},
    )
    return proc.returncode, proc.stdout, proc.stderr


def _json_part(out: str) -> dict:
    return json.loads(out[out.index("{"):])


async def test_pending_show_accept_flow(tmp_path, repo) -> None:
    db, preview_id = await _make_pending(tmp_path, repo)

    code, out, _ = _cli(["pending"], db)
    assert code == 0 and preview_id in out and "git push origin main" in out

    code, out, _ = _cli(["show", preview_id], db)
    assert code == 0
    # the transport list renders prominently before the JSON
    assert "this push transports 1 commit(s):" in out
    assert "first commit" in out
    shown = _json_part(out)
    full_hash = shown["payload_hash"]
    assert shown["payload"]["command"] == "git push origin main"
    assert shown["approval"] is None

    # blind accept without the FULL hash echo fails, naming length + source
    code, _, err = _cli(["accept", preview_id, "--hash", full_hash[:12]], db)
    assert code == 1
    assert "FULL 64-character" in err and "you passed 12 characters" in err
    assert "hashgate show" in err

    code, out, _ = _cli(["accept", preview_id, "--hash", full_hash], db)
    assert code == 0 and "single-use" in out and "expires" in out
    assert "— in " in out  # countdown
    assert "the agent can retry the command now" in out

    # ONE path for a second accept: idempotent notice, no new approval row
    code, out, _ = _cli(["accept", preview_id, "--hash", full_hash], db)
    assert code == 0
    assert "already has an open approval" in out
    assert "the agent can retry the command now" in out
    code, out, _ = _cli(["show", preview_id], db)
    assert _json_part(out)["approval"]["decision"] == "approved"

    code, out, _ = _cli(["pending"], db)
    assert "no pending previews" in out


async def test_deny_requires_reason_and_records(tmp_path, repo) -> None:
    db, preview_id = await _make_pending(tmp_path, repo)
    code, _, err = _cli(["deny", preview_id, "--reason", ""], db)
    assert code == 1 and "--reason is required" in err

    code, out, _ = _cli(["deny", preview_id, "--reason", "not today"], db)
    assert code == 0 and "denied" in out

    code, out, _ = _cli(["show", preview_id], db)
    assert _json_part(out)["approval"]["decision"] == "denied"


async def test_history_lists_outcomes(tmp_path, repo) -> None:
    db, denied_id = await _make_pending(tmp_path, repo, "git push origin main")
    _cli(["deny", denied_id, "--reason", "wrong branch"], db)
    # a second, different proposal: approve and consume it
    _git(repo, "commit", "--allow-empty", "-m", "second")
    reason = (await _pretooluse(db, repo, "git push origin main"))[
        "permissionDecisionReason"]
    applied_id = reason.split("Pending as ")[1].split(" ")[0]
    code, out, _ = _cli(["show", applied_id], db)
    full_hash = _json_part(out)["payload_hash"]
    _cli(["accept", applied_id, "--hash", full_hash], db)
    allow = await _pretooluse(db, repo, "git push origin main")
    assert allow["permissionDecision"] == "allow"

    code, out, _ = _cli(["history"], db)
    assert code == 0
    lines = out.strip().splitlines()
    assert len(lines) == 2  # newest first
    assert applied_id[:12] in lines[0] and "applied" in lines[0]
    assert "head=" in lines[0] and "decided=" in lines[0]
    assert denied_id[:12] in lines[1] and "denied" in lines[1]
    assert "reason='wrong branch'" in lines[1]

    # 'approved' outcome (open approval, not yet consumed)
    _git(repo, "commit", "--allow-empty", "-m", "third")
    reason = (await _pretooluse(db, repo, "git push origin main"))[
        "permissionDecisionReason"]
    open_id = reason.split("Pending as ")[1].split(" ")[0]
    code, out, _ = _cli(["show", open_id], db)
    _cli(["accept", open_id, "--hash", _json_part(out)["payload_hash"]], db)
    code, out, _ = _cli(["history", "--limit", "1"], db)
    assert open_id[:12] in out and "approved" in out


async def test_denied_head_warning_in_show(tmp_path, repo) -> None:
    # deny state A; commit; the next proposal transports A's HEAD -> warning
    db, denied_id = await _make_pending(tmp_path, repo)
    _cli(["deny", denied_id, "--reason", "secret in diff"], db)
    code, out, _ = _cli(["show", denied_id], db)
    denied_head = _json_part(out)["payload"]["head_sha"]

    (repo / "b.txt").write_text("more\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "on top of denied state")
    _, new_id = await _make_pending(tmp_path, repo)

    code, out, _ = _cli(["show", new_id], db)
    assert code == 0
    assert f"⚠ commit {denied_head[:12]} was HEAD of a denied push proposal" in out
    assert "reason: 'secret in diff'" in out
    # the warning is display-only: payload hash == canonical hash of payload
    shown = _json_part(out)
    from hashgate.canonical import canonical_hash
    assert shown["payload_hash"] == canonical_hash(shown["payload"])
    assert "was HEAD of a denied" not in json.dumps(shown["payload"])


async def test_show_without_id_lists_pending(tmp_path, repo) -> None:
    db, preview_id = await _make_pending(tmp_path, repo)
    code, out, _ = _cli(["show"], db)
    assert code == 0 and preview_id in out


async def test_unknown_command_suggests_closest(tmp_path, repo) -> None:
    db, _ = await _make_pending(tmp_path, repo)
    code, _, err = _cli(["pnding"], db)
    assert code == 2
    assert "did you mean 'pending'?" in err


async def test_bundle_export_accepts_preview_id(tmp_path, repo) -> None:
    db, preview_id = await _make_pending(tmp_path, repo)
    out_file = tmp_path / "bundle.json"
    code, out, _ = _cli(["bundle", preview_id, "--out", str(out_file)], db)
    assert code == 0 and "outcome=preview" in out
    bundle = json.loads(out_file.read_text())
    from hashgate.evidence import verify_bundle
    assert verify_bundle(bundle).valid


async def test_unknown_ids_exit_1(tmp_path, repo) -> None:
    db, _ = await _make_pending(tmp_path, repo)
    assert _cli(["show", "nope"], db)[0] == 1
    assert _cli(["bundle", "nope"], db)[0] == 1
