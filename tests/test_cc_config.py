# SPDX-License-Identifier: Apache-2.0
"""Shared configuration — env > config.toml > default, effective for BOTH
processes. Pins the TTL bug fix: a TTL set in the shared config governs the
approval expiry no matter that the CLI (not the server) records the accept."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import httpx

from hashgate.integrations.claude_code.config import GateConfig, load_config
from hashgate.integrations.claude_code.server import create_app
from hashgate.store import utcnow

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


def test_invalid_toml_is_a_clean_error_with_hint(tmp_path) -> None:
    # field finding: an unquoted token value crashed the server with a raw
    # tomllib traceback — now a clean error naming file, problem and hint
    import pytest

    from hashgate.integrations.claude_code.config import GateConfigError
    config = tmp_path / "config.toml"
    config.write_text("operator_token = 29f0ae922d290ebc02ef46bef1124411\n")
    with pytest.raises(GateConfigError) as exc:
        load_config(config_path=str(config), env={})
    message = str(exc.value)
    assert str(config) in message
    assert "string values need quotes" in message


def test_invalid_toml_cli_dies_friendly(tmp_path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("token = abc\n")
    proc = _cli(["pending"], str(tmp_path / "hooks.db"),
                {"HASHGATE_CONFIG": str(config)})
    assert proc.returncode == 1
    assert "invalid TOML" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_defaults_without_file_or_env() -> None:
    cfg = load_config(config_path="/nonexistent/config.toml", env={})
    assert cfg.ttl_seconds == 900
    assert cfg.port == 8377
    assert cfg.token is None
    assert cfg.db_path == "~/.hashgate/hooks.db"
    assert cfg.config_path is None


def test_file_values_apply(tmp_path) -> None:
    config = tmp_path / "config.toml"
    config.write_text('db = "/tmp/x.db"\nttl_seconds = 30\n'
                      'token = "abc"\nport = 9999\n')
    cfg = load_config(config_path=str(config), env={})
    assert cfg.ttl_seconds == 30
    assert cfg.token == "abc"
    assert cfg.port == 9999
    assert cfg.db_path == "/tmp/x.db"
    assert cfg.config_path == str(config)


def test_env_overrides_file(tmp_path) -> None:
    config = tmp_path / "config.toml"
    config.write_text('ttl_seconds = 30\ntoken = "file-token"\n')
    cfg = load_config(config_path=str(config),
                      env={"HASHGATE_TTL_SECONDS": "60"})
    assert cfg.ttl_seconds == 60          # env wins
    assert cfg.token == "file-token"      # file still applies where env is silent


def test_env_config_path_selects_the_file(tmp_path) -> None:
    config = tmp_path / "elsewhere.toml"
    config.write_text("ttl_seconds = 45\n")
    cfg = load_config(env={"HASHGATE_CONFIG": str(config)})
    assert cfg.ttl_seconds == 45


def test_summary_shows_effective_values_and_masks_token(tmp_path) -> None:
    cfg = GateConfig(db_path=str(tmp_path / "x.db"), ttl_seconds=30,
                     token="secret-value", port=8377, config_path="/x/config.toml")
    line = cfg.summary()
    assert "ttl=30s" in line and "token=set" in line and "config=/x/config.toml" in line
    assert "secret-value" not in line  # never print the token itself


# --- the TTL bug, end to end: config.toml governs the CLI-issued approval ----
def _make_repo(tmp_path) -> Path:
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


async def _pending_preview(db_path: str, repo) -> str:
    app = create_app(GateConfig(db_path=db_path))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://gate") as client:
        response = await client.post("/hooks/pretooluse", json={
            "session_id": "s", "cwd": str(repo), "tool_name": "Bash",
            "tool_input": {"command": "git push"}})
    reason = response.json()["hookSpecificOutput"]["permissionDecisionReason"]
    return reason.split("Pending as ")[1].split(" ")[0]


def _cli(args: list[str], db: str, env_extra: dict):
    return subprocess.run(
        [sys.executable, "-m", "hashgate.integrations.claude_code.cli",
         "--db", db, *args],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONPATH": _SRC, "HASHGATE_OPERATOR": "operator:t",
             **env_extra})


async def _accept_and_read_expiry(tmp_path, repo, env_extra: dict) -> float:
    db = str(tmp_path / "hooks.db")
    preview_id = await _pending_preview(db, repo)
    show = _cli(["show", preview_id], db, env_extra)
    payload_hash = json.loads(show.stdout[show.stdout.index("{"):])["payload_hash"]
    accept = _cli(["accept", preview_id, "--hash", payload_hash], db, env_extra)
    assert accept.returncode == 0, accept.stderr
    show = _cli(["show", preview_id], db, env_extra)
    expires_at = json.loads(
        show.stdout[show.stdout.index("{"):])["approval"]["expires_at"]
    return (datetime.fromisoformat(expires_at) - utcnow()).total_seconds()


async def test_config_toml_ttl_governs_cli_accept(tmp_path) -> None:
    repo = _make_repo(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text("ttl_seconds = 30\n")
    remaining = await _accept_and_read_expiry(
        tmp_path, repo, {"HASHGATE_CONFIG": str(config)})
    assert 0 < remaining <= 31  # 30s from config.toml, NOT the 900s default


async def test_env_ttl_overrides_config_toml_for_the_cli(tmp_path) -> None:
    repo = _make_repo(tmp_path)
    config = tmp_path / "config.toml"
    config.write_text("ttl_seconds = 30\n")
    remaining = await _accept_and_read_expiry(
        tmp_path, repo,
        {"HASHGATE_CONFIG": str(config), "HASHGATE_TTL_SECONDS": "120"})
    assert 100 < remaining <= 121  # env beats file
