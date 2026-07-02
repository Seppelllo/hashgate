# SPDX-License-Identifier: Apache-2.0
"""v0.2 actions — destructive git + deploys: derivation against real
fixtures, state change => new hash, unresolved marked (never invented),
secrets only as hashes, deterministic, offline."""
from __future__ import annotations

import json
import subprocess

import pytest

from hashgate.canonical import canonical_hash
from hashgate.errors import ValidationFailed
from hashgate.integrations.claude_code.actions import (
    DockerComposeUpAction,
    GenericDeployScriptAction,
    GitCommandContext,
    GitForcePushAction,
    GitResetHardAction,
    KamalDeployAction,
    KubectlApplyAction,
    RmRfAction,
)

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


@pytest.fixture
def repo_with_remote(repo, tmp_path):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(remote)],
                   check=True, capture_output=True, env=_GIT_ENV)
    _git(repo, "remote", "add", "origin", str(remote))
    _git(repo, "push", "-u", "origin", "main")
    return repo, remote


def _ctx(repo, command) -> GitCommandContext:
    return GitCommandContext(cwd=str(repo), command=command)


# --- force push -----------------------------------------------------------------
async def test_force_push_binds_flag_and_overwritten_remote(repo_with_remote) -> None:
    repo, _ = repo_with_remote
    _git(repo, "commit", "--allow-empty", "-m", "local work")
    payload = await GitForcePushAction().derive(
        _ctx(repo, "git push --force-with-lease origin main"))
    assert payload["action"] == "git_force_push"
    assert payload["force"] is True
    assert payload["force_flag"] == "--force-with-lease"
    assert payload["overwrites_remote_sha"] == _git(repo, "rev-parse", "origin/main")
    assert payload["remote_sha"] == payload["overwrites_remote_sha"]
    assert [c["subject"] for c in payload["commits"]] == ["local work"]


async def test_force_push_hash_changes_when_remote_moves(repo_with_remote, tmp_path) -> None:
    repo, remote = repo_with_remote
    action = GitForcePushAction()
    ctx = _ctx(repo, "git push -f")
    h1 = canonical_hash(await action.derive(ctx))
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "--branch", "main", str(remote), str(clone)],
                   check=True, capture_output=True, env=_GIT_ENV)
    subprocess.run(["git", "-C", str(clone), "commit", "--allow-empty",
                    "-m", "other"], check=True, capture_output=True, env=_GIT_ENV)
    subprocess.run(["git", "-C", str(clone), "push", "origin", "main"],
                   check=True, capture_output=True, env=_GIT_ENV)
    _git(repo, "fetch", "origin")
    h2 = canonical_hash(await action.derive(ctx))
    assert h1 != h2  # what would be overwritten changed


async def test_force_push_validate_refuses_plain_push(repo_with_remote) -> None:
    repo, _ = repo_with_remote
    action = GitForcePushAction()
    ctx = _ctx(repo, "git push origin main")
    payload = await action.derive(ctx)
    with pytest.raises(ValidationFailed):
        await action.validate(ctx, payload)


# --- reset --hard ----------------------------------------------------------------
async def test_reset_hard_binds_target_and_discarded_commits(repo) -> None:
    _git(repo, "commit", "--allow-empty", "-m", "will be dropped 1")
    _git(repo, "commit", "--allow-empty", "-m", "will be dropped 2")
    payload = await GitResetHardAction().derive(_ctx(repo, "git reset --hard HEAD~2"))
    assert payload["target"] == "HEAD~2"
    assert payload["target_sha"] == _git(repo, "rev-parse", "HEAD~2")
    assert payload["head_sha"] == _git(repo, "rev-parse", "HEAD")
    assert [c["subject"] for c in payload["discarded_commits"]] == \
        ["will be dropped 2", "will be dropped 1"]


async def test_reset_hard_unresolvable_target_is_marked(repo) -> None:
    payload = await GitResetHardAction().derive(
        _ctx(repo, "git reset --hard no-such-ref"))
    assert payload["target"] == "no-such-ref"
    assert payload["target_sha"] is None          # unresolved, visible
    assert payload["discarded_commits"] is None   # not invented


async def test_reset_hard_defaults_to_head(repo) -> None:
    payload = await GitResetHardAction().derive(_ctx(repo, "git reset --hard"))
    assert payload["target"] == "HEAD"
    assert payload["discarded_commits"] == []


# --- rm -rf ------------------------------------------------------------------------
async def test_rm_rf_resolves_globs_and_detects_tracked_files(repo) -> None:
    (repo / "build").mkdir()
    (repo / "build" / "x.o").write_text("x")
    (repo / "tracked.txt").write_text("t")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "track")
    payload = await RmRfAction().derive(_ctx(repo, "rm -rf build/ tracked.txt"))
    assert payload["repo_root"] == _git(repo, "rev-parse", "--show-toplevel")
    resolved = [t for target in payload["targets"] for t in (target["resolved"] or [])]
    assert any(p.endswith("build/") or p.endswith("build") for p in resolved)
    assert any(p.endswith("tracked.txt") for p in resolved)
    assert payload["tracked_paths_affected"] is True


async def test_rm_rf_untracked_only_and_variables_marked(repo) -> None:
    (repo / "junk").mkdir()
    payload = await RmRfAction().derive(_ctx(repo, "rm -rf junk $HOME/x"))
    assert payload["tracked_paths_affected"] is False
    variable_target = next(t for t in payload["targets"] if t["raw"] == "$HOME/x")
    assert variable_target["resolved"] is None  # never guessed


async def test_rm_rf_outside_a_repo_marks_tracking_unknown(tmp_path) -> None:
    workdir = tmp_path / "plain"
    workdir.mkdir()
    (workdir / "data").mkdir()
    payload = await RmRfAction().derive(
        GitCommandContext(cwd=str(workdir), command="rm -rf data"))
    assert payload["repo_root"] is None
    assert payload["tracked_paths_affected"] is None  # unknown, not false


# --- kamal ---------------------------------------------------------------------------
async def test_kamal_binds_head_destination_and_config_hash(repo) -> None:
    config = repo / "config"
    config.mkdir()
    (config / "deploy.yml").write_text("service: app\n")
    (config / "deploy.staging.yml").write_text("host: staging\n")
    payload = await KamalDeployAction().derive(
        _ctx(repo, "kamal deploy -d staging"))
    assert payload["head_sha"] == _git(repo, "rev-parse", "HEAD")
    assert payload["destination"] == "staging"
    assert payload["deploy_config_hash"] is not None
    assert payload["destination_config_hash"] is not None
    assert "service: app" not in json.dumps(payload)  # hash, never content


async def test_kamal_config_change_changes_hash(repo) -> None:
    config = repo / "config"
    config.mkdir()
    (config / "deploy.yml").write_text("service: app\n")
    action = KamalDeployAction()
    ctx = _ctx(repo, "kamal deploy")
    h1 = canonical_hash(await action.derive(ctx))
    (config / "deploy.yml").write_text("service: app\nimage: new\n")
    h2 = canonical_hash(await action.derive(ctx))
    _git(repo, "commit", "--allow-empty", "-m", "new head")
    h3 = canonical_hash(await action.derive(ctx))
    assert len({h1, h2, h3}) == 3  # config change AND head change both bind


async def test_kamal_missing_config_is_visible(repo) -> None:
    payload = await KamalDeployAction().derive(_ctx(repo, "kamal deploy"))
    assert payload["deploy_config_hash"] is None  # marked, not omitted


# --- docker compose ---------------------------------------------------------------------
async def test_compose_binds_file_hashes_services_and_env_hash(tmp_path) -> None:
    workdir = tmp_path / "app"
    workdir.mkdir()
    (workdir / "docker-compose.yml").write_text("services:\n  web: {}\n")
    (workdir / ".env").write_text("DB_PASSWORD=super-secret-value\n")
    payload = await DockerComposeUpAction().derive(
        GitCommandContext(cwd=str(workdir), command="docker compose up -d web worker"))
    assert payload["compose_files"][0]["path"] == "docker-compose.yml"
    assert payload["compose_files"][0]["content_hash"]
    assert payload["services"] == ["web", "worker"]
    assert payload["env_file_hash"]
    dump = json.dumps(payload)
    assert "super-secret-value" not in dump   # secrets: hash only, pinned
    assert "DB_PASSWORD" not in dump


async def test_compose_explicit_files_and_missing_default(tmp_path) -> None:
    workdir = tmp_path / "app"
    workdir.mkdir()
    (workdir / "prod.yml").write_text("services: {}\n")
    payload = await DockerComposeUpAction().derive(GitCommandContext(
        cwd=str(workdir), command="docker compose -f prod.yml -f missing.yml up"))
    by_path = {f["path"]: f["content_hash"] for f in payload["compose_files"]}
    assert by_path["prod.yml"] is not None
    assert by_path["missing.yml"] is None  # missing file: visible, not dropped
    empty = tmp_path / "empty"
    empty.mkdir()
    payload = await DockerComposeUpAction().derive(GitCommandContext(
        cwd=str(empty), command="docker compose up"))
    assert payload["compose_files"] == [{"path": "unresolved", "content_hash": None}]


async def test_compose_env_change_changes_hash(tmp_path) -> None:
    workdir = tmp_path / "app"
    workdir.mkdir()
    (workdir / "compose.yaml").write_text("services: {}\n")
    (workdir / ".env").write_text("A=1\n")
    action = DockerComposeUpAction()
    ctx = GitCommandContext(cwd=str(workdir), command="docker compose up")
    h1 = canonical_hash(await action.derive(ctx))
    (workdir / ".env").write_text("A=2\n")
    h2 = canonical_hash(await action.derive(ctx))
    assert h1 != h2


# --- kubectl ------------------------------------------------------------------------------
async def test_kubectl_binds_manifests_context_namespace(tmp_path) -> None:
    workdir = tmp_path / "k"
    workdir.mkdir()
    (workdir / "app.yaml").write_text("kind: Deployment\n")
    payload = await KubectlApplyAction().derive(GitCommandContext(
        cwd=str(workdir),
        command="kubectl --context prod -n web apply -f app.yaml"))
    assert payload["context"] == "prod"
    assert payload["namespace"] == "web"
    assert payload["manifests"][0]["path"] == "app.yaml"
    assert payload["manifests"][0]["content_hash"]


async def test_kubectl_unresolved_context_is_explicit(tmp_path) -> None:
    workdir = tmp_path / "k"
    workdir.mkdir()
    (workdir / "m.yml").write_text("kind: Service\n")
    payload = await KubectlApplyAction().derive(GitCommandContext(
        cwd=str(workdir), command="kubectl apply -f m.yml"))
    assert payload["context"] == "unresolved"    # WHICH cluster? say so
    assert payload["namespace"] == "unresolved"


async def test_kubectl_directory_manifests_are_hashed(tmp_path) -> None:
    workdir = tmp_path / "k"
    (workdir / "k8s").mkdir(parents=True)
    (workdir / "k8s" / "a.yaml").write_text("a: 1\n")
    (workdir / "k8s" / "b.yml").write_text("b: 2\n")
    payload = await KubectlApplyAction().derive(GitCommandContext(
        cwd=str(workdir), command="kubectl apply -f k8s/"))
    paths = [m["path"] for m in payload["manifests"]]
    assert sorted(paths) == ["k8s/a.yaml", "k8s/b.yml"]
    assert all(m["content_hash"] for m in payload["manifests"])


# --- deploy script ------------------------------------------------------------------------
async def test_deploy_script_binds_artifact_hash_and_head(repo) -> None:
    (repo / "deploy.sh").write_text("#!/bin/sh\necho deploy\n")
    payload = await GenericDeployScriptAction().derive(_ctx(repo, "./deploy.sh"))
    assert payload["script"] == "./deploy.sh"
    assert payload["script_hash"]
    assert payload["head_sha"] == _git(repo, "rev-parse", "HEAD")
    (repo / "deploy.sh").write_text("#!/bin/sh\necho changed\n")
    payload2 = await GenericDeployScriptAction().derive(_ctx(repo, "./deploy.sh"))
    assert payload2["script_hash"] != payload["script_hash"]


async def test_make_deploy_binds_makefile(repo) -> None:
    (repo / "Makefile").write_text("deploy:\n\techo hi\n")
    payload = await GenericDeployScriptAction().derive(_ctx(repo, "make deploy"))
    assert payload["script"] == "Makefile"
    assert payload["make_target"] == "deploy"
    assert payload["script_hash"]


# --- shared properties ---------------------------------------------------------------------
async def test_derivations_are_deterministic(repo) -> None:
    (repo / "deploy.sh").write_text("x\n")
    cases = [
        (GitResetHardAction(), "git reset --hard"),
        (RmRfAction(), "rm -rf nothing-here"),
        (KamalDeployAction(), "kamal deploy"),
        (GenericDeployScriptAction(), "./deploy.sh"),
    ]
    for action, command in cases:
        ctx = _ctx(repo, command)
        assert canonical_hash(await action.derive(ctx)) == \
            canonical_hash(await action.derive(ctx)), command


async def test_payloads_are_canonicalizable_no_floats_no_timestamps(repo) -> None:
    (repo / "deploy.sh").write_text("x\n")
    for action, command in [
        (GitResetHardAction(), "git reset --hard"),
        (RmRfAction(), "rm -rf x"),
        (KamalDeployAction(), "kamal deploy"),
        (GenericDeployScriptAction(), "make deploy"),
    ]:
        if action.action_type == "deploy_script" and "make" in command:
            (repo / "Makefile").write_text("deploy:\n\ttrue\n")
        payload = await action.derive(_ctx(repo, command))
        canonical_hash(payload)  # raises on floats/forbidden types
        dump = json.dumps(payload).lower()
        assert "derived_at" not in dump and "timestamp" not in dump
