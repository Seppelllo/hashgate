# Contributing / Development notes

## Setup

**Every terminal: activate/select the project environment first** (`uv run`
does this implicitly; with plain venvs, `source .venv/bin/activate`). The dev
environment is pinned to Python 3.12 via `.python-version`.

```bash
uv sync --no-editable --group dev                       # once (and after deps change)
uv run --no-editable --group dev python -m pytest -q    # full suite (no network)
uv run --no-editable --group dev ruff check src tests examples
bash scripts/verify_install.sh                          # fresh-venv install proof
```

`--no-editable` is deliberate (see the pitfall below). `[tool.uv].cache-keys`
covers `src/**/*.py`, so uv rebuilds the package automatically whenever a
source file changes — the dev loop stays "edit, run" (verified: an edited
`__version__` shows up on the next `uv run`).

For pip users: **`pip install '.[server]'` — NOT `pip install -e`.** Editable
installs are known-broken in the environments we tested (below).

## Known pitfall: editable installs silently broken (underscore `.pth` skip)

Observed reproducibly on macOS with CPython 3.12.12 and 3.14.3; likely
environment-dependent — Linux/other setups may be unaffected. There, the
`site` module does not process `.pth` files whose names start with an
underscore (a byte-identical copy under a non-underscore name IS processed).
PEP-660 editable installs write underscore-prefixed `.pth` files (hatchling:
`_editable_impl_<pkg>.pth` / `_<pkg>.pth`; setuptools: `__editable__.*.pth`),
so an editable-installed package silently fails to import
(`ModuleNotFoundError: No module named 'hashgate'`) — and console scripts
(`hashgate`, `hashgate-hook-wrapper`) die the same way, which is worse than a
broken test run. Built wheels / non-editable installs are unaffected — they
copy the package into `site-packages`.

Since the cause sits in the local Python's `site` behavior and hits every
editable backend alike, we do not fight it in the build backend. Decision:
**non-editable everywhere** (`uv … --no-editable` + cache-keys for the dev
loop; `pip install '.[server]'` for consumers), plus `tests/conftest.py`
putting `src/` on `sys.path` so the plain test suite never depends on install
mechanics at all. If imports break after toolchain changes, look at the
`.pth` files in `site-packages` first; this was debugged twice already.

## Supported Python versions

The package claims 3.11–3.13 (classifiers). The CI matrix over
3.11/3.12/3.13 exists (`.github/workflows/ci.yml`); its first verified run
happens on the first push to the public repository — until then the claim is
backed locally by the 3.12 pin only.

## TODO (tracked for the next milestone)

- [x] CI workflow: pytest + ruff matrix over Python 3.11/3.12/3.13
      (`.github/workflows/ci.yml` — verified on the first push to a public
      repo, deliberately not before)
- [x] Evidence exporter + audit-chain linkage
- [x] Worked end-to-end example (PR-merge gate) in `examples/`
- [x] Fill the `TODO-owner` placeholders in `pyproject.toml` `[project.urls]`
      (done — they point at the public repository)
- [x] First real consumer: Claude Code PreToolUse gate
      (`hashgate[server]` — server, operator CLI, fail-closed wrapper)

Roadmap candidates live in the README (Status & roadmap section); once the
repository is public, larger items move to GitHub issues.

## Releasing

1. Bump `version` in `pyproject.toml`, commit, push, wait for green CI.
2. Create and push a tag `vX.Y.Z` (or a GitHub release with that tag). The
   release workflow (`.github/workflows/release.yml`) re-runs the test
   matrix at the tag, guards that the tag matches the pyproject version,
   builds, and publishes to PyPI via Trusted Publishing (OIDC — no tokens
   in the repo).
3. PyPI uploads are immutable: a bad release gets yanked and replaced by a
   patch version, never overwritten.
4. One-time prerequisite (maintained manually on pypi.org, not in the
   repo): the Trusted Publisher must be registered — owner `Seppelllo`,
   repo `hashgate`, workflow `release.yml`, environment `pypi`.

## Design ground rules (do not weaken)

- No auto-accept, no scheduler in the core. hashgate gates; it never executes
  on its own initiative.
- Fail-closed: flags default off, policies default deny, a broken policy
  source is a deny.
- `apply()` never runs without a fresh policy check, a hash match against the
  operator-echoed `expected_hash`, validation, and an ATOMIC idempotency
  claim — in that order.
- The canonical format is versioned; changing it means a new canon version,
  never a silent edit (golden fixtures enforce this).
- Audit events carry IDs + hashes, never payload bodies or secrets.
- Tests run offline (in-memory SQLite, no network).
