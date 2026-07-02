# Contributing / Development notes

## Setup

```bash
uv run --group dev python -m pytest -q     # full test suite (no network needed)
uv run --group dev ruff check src tests
```

The dev environment is pinned to Python 3.12 via `.python-version`.

## Known pitfall: editable installs silently broken (underscore `.pth` skip)

Observed reproducibly on CPython 3.12.12 and 3.14.3 in this environment: the
`site` module does not process `.pth` files whose names start with an
underscore (a byte-identical copy under a non-underscore name IS processed;
uv's `_virtualenv.pth` is skipped the same way, without visible harm).
Hatchling's editable installs write underscore-prefixed `.pth` files
(`_editable_impl_<pkg>.pth`, or `_<pkg>.pth` with `dev-mode-dirs`), so the
editable-installed package can silently fail to import
(`ModuleNotFoundError: No module named 'hashgate'`) even though the install
"succeeded". Built wheels (real installs) are unaffected — they copy the
package into `site-packages`.

Consequence for this repo: **the test suite does not depend on the editable
install at all** — `tests/conftest.py` puts `src/` on `sys.path` directly.
If imports break after toolchain changes, look at the `.pth` files in
`site-packages` first; this was debugged twice already.

## Supported Python versions

The package claims 3.11–3.13 (classifiers). TODO before the first release:
CI matrix across 3.11 / 3.12 / 3.13 so the claim is backed by green runs,
not just the local 3.12 pin.

## TODO (tracked for the next milestone)

- [x] CI workflow: pytest + ruff matrix over Python 3.11/3.12/3.13
      (`.github/workflows/ci.yml` — verified on the first push to a public
      repo, deliberately not before)
- [x] Evidence exporter + audit-chain linkage
- [x] Worked end-to-end example (PR-merge gate) in `examples/`
- [ ] Fill the `TODO-owner` placeholders in `pyproject.toml` `[project.urls]`
      when the public repository exists
- [x] First real consumer: Claude Code PreToolUse gate
      (`hashgate[server]` — server, operator CLI, fail-closed wrapper)
- [ ] Roadmap candidates (post-0.1): sync wrapper, real signature
      implementations, FastAPI request-level middleware, further agent-tool
      integrations, retention/export tooling

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
