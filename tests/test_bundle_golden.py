# SPDX-License-Identifier: Apache-2.0
"""Golden oversight bundles — committed once, self-consistent forever.

These fixtures are real exporter output (a happy chain and a refusal chain).
They pin (a) that verify_bundle accepts historically exported bundles and
(b) that any change to the bundle format shows up as a conscious fixture
regeneration in review, never as a silent drift."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashgate.canonical import canonical_hash
from hashgate.evidence import BUNDLE_FORMAT, verify_bundle

_FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name,outcome,kinds", [
    ("bundle_happy.json", "applied", ["preview", "applied"]),
    ("bundle_refusal.json", "hash_mismatch", ["preview", "hash_mismatch"]),
])
def test_golden_bundle_verifies(name: str, outcome: str, kinds: list[str]) -> None:
    bundle = _load(name)
    assert bundle["bundle_format"] == BUNDLE_FORMAT
    assert bundle["outcome"] == outcome
    assert [e["kind"] for e in bundle["events"]] == kinds
    verdict = verify_bundle(bundle)
    assert verdict.valid, verdict.problems


def test_golden_refusal_carries_both_hashes_and_no_payload_body() -> None:
    bundle = _load("bundle_refusal.json")
    mismatch = bundle["events"][1]
    assert mismatch["expected_hash"] != mismatch["derived_hash"]
    assert len(mismatch["expected_hash"]) == 64
    # payload bodies never appear in evidence
    assert "acme/api" not in json.dumps(bundle)


def test_golden_seal_self_exclusion() -> None:
    for name in ("bundle_happy.json", "bundle_refusal.json"):
        bundle = _load(name)
        body = {k: v for k, v in bundle.items() if k not in ("bundle_hash", "signature")}
        assert canonical_hash(body) == bundle["bundle_hash"], name


def test_golden_tamper_detection() -> None:
    bundle = _load("bundle_happy.json")
    bundle["events"][1]["reason"] = "totally legitimate"
    assert not verify_bundle(bundle).valid
