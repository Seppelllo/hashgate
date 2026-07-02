# SPDX-License-Identifier: Apache-2.0
"""Golden regression anchors for hashgate-canon-v1.

If any of these hashes ever changes, that is a BREAKING format change and must
become a new canon version (hashgate-canon-v2) — the fixture is never updated
to match a changed implementation. See docs/SPEC_canonical.md §change policy.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashgate.canonical import canonical_hash

_FIXTURE = Path(__file__).parent / "fixtures" / "canonical_golden.json"
_CASES = json.loads(_FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _CASES, ids=[c["name"] for c in _CASES])
def test_golden_hash(case: dict) -> None:
    assert canonical_hash(case["payload"]) == case["expected_hash"], case["name"]


def test_golden_corpus_is_meaningful() -> None:
    assert len(_CASES) >= 10
    assert len({c["expected_hash"] for c in _CASES}) == len(_CASES)  # all distinct
