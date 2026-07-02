# SPDX-License-Identifier: Apache-2.0
"""canonical serialization — property-style pins for docs/SPEC_canonical.md."""
from __future__ import annotations

import hashlib
import random

import pytest

from hashgate.canonical import CANONICAL_VERSION, canonical_bytes, canonical_hash
from hashgate.errors import CanonicalizationError


def test_stability_independent_of_insertion_order() -> None:
    items = [("alpha", 1), ("beta", "x"), ("gamma", None), ("delta", [1, 2]),
             ("epsilon", {"n": True}), ("zeta", "Prüfung")]
    reference = canonical_hash(dict(items))
    rng = random.Random(42)
    for _ in range(25):
        shuffled = items[:]
        rng.shuffle(shuffled)
        assert canonical_hash(dict(shuffled)) == reference


def test_repeated_calls_are_deterministic() -> None:
    payload = {"a": [1, {"b": None}], "c": "täxt"}
    assert canonical_hash(payload) == canonical_hash(payload)
    assert canonical_bytes(payload) == canonical_bytes(payload)


def test_unicode_is_utf8_not_ascii_escaped() -> None:
    body = canonical_bytes({"s": "Prüfung 🚀 監視"})
    assert "Prüfung 🚀 監視".encode() in body
    assert b"\\u" not in body  # the core motivation against legacy family B


def test_compact_separators_no_whitespace() -> None:
    body = canonical_bytes({"a": 1, "b": [1, 2]}).decode()
    assert '{"a":1,"b":[1,2]}' in body
    assert ", " not in body and ": " not in body


def test_version_prefix_is_part_of_hashed_bytes() -> None:
    payload = {"a": 1}
    body = canonical_bytes(payload)
    assert body.startswith(f"{CANONICAL_VERSION}:".encode())
    # a hypothetical v2 prefix over the SAME json body never collides with v1
    json_part = body.decode().split(":", 1)[1]
    fake_v2 = hashlib.sha256(f"hashgate-canon-v2:{json_part}".encode()).hexdigest()
    assert fake_v2 != canonical_hash(payload)


def test_deep_nesting_roundtrip_stable() -> None:
    payload: dict = {"level": 0}
    node = payload
    for i in range(1, 60):
        node["child"] = {"level": i, "items": [str(i), i, None, i % 2 == 0]}
        node = node["child"]
    assert canonical_hash(payload) == canonical_hash(payload)


def test_none_value_differs_from_absent_key() -> None:
    assert canonical_hash({"a": None}) != canonical_hash({})
    assert canonical_hash({"a": None, "b": 1}) != canonical_hash({"b": 1})


def test_list_order_is_significant() -> None:
    assert canonical_hash({"x": [1, 2]}) != canonical_hash({"x": [2, 1]})


def test_key_sorting_is_codepoint_order() -> None:
    # "10" < "2" in code-point order — pinned so nobody "fixes" it to natural order
    body = canonical_bytes({"2": "b", "10": "a"}).decode()
    assert body.index('"10"') < body.index('"2"')


@pytest.mark.parametrize(
    "payload",
    [
        {"x": 1.5},
        {"x": 0.0},
        {"deep": {"list": [1, [2, [3.14]]]}},
        {"a": [{"b": {"c": 1e10}}]},
    ],
)
def test_floats_rejected_anywhere(payload: dict) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_hash(payload)


def test_float_error_reports_path() -> None:
    with pytest.raises(CanonicalizationError) as exc:
        canonical_hash({"a": [{"b": 1.5}]})
    assert "$.a[0].b" in str(exc.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"x": (1, 2)},          # tuple
        {"x": {1: "a"}},        # non-string key
        {"x": b"bytes"},        # bytes
        {"x": {"a", "b"}},      # set
    ],
)
def test_disallowed_types_rejected(payload: dict) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_hash(payload)


@pytest.mark.parametrize("payload", [[1, 2], "s", 1, None, True])
def test_top_level_must_be_dict(payload) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_hash(payload)  # type: ignore[arg-type]


def test_bools_and_ints_allowed_and_distinct() -> None:
    # bool is an int subclass in Python; JSON distinguishes true from 1
    assert canonical_hash({"x": True}) != canonical_hash({"x": 1})
    canonical_hash({"zero": 0, "neg": -1, "big": 2**80, "t": True})  # no raise


def test_hash_is_lowercase_hex_sha256() -> None:
    h = canonical_hash({})
    assert len(h) == 64 and h == h.lower()
    assert h == hashlib.sha256(canonical_bytes({})).hexdigest()
