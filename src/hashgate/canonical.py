# SPDX-License-Identifier: Apache-2.0
"""Canonical serialization + hashing — the root of every hashgate guarantee.

The normative specification lives in ``docs/SPEC_canonical.md``. Summary:

- JSON with ``sort_keys=True``, compact separators ``(",", ":")``,
  ``ensure_ascii=False`` (real UTF-8, no ``\\uXXXX`` escaping of non-ASCII),
- version prefix ``hashgate-canon-v1:`` in front of the JSON body,
- SHA-256 over the UTF-8 bytes of ``prefix + body``.

Allowed value types: ``dict`` (string keys only), ``list``, ``str``, ``int``,
``bool``, ``None``. Everything else — most importantly **floats** — raises
:class:`hashgate.errors.CanonicalizationError`. Floats are rejected because
their textual representation is not reliably deterministic across platforms,
languages and serializers; encode numeric fractions as strings (or
Decimal-as-string) instead.

A ``None`` value and an absent key are DIFFERENT payloads and hash
differently — that distinction is deliberate and load-bearing.

Any change to this format is a breaking change and MUST become a new,
explicitly versioned canon (``hashgate-canon-v2``), never a silent edit —
that is what the version prefix is for.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from hashgate.errors import CanonicalizationError

HASH_ALGO = "sha256"
CANONICAL_VERSION = "hashgate-canon-v1"


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize ``payload`` into its canonical byte form (prefix + JSON, UTF-8).

    Raises :class:`CanonicalizationError` if the payload is not a dict or
    contains a disallowed type anywhere in its tree.
    """
    if not isinstance(payload, dict):
        raise CanonicalizationError(
            f"top-level payload must be a dict, got {type(payload).__name__}"
        )
    _validate(payload, "$")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{CANONICAL_VERSION}:{body}".encode()


def canonical_hash(payload: dict[str, Any]) -> str:
    """SHA-256 hex digest of :func:`canonical_bytes`."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _validate(obj: Any, path: str) -> None:
    # NOTE: bool is a subclass of int in Python — the float check must come
    # first, and bool is explicitly allowed below.
    if isinstance(obj, float):
        raise CanonicalizationError(
            f"float at {path}: floats are not allowed in gated payloads "
            "(non-deterministic textual representation); use str or "
            "Decimal-as-str instead"
        )
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"non-string dict key at {path}: {key!r} ({type(key).__name__})"
                )
            _validate(value, f"{path}.{key}")
        return
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            _validate(item, f"{path}[{i}]")
        return
    if obj is None or isinstance(obj, str | bool | int):
        return
    raise CanonicalizationError(
        f"type {type(obj).__name__} at {path} is not allowed in gated payloads "
        "(allowed: dict, list, str, int, bool, None)"
    )
