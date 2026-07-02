# SPDX-License-Identifier: Apache-2.0
"""Legacy canonicalization codecs — FOR MIGRATION PURPOSES ONLY.

These codecs reproduce the two hash-serialization "families" found in the
production agent-runtime project hashgate was extracted from, so that a
migrating consumer can verify or re-compute hashes that were persisted under
the old conventions:

- ``legacy-a``: ``json.dumps(payload, sort_keys=True, ensure_ascii=False)`` —
  real UTF-8, but with Python's DEFAULT separators ``(", ", ": ")``
  (i.e. whitespace).
- ``legacy-b``: ``json.dumps(payload, sort_keys=True, separators=(",", ":"))``
  — compact, but with ``ensure_ascii=True`` (non-ASCII escaped as ``\\uXXXX``).

Neither codec has a version prefix, and — matching the legacy behaviour —
neither rejects floats or non-string keys. Do NOT use these for new payloads;
use :mod:`hashgate.canonical` (``hashgate-canon-v1``).

There is no guarantee that a given legacy hash is byte-reproducible for a
specific historical payload: legacy systems hashed hand-curated basis dicts,
and reproduction has to be decided per flow during migration.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from hashgate.errors import CanonicalizationError

LEGACY_CODEC_A = "legacy-a"
LEGACY_CODEC_B = "legacy-b"

LEGACY_CODECS: tuple[str, ...] = (LEGACY_CODEC_A, LEGACY_CODEC_B)


def legacy_canonical_bytes(payload: dict[str, Any], codec: str) -> bytes:
    """Serialize ``payload`` with a named legacy codec (no prefix, no
    strictness — matches the historical behaviour)."""
    if codec == LEGACY_CODEC_A:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    if codec == LEGACY_CODEC_B:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    raise CanonicalizationError(
        f"unknown legacy codec {codec!r} (known: {', '.join(LEGACY_CODECS)})"
    )


def legacy_hash(payload: dict[str, Any], codec: str) -> str:
    """SHA-256 hex digest of :func:`legacy_canonical_bytes`."""
    return hashlib.sha256(legacy_canonical_bytes(payload, codec)).hexdigest()
