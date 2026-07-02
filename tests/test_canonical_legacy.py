# SPDX-License-Identifier: Apache-2.0
"""Legacy codecs (legacy-a / legacy-b) — migration-only reproductions."""
from __future__ import annotations

import pytest

from hashgate.canonical import canonical_hash
from hashgate.canonical_legacy import (
    LEGACY_CODEC_A,
    LEGACY_CODEC_B,
    legacy_canonical_bytes,
    legacy_hash,
)
from hashgate.errors import CanonicalizationError

_PAYLOAD = {"title": "Prüfung", "n": 1}


def test_families_and_v1_all_differ_on_unicode_payload() -> None:
    hashes = {
        canonical_hash(_PAYLOAD),
        legacy_hash(_PAYLOAD, LEGACY_CODEC_A),
        legacy_hash(_PAYLOAD, LEGACY_CODEC_B),
    }
    assert len(hashes) == 3


def test_legacy_a_has_whitespace_and_real_utf8() -> None:
    body = legacy_canonical_bytes(_PAYLOAD, LEGACY_CODEC_A)
    assert b'", "' in body or b'": ' in body  # default separators
    assert "Prüfung".encode() in body
    assert not body.startswith(b"hashgate-canon")  # no prefix


def test_legacy_b_is_compact_but_ascii_escaped() -> None:
    body = legacy_canonical_bytes(_PAYLOAD, LEGACY_CODEC_B)
    assert b'":' in body and b'": ' not in body  # compact
    assert b"\\u00fc" in body  # ü escaped — the family-B divergence
    assert not body.startswith(b"hashgate-canon")


def test_legacy_permits_floats_matching_historical_behaviour() -> None:
    # documented non-strictness: the legacy systems never rejected floats
    legacy_hash({"x": 1.5}, LEGACY_CODEC_A)
    legacy_hash({"x": 1.5}, LEGACY_CODEC_B)


def test_unknown_codec_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        legacy_hash(_PAYLOAD, "legacy-c")


def test_known_values_pinned() -> None:
    # regression anchors for the reproduced families (see SPEC §7)
    assert legacy_hash(_PAYLOAD, LEGACY_CODEC_A) == (
        "79e9221ac737776ab6a2bc194f643ca1c239c9944eff067ecc7b1c344c310e91"
    )
    assert legacy_hash(_PAYLOAD, LEGACY_CODEC_B) == (
        "b42a238ff806de8a3ef7f85eff74743f5a9833f8c18395426893361652e2ac8b"
    )
