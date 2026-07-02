# SPDX-License-Identifier: Apache-2.0
"""Allowlist-first redaction — the documented blocklist-collision cases from
the source project are rebuilt here and must pass WITHOUT any
"re-set-after-redact" workaround."""
from __future__ import annotations

from hashgate.redact import MASK, Redactor, redact_payload

_HEX64 = "9f" * 32  # 64-hex sha256-shaped value (contains digits, len 64)


# --- the historical collision cases, solved by design ------------------------
def test_collision_1_hashes_survive_the_long_token_rule() -> None:
    # historically: a >=40-char token rule ate 64-hex hashes; call sites had
    # to re-set output_hash/prompt_hash AFTER redact.
    out = redact_payload({"output_hash": _HEX64, "prompt_hash": _HEX64})
    assert out == {"output_hash": _HEX64, "prompt_hash": _HEX64}


def test_collision_2_authoritative_survives_the_auth_substring() -> None:
    # historically: key "authoritative" matched the "auth" substring blocklist
    # and had to be set AFTER redact.
    out = redact_payload({"authoritative": True})
    assert out == {"authoritative": True}


def test_collision_3_capability_contract_booleans_survive() -> None:
    # historically: keys containing credential/token/nats masked boolean
    # capability contracts into "***".
    payload = {
        "credentials_allowed": False,
        "provider_tokens_allowed": False,
        "nats_allowed": False,
        "max_steps": 0,
    }
    assert redact_payload(payload) == payload


def test_collision_4_counter_keys_survive() -> None:
    # historically: a forbidden-marker scan collided with a legitimate counter
    # key; here counters are ints and therefore never maskable.
    assert redact_payload({"worker_jobs": 3}) == {"worker_jobs": 3}


# --- masking still works where it must ----------------------------------------
def test_sensitive_keys_are_masked() -> None:
    out = redact_payload({
        "api_key": "abc123",
        "authorization": "Bearer xyz1",
        "password": "hunter2",
        "gitlab_token": "glpat-123",
    })
    assert set(out.values()) == {MASK}


def test_sensitive_key_with_hash_value_is_still_masked() -> None:
    # a 64-hex value under a blocklisted, non-allowlisted key stays masked
    assert redact_payload({"session_token": _HEX64}) == {"session_token": MASK}


def test_long_tokens_inside_free_strings_are_scrubbed() -> None:
    token = "A1" * 25  # 50 chars, has digits
    out = redact_payload({"note": f"leaked {token} in log"})
    assert out == {"note": f"leaked {MASK} in log"}


def test_hash_under_undeclared_key_is_masked_fail_closed() -> None:
    # fail-closed by design: declare your keys or lose the value
    assert redact_payload({"note": _HEX64}) == {"note": MASK}


def test_long_alpha_only_runs_are_not_tokens() -> None:
    words = "a" * 45  # no digit -> not token-like
    assert redact_payload({"note": words}) == {"note": words}


# --- allowlist precedence and recursion ----------------------------------------
def test_explicit_allow_keys_beat_the_blocklist() -> None:
    out = redact_payload({"token_fingerprint": _HEX64},
                         allow_keys={"token_fingerprint"})
    assert out == {"token_fingerprint": _HEX64}


def test_default_allow_suffixes_cover_ids_and_hashes() -> None:
    payload = {"spec_hash": _HEX64, "artifact_ids": [1, 2], "run_id": "r-1" * 20}
    assert redact_payload(payload) == payload


def test_recursion_into_nested_containers() -> None:
    out = redact_payload({
        "steps": [{"api_key": "k1", "output_hash": _HEX64, "ok": True}],
        "meta": {"secrets": {"a": "b"}, "count": 2},
    })
    assert out["steps"][0] == {"api_key": MASK, "output_hash": _HEX64, "ok": True}
    # a sensitive key masks its WHOLE container, fail closed
    assert out["meta"]["secrets"] == MASK
    assert out["meta"]["count"] == 2


def test_input_is_never_mutated() -> None:
    payload = {"api_key": "k", "nested": {"password": "p"}}
    Redactor().redact(payload)
    assert payload == {"api_key": "k", "nested": {"password": "p"}}


def test_unknown_scalar_types_fail_closed() -> None:
    class Weird:
        pass

    assert redact_payload({"thing": Weird()}) == {"thing": MASK}
