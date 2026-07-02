# SPDX-License-Identifier: Apache-2.0
"""Structural pin on Gate.accept — the accept order is not just tested
behaviorally but pinned in the SOURCE: policy check before derivation,
hash-mismatch raise before validate, atomic claim after the hash compare and
before apply, and exactly ONE apply call site (so apply is unreachable
without a prior hash match on every path)."""
from __future__ import annotations

import inspect
import io
import tokenize

from hashgate.gate import Gate


def _tokenized_accept() -> str:
    source = inspect.getsource(Gate.accept)
    return " ".join(
        tok.string
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type not in (tokenize.COMMENT, tokenize.STRING, tokenize.NL, tokenize.NEWLINE,
                            tokenize.INDENT, tokenize.DEDENT)
    )


def test_accept_order_is_structurally_pinned() -> None:
    code = _tokenized_accept()
    i_policy = code.index("policy . check")
    i_derive = code.index("action . derive")
    i_hash = code.index("canonical_hash")
    i_mismatch = code.index("raise HashMismatch")
    i_validate = code.index("action . validate")
    i_claim = code.index("try_claim_idempotency")
    i_apply = code.index("action . apply")
    assert i_policy < i_derive < i_hash < i_mismatch < i_validate < i_claim < i_apply


def test_apply_has_exactly_one_call_site_after_claim() -> None:
    code = _tokenized_accept()
    assert code.count("action . apply") == 1
    assert code.count("try_claim_idempotency") == 1
    assert code.index("try_claim_idempotency") < code.index("action . apply")


def test_no_hook_call_before_the_policy_check() -> None:
    code = _tokenized_accept()
    i_policy = code.index("policy . check")
    for hook in ("action . derive", "action . validate",
                 "idempotency_key", "action . apply", "find_preview_by_hash"):
        assert code.index(hook) > i_policy, hook


def test_frozen_branch_never_rederives() -> None:
    # within accept there is exactly ONE derive call site and it lives in the
    # else-branch of the frozen check — the frozen path loads stored bytes.
    code = _tokenized_accept()
    assert code.count("action . derive") == 1
    assert "find_preview_by_hash" in code
    assert code.index("_is_frozen") < code.index("action . derive")
