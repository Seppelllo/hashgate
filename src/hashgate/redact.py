# SPDX-License-Identifier: Apache-2.0
"""Allowlist-first redaction for audit material.

Blocklist-only redaction heuristics (mask keys containing "auth", mask any
long token-like string) systematically collide with legitimate audit
material: 64-hex SHA-256 hashes get eaten by long-token rules, a key like
``authoritative`` gets eaten by the ``auth`` substring, boolean capability
contracts (``credentials_allowed: false``) get masked into uselessness. The
source project worked around this at every call site ("re-set the hash AFTER
redact"); hashgate fixes it by DESIGN instead:

1. **Booleans, ints and None are never masked** — no secret is a bool/int/None,
   and masking them destroys contract information.
2. **Allowlisted keys are never masked** — hashes/ids are first-class audit
   citizens. By default every key ending in ``_hash``/``_sha``/``_digest``/
   ``_id``/``_ids`` (plus a few exact names) is allowlisted; consumers can
   declare more via ``allow_keys``.
3. Only then do the fail-closed heuristics run: sensitive-substring key
   masking and long-token string scrubbing.

Consequence (fail-closed by design): a hash stored under an UNDECLARED key
(``{"note": "<64 hex>"}``) is still masked — declare your keys.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MASK = "***"

#: keys that are never masked, regardless of value (suffix match, lowercase)
DEFAULT_ALLOW_KEY_RE = re.compile(r"(^|_)(hash|sha|digest|id|ids|key_name)$")

#: exact key names that are never masked
DEFAULT_ALLOW_KEYS = frozenset(
    {
        "payload_hash",
        "expected_hash",
        "derived_hash",
        "expected",
        "derived",
        "idempotency_key",
        "event_id",
        "chain_id",
        "prev_event_id",
        "apply_id",
        "preview_id",
        "action_type",
        "operator_id",
        "reason",
        "channel",
        "kind",
        "at",
    }
)

#: substring blocklist on keys (checked AFTER the allowlist)
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|passphrase|token|secret|api[_-]?key|bearer|"
    r"credential|private[_-]?key|auth)"
)

#: token-like runs: >=40 chars of [A-Za-z0-9_-] containing at least one digit
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{40,}")


def _looks_like_token(run: str) -> bool:
    return any(ch.isdigit() for ch in run)


@dataclass(frozen=True)
class Redactor:
    """Configurable allowlist-first redactor (see module docstring)."""

    allow_keys: frozenset[str] = field(default_factory=frozenset)
    mask: str = MASK

    def _key_allowed(self, key: str) -> bool:
        low = key.lower()
        return (
            key in self.allow_keys
            or low in DEFAULT_ALLOW_KEYS
            or DEFAULT_ALLOW_KEY_RE.search(low) is not None
        )

    def redact(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a redacted deep copy; the input is never mutated."""
        return {key: self._value(key, value) for key, value in payload.items()}

    def _value(self, key: str, value: Any) -> Any:
        if isinstance(value, dict | list | tuple):
            # a sensitive, undeclared key masks its WHOLE container (fail
            # closed — structure under "secrets"/"credentials" is not kept)
            if isinstance(key, str) and not self._key_allowed(key) \
                    and SENSITIVE_KEY_RE.search(key):
                return self.mask
            if isinstance(value, dict):
                return {k: self._value(k, v) for k, v in value.items()}
            return [self._value(key, item) for item in value]
        # rule 1: bools/ints/None are contract data, never secrets
        if value is None or isinstance(value, bool | int):
            return value
        # rule 2: allowlisted keys keep their value verbatim
        if isinstance(key, str) and self._key_allowed(key):
            return value
        # rule 3a: sensitive key substring -> mask the whole value
        if isinstance(key, str) and SENSITIVE_KEY_RE.search(key):
            return self.mask
        # rule 3b: long token-like runs inside remaining strings
        if isinstance(value, str):
            return _LONG_TOKEN_RE.sub(
                lambda m: self.mask if _looks_like_token(m.group(0)) else m.group(0),
                value,
            )
        return self.mask  # unknown scalar type: fail closed


def redact_payload(
    payload: dict[str, Any],
    *,
    allow_keys: frozenset[str] | set[str] = frozenset(),
    mask: str = MASK,
) -> dict[str, Any]:
    """Convenience wrapper around :class:`Redactor`."""
    return Redactor(allow_keys=frozenset(allow_keys), mask=mask).redact(payload)
