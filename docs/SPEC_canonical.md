# hashgate canonical serialization — `hashgate-canon-v1`

**Status:** Normative. This document defines the byte-exact serialization that
every hashgate hash is computed over. The implementation in
`src/hashgate/canonical.py` follows this document; where they disagree, this
document wins and the implementation is buggy.

**Change policy:** Any change to this format — however small — changes hash
values and is therefore a **breaking change**. It MUST be released as a new,
explicitly versioned canon (`hashgate-canon-v2`, …) with its own prefix.
A silent edit of `v1` is forbidden. The golden fixtures in
`tests/fixtures/canonical_golden.json` pin this: if a fixture hash ever
changes, the change is rejected, not the fixture.

---

## 1. Definition

For a payload `P` (a JSON-compatible dict, see §2):

```
body   = JSON(P)  with  sort_keys=True,
                        separators=(",", ":"),      # no whitespace
                        ensure_ascii=False          # real UTF-8, no \uXXXX for non-ASCII
bytes  = UTF-8( "hashgate-canon-v1:" + body )
hash   = SHA-256(bytes), lowercase hex digest (64 chars)
```

Reference (Python): `json.dumps(P, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

### Worked example

```
payload : {"title": "Prüfung", "n": 1}
bytes   : hashgate-canon-v1:{"n":1,"title":"Prüfung"}
sha256  : 3fbd6966064f6bee133b1fcbd52c44abeb64690c03acd05f7e1bbad3d74a9cbe
```

The empty payload `{}` hashes to
`2b3bcd05388b807ed3a424b147bb808761c9e71cecbe109f8f7d38dd1fd1d3cc`.

## 2. Allowed types

The top level MUST be a `dict`. Anywhere in the tree, exactly these types are
allowed:

| Type | Notes |
|---|---|
| `dict` | keys MUST be `str` (non-string keys → `CanonicalizationError`) |
| `list` | order is significant (`[1,2]` ≠ `[2,1]`) |
| `str` | arbitrary Unicode |
| `int` | arbitrary precision (see §5 interop note) |
| `bool` | `true`/`false` |
| `None` | serialized as `null` |

Everything else is rejected with `CanonicalizationError` — including `float`,
`tuple`, `set`, `bytes`, `datetime`, `Decimal` and arbitrary objects. There is
no `default=` escape hatch: implicit coercion is exactly the ambiguity this
spec exists to prevent.

## 3. Floats are forbidden — rationale

The textual representation of binary floating-point values is not reliably
deterministic across platforms, languages and serializers (shortest-round-trip
vs. fixed-precision formatting, `1e21` vs. `1000000000000000000000`, signed
zero, NaN/Infinity, locale-adjacent formatting bugs). A single differing byte
produces a different hash and a spurious `HashMismatch` — or worse, two
*different* values that print identically. Encode fractional numbers as
strings (e.g. `"1.25"`, ideally Decimal-derived) and treat them as opaque
tokens for hashing purposes.

## 4. `None` vs. absent key

`{"a": null}` and `{}` are **different payloads** and hash differently.
Action authors must decide per field whether "not set" is expressed as an
absent key or an explicit `null`, and then do so consistently — the derivation
(`derive()`) must be deterministic in this choice.

## 5. Determinism details

- **Key ordering:** lexicographic by Unicode code point of the key string
  (Python's default `str` ordering under `sort_keys=True`). Note that this is
  code-point order, not natural/numeric order: `"10" < "2"`.
- **String escaping:** JSON mandates escaping of `"`, `\` and control
  characters (< U+0020); with `ensure_ascii=False` all other characters are
  emitted as raw UTF-8. This is deterministic in CPython's `json` module.
  Non-canonical alternate escapes never occur because hashgate always
  *produces* the serialization itself (payloads are Python objects in,
  bytes out — hashgate never re-hashes third-party JSON text).
- **Unicode normalization is NOT applied.** `"ü"` (U+00FC) and `"ü"`
  (u + combining diaeresis) are different strings and hash differently.
  Derivations that ingest user text SHOULD normalize (e.g. NFC) *before*
  building the payload if visually-identical inputs must coincide.
- **Integer interop note:** Python ints are arbitrary precision. Integers with
  magnitude above 2^53 may lose precision in consumers that parse JSON into
  IEEE-754 doubles (JavaScript). They hash fine; the interop caveat is the
  action author's to manage (use strings for such ids if consumers are mixed).
- **Version prefix:** the `hashgate-canon-v1:` prefix is part of the hashed
  bytes. A future `v2` therefore never collides with `v1` for any payload.

## 6. Rules for action authors (informative, but load-bearing)

1. **No timestamps in hash bases.** "Derived at", "expires at" etc. belong on
   the `Preview` object / audit trail, never inside the hashed payload —
   otherwise every re-derivation mismatches by construction. (Convention
   inherited from the source system, where every hash basis excludes
   timestamps explicitly.)
2. **No floats** (§3). Pre-round and stringify if you must carry fractions.
3. **No secrets, no full documents.** The payload is what the operator reviews
   and what appears (as a hash) in audit events; keep it a compact, curated
   basis: IDs, shas, titles, counts, decisions. Hash large content separately
   (content-address it) and put the *content hash* into the payload — the
   PR-merge example pins `head_sha` instead of the diff itself.
4. **Sort any set-like list** (`sorted(reason_codes)`) inside `derive()`;
   only genuinely ordered lists may rely on order.
5. **Self-exclusion:** a payload must never contain its own hash or fields
   derived from it.

## 7. Legacy codecs (migration only)

`hashgate.canonical_legacy` ships two named codecs that reproduce the
serialization families of the system hashgate was extracted from — for
verifying/migrating persisted legacy hashes, never for new payloads:

| Codec | `json.dumps` args | Divergence from v1 |
|---|---|---|
| `legacy-a` | `sort_keys=True, ensure_ascii=False` | default separators → whitespace; no prefix; no strictness |
| `legacy-b` | `sort_keys=True, separators=(",", ":")` | `ensure_ascii=True` → `\uXXXX` escapes; no prefix; no strictness |

For `{"title": "Prüfung", "n": 1}`:

```
hashgate-canon-v1: 3fbd6966064f6bee133b1fcbd52c44abeb64690c03acd05f7e1bbad3d74a9cbe
legacy-a:          79e9221ac737776ab6a2bc194f643ca1c239c9944eff067ecc7b1c344c310e91
legacy-b:          b42a238ff806de8a3ef7f85eff74743f5a9833f8c18395426893361652e2ac8b
```

All three differ — which is exactly why the version prefix exists.
