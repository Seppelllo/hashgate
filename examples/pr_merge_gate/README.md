# PR-merge gate — the hashgate reference example

```bash
python examples/pr_merge_gate/pr_merge_gate.py
```

Fully offline (fake PR, fake merge API). Two scenarios:

**Scenario A — happy path.** The operator previews the merge payload (repo,
PR number, `head_sha`, diff stat), accepts by echoing its canonical hash, the
gate re-derives server-side, hashes match, the merge API is called SHA-pinned,
and an oversight bundle (`preview → applied`) is exported and verified.

**Scenario B — the one-paragraph pitch.** The operator previews and accepts —
but between preview and accept, the agent pushes another commit. Because
`head_sha` is part of the hashed payload, the server-side re-derivation now
produces a different hash: the accept **bursts automatically** with
`HashMismatch`. Nothing is merged. The refusal itself becomes an audited,
exportable, verifiable evidence bundle (`preview → hash_mismatch`, carrying
both hashes): *the agent tried, the gate prevented it, and you can prove it.*
A plain "Approve" button cannot give you that — the approval would have
applied to whatever the branch happens to point at by then.
