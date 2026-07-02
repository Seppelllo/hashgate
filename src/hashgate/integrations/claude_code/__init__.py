# SPDX-License-Identifier: Apache-2.0
"""Claude Code PreToolUse gate — hashgate's first real external consumer.

A local gate server intercepts dangerous tool calls (v0.1: ``git push`` /
``git merge`` in Bash) via Claude Code's PreToolUse hook and lets them
through only against a hash-bound, single-use, expiring operator approval.
Every path — pending, approval, consume, refusal — leaves a verifiable
evidence chain.

Install with the ``server`` extra: ``pip install hashgate[server]``.
Setup: ``docs/claude_code_setup.md``.
"""
