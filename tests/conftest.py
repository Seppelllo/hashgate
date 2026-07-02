# SPDX-License-Identifier: Apache-2.0
"""Make the test suite independent of editable-install mechanics.

Rationale: on current CPython patch releases the `site` module skips
underscore-prefixed `.pth` files, which silently breaks hatchling editable
installs (see CONTRIBUTING.md). Real installs (built wheels) are unaffected;
for the dev loop we simply put `src/` on sys.path ourselves.
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
