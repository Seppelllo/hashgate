# SPDX-License-Identifier: Apache-2.0
"""Core types — operator context validation pins."""
from __future__ import annotations

import pytest

from hashgate.errors import ValidationFailed
from hashgate.types import MAX_OPERATOR_ID_LEN, MAX_REASON_LEN, OperatorContext


@pytest.mark.parametrize(
    ("operator_id", "reason"),
    [("", "r"), ("op", ""), ("  ", "r"), ("op", "   "), (None, "r"), ("op", None)],
)
def test_operator_and_reason_required(operator_id, reason) -> None:
    with pytest.raises(ValidationFailed) as exc:
        OperatorContext(operator_id=operator_id, reason=reason)  # type: ignore[arg-type]
    assert exc.value.code == "operator_id_and_reason_required"
    assert exc.value.http_status == 400


def test_clipping_and_defaults() -> None:
    op = OperatorContext(operator_id="x" * 500, reason="y" * 5000, channel="")
    assert len(op.operator_id) == MAX_OPERATOR_ID_LEN
    assert len(op.reason) == MAX_REASON_LEN
    assert op.channel == "api"


def test_channel_recorded() -> None:
    op = OperatorContext(operator_id="op", reason="r", channel="cockpit-ui")
    assert op.channel == "cockpit-ui"
