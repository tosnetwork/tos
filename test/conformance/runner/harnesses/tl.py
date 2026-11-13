# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""tl harness: TL wire-format verdicts on boxed bytes (schema/harness/tl-v1.schema.json)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "tl"
SCHEMAS = frozenset({"tos_api", "lite_api", "toslib_api"})
REASONS = frozenset(
    {"truncated", "trailing_data", "unknown_constructor", "oversize", "invalid_value"}
)
CONTEXT_REQUIRED = frozenset({"schema", "kind", "bytes"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "accepted": frozenset({"outcome", "constructor", "bytes"}),
    "rejected": frozenset({"outcome", "reason"}),
}


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    if ctx["schema"] not in SCHEMAS:
        raise t.FixtureError(f"{where}.schema: unknown {ctx['schema']!r}")
    if ctx["kind"] not in ("object", "function"):
        raise t.FixtureError(f"{where}.kind: object or function")
    if ctx["schema"] == "toslib_api" and ctx["kind"] != "object":
        raise t.FixtureError(f"{where}.kind: toslib_api has only wire objects")
    t.text(ctx["bytes"], t.HEX_RE, f"{where}.bytes")
    if len(ctx["bytes"]) > 2 << 20:
        raise t.FixtureError(f"{where}.bytes: more than 1 MiB")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    outcome = t.outcome_shape(eff, EFFECT_SHAPES, where)
    if outcome == "accepted":
        t.integer(eff["constructor"], f"{where}.constructor", -(1 << 31), (1 << 31) - 1)
        t.text(eff["bytes"], t.HEX_RE, f"{where}.bytes")
    elif eff["reason"] not in REASONS:
        raise t.FixtureError(f"{where}.reason: unknown {eff['reason']!r}")
