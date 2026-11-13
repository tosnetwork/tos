# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""txn harness: one transaction (schema/harness/txn-v1.schema.json)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "txn"
CONTEXT_REQUIRED = frozenset({"config", "shard_account", "now", "lt", "rand_seed"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED | {"message", "tick_tock", "libraries", "prev_blocks"}
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "accepted": frozenset({"outcome", "transaction_hash", "account_hash", "shard_account_hash"}),
    "rejected": frozenset({"outcome", "vm_exit_code"}),
    "error": frozenset({"outcome"}),
}


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    for key in ("config", "shard_account", "message", "libraries", "prev_blocks"):
        if key in ctx:
            t.boc(ctx[key], f"{where}.{key}")
    if ("message" in ctx) == ("tick_tock" in ctx):
        raise t.FixtureError(f"{where}: exactly one of message and tick_tock")
    if "tick_tock" in ctx and ctx["tick_tock"] not in ("tick", "tock"):
        raise t.FixtureError(f"{where}.tick_tock: tick or tock")
    t.integer(ctx["now"], f"{where}.now", 1, 0xFFFFFFFF)
    t.integer(ctx["lt"], f"{where}.lt", 1)
    t.text(ctx["rand_seed"], t.SEED_RE, f"{where}.rand_seed")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    t.outcome_shape(eff, EFFECT_SHAPES, where)
    for key in ("transaction_hash", "account_hash", "shard_account_hash"):
        if key in eff:
            t.cell_hash(eff[key], f"{where}.{key}")
    if "vm_exit_code" in eff:
        t.integer(eff["vm_exit_code"], f"{where}.vm_exit_code")
