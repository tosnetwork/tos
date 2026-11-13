# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""block harness: one block applied to its previous state (schema/harness/block-v1.schema.json)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "block"
CONTEXT_REQUIRED = frozenset({"block", "prev_state"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED | {"master_block", "master_state"}
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "accepted": frozenset({"outcome", "block_root_hash", "new_state_hash", "transactions"}),
    "rejected": frozenset({"outcome", "reason"}),
}
REASONS = frozenset(
    {
        "malformed_block",
        "split_merge_unsupported",
        "state_update_invalid",
        "prev_state_mismatch",
        "state_update_not_applicable",
        "state_update_mismatch",
        "prev_state_malformed",
        "master_context_mismatch",
        "config_unavailable",
        "account_unavailable",
        "transaction_context_mismatch",
        "execution_refused",
        "transaction_mismatch",
        "account_hash_mismatch",
        "new_state_mismatch",
        "pruned_state",
    }
)
MAX_TRANSACTIONS = 4096


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    for key in CONTEXT_ALLOWED:
        if key in ctx:
            t.boc(ctx[key], f"{where}.{key}")
    if ("master_block" in ctx) != ("master_state" in ctx):
        raise t.FixtureError(f"{where}: master_block and master_state go together")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    if t.outcome_shape(eff, EFFECT_SHAPES, where) == "rejected":
        if eff["reason"] not in REASONS:
            raise t.FixtureError(f"{where}.reason: unknown {eff['reason']!r}")
        return
    t.cell_hash(eff["block_root_hash"], f"{where}.block_root_hash")
    t.cell_hash(eff["new_state_hash"], f"{where}.new_state_hash")
    for i, item in enumerate(
        t.array(eff["transactions"], f"{where}.transactions", MAX_TRANSACTIONS)
    ):
        entry = t.obj(item, f"{where}.transactions[{i}]")
        t.keys(
            entry, {"transaction_hash", "account_hash"}, {"transaction_hash", "account_hash"}, where
        )
        t.cell_hash(entry["transaction_hash"], f"{where}.transactions[{i}].transaction_hash")
        t.cell_hash(entry["account_hash"], f"{where}.transactions[{i}].account_hash")
