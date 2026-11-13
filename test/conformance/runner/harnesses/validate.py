# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""validate harness: the node's ValidateQuery of one candidate (schema/harness/validate-v1.schema.json)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "validate"
CONTEXT_REQUIRED = frozenset(
    {
        "block_id",
        "block",
        "created_by",
        "prev",
        "min_masterchain",
        "top_masterchain",
        "validator_set_from",
        "states",
    }
)
CONTEXT_ALLOWED = CONTEXT_REQUIRED | {"collated_data", "skip_shard_signatures"}
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "accepted": frozenset({"outcome", "ok_from_utime_ms"}),
    "rejected": frozenset({"outcome", "reason"}),
    "error": frozenset({"outcome", "reason"}),
}
# The fixed classes of ref/validate-offline.cpp (classify); "unclassified" is any other message.
REASONS = frozenset(
    {
        "input_unavailable",
        "candidate_id_mismatch",
        "shard_mismatch",
        "prev_block_mismatch",
        "creator_mismatch",
        "validator_set_mismatch",
        "prev_state_mismatch",
        "new_state_mismatch",
        "limit_exceeded",
        "utime_lt_invalid",
        "value_flow_invalid",
        "account_update_invalid",
        "transaction_invalid",
        "message_invalid",
        "pruned_input",
        "unclassified",
    }
)
SHARD_RE = re.compile(r"^[0-9a-f]{16}$")
MAX_STATES = 32
U32 = 0xFFFFFFFF
U63 = (1 << 63) - 1


def block_id(value: object, where: str) -> None:
    keys = {"workchain", "shard", "seqno", "root_hash", "file_hash"}
    item = t.obj(value, where)
    t.keys(item, keys, keys, where)
    t.integer(item["workchain"], f"{where}.workchain", -(1 << 31), (1 << 31) - 1)
    t.text(item["shard"], SHARD_RE, f"{where}.shard")
    t.integer(item["seqno"], f"{where}.seqno", 0, U32)
    t.cell_hash(item["root_hash"], f"{where}.root_hash")
    t.cell_hash(item["file_hash"], f"{where}.file_hash")


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    for key in ("block_id", "min_masterchain", "top_masterchain", "validator_set_from"):
        block_id(ctx[key], f"{where}.{key}")
    t.boc(ctx["block"], f"{where}.block")
    if "collated_data" in ctx:
        t.boc(ctx["collated_data"], f"{where}.collated_data")
    t.cell_hash(ctx["created_by"], f"{where}.created_by")
    prev = t.array(ctx["prev"], f"{where}.prev", 2)
    if not prev:
        raise t.FixtureError(f"{where}.prev: one or two block ids required")
    for i, item in enumerate(prev):
        block_id(item, f"{where}.prev[{i}]")
    if "skip_shard_signatures" in ctx:
        t.boolean(ctx["skip_shard_signatures"], f"{where}.skip_shard_signatures")
    for i, raw in enumerate(t.array(ctx["states"], f"{where}.states", MAX_STATES)):
        at = f"{where}.states[{i}]"
        item = t.obj(raw, at)
        t.keys(item, {"block", "state"}, {"block", "state"}, at)
        block_id(item["block"], f"{at}.block")
        t.boc(item["state"], f"{at}.state")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    if t.outcome_shape(eff, EFFECT_SHAPES, where) == "accepted":
        t.integer(eff["ok_from_utime_ms"], f"{where}.ok_from_utime_ms", 0, U63)
        return
    if eff["reason"] not in REASONS:
        raise t.FixtureError(f"{where}.reason: unknown {eff['reason']!r}")
