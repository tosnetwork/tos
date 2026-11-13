# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""get_method harness: one liteserver get-method run (schema/harness/get_method-v1.schema.json)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "get_method"
CONTEXT_REQUIRED = frozenset(
    {
        "mc_state",
        "mc_block",
        "account",
        "now",
        "lt",
        "rand_seed",
        "method_id",
        "stack",
        "gas_limit",
    }
)
CONTEXT_ALLOWED = CONTEXT_REQUIRED
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "executed": frozenset({"outcome", "exit_code", "gas_used", "stack", "missing_library"}),
    "no_state": frozenset({"outcome"}),
    "context_unavailable": frozenset({"outcome"}),
}
METHOD_ID_RE = re.compile(r"^(0|-?[1-9][0-9]{0,18})$")
BLOCK_ID_KEYS = {"seqno", "root_hash", "file_hash"}


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    t.boc(ctx["mc_state"], f"{where}.mc_state")
    t.boc(ctx["account"], f"{where}.account")
    block_id = t.obj(ctx["mc_block"], f"{where}.mc_block")
    t.keys(block_id, BLOCK_ID_KEYS, BLOCK_ID_KEYS, f"{where}.mc_block")
    t.integer(block_id["seqno"], f"{where}.mc_block.seqno", 0, 0xFFFFFFFF)
    t.cell_hash(block_id["root_hash"], f"{where}.mc_block.root_hash")
    t.cell_hash(block_id["file_hash"], f"{where}.mc_block.file_hash")
    t.integer(ctx["now"], f"{where}.now", 0, 0xFFFFFFFF)
    t.integer(ctx["lt"], f"{where}.lt", 0, 2**63 - 1)
    t.text(ctx["rand_seed"], t.SEED_RE, f"{where}.rand_seed")
    method_id = t.text(ctx["method_id"], METHOD_ID_RE, f"{where}.method_id")
    if not -(2**63) <= int(method_id) < 2**63:
        raise t.FixtureError(f"{where}.method_id: not a signed 64-bit integer")
    for i, item in enumerate(t.array(ctx["stack"], f"{where}.stack", 255)):
        t.stack_item(item, f"{where}.stack[{i}]")
    t.integer(ctx["gas_limit"], f"{where}.gas_limit", 0, 2**63 - 1)


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    if t.outcome_shape(eff, EFFECT_SHAPES, where) != "executed":
        return
    t.integer(eff["exit_code"], f"{where}.exit_code")
    t.integer(eff["gas_used"], f"{where}.gas_used")
    t.string_list(eff["stack"], f"{where}.stack")
    t.optional_hash(eff["missing_library"], f"{where}.missing_library")
