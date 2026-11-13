# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""vm harness: one program on vm::VmState (schema/harness/vm-v1.schema.json)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "vm"
CONTEXT_REQUIRED = frozenset({"code", "global_version", "gas", "stack"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED | {
    "data",
    "c7",
    "flags",
    "libraries",
    "chksig_always_succeed",
    "max_library_loads",
}
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    None: frozenset({"exit_code", "gas_used", "steps", "committed", "c4_hash", "c5_hash", "stack"})
}


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    t.boc(ctx["code"], f"{where}.code")
    t.integer(ctx["global_version"], f"{where}.global_version", 0, 255)
    if "flags" in ctx:
        t.integer(ctx["flags"], f"{where}.flags", 0, 255)
    if "data" in ctx:
        t.boc(ctx["data"], f"{where}.data")
    if "c7" in ctx:
        t.stack_item(ctx["c7"], f"{where}.c7")
        if t.obj(ctx["c7"], f"{where}.c7").get("type") != "tuple":
            raise t.FixtureError(f"{where}.c7: tuple required")
    gas = t.obj(ctx["gas"], f"{where}.gas")
    t.keys(gas, {"limit", "max"}, {"limit", "max", "credit"}, f"{where}.gas")
    for key in gas:
        t.integer(gas[key], f"{where}.gas.{key}", 0)
    for i, item in enumerate(t.array(ctx["stack"], f"{where}.stack", 255)):
        t.stack_item(item, f"{where}.stack[{i}]")
    if "chksig_always_succeed" in ctx:
        t.boolean(ctx["chksig_always_succeed"], f"{where}.chksig_always_succeed")
    if "max_library_loads" in ctx:
        t.integer(ctx["max_library_loads"], f"{where}.max_library_loads", 0, 0xFFFFFFFF)
    for i, lib in enumerate(t.array(ctx.get("libraries", []), f"{where}.libraries", 4)):
        t.boc(lib, f"{where}.libraries[{i}]")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    t.outcome_shape(eff, EFFECT_SHAPES, where)
    for key in ("exit_code", "gas_used", "steps"):
        t.integer(eff[key], f"{where}.{key}")
    t.boolean(eff["committed"], f"{where}.committed")
    t.optional_hash(eff["c4_hash"], f"{where}.c4_hash")
    t.optional_hash(eff["c5_hash"], f"{where}.c5_hash")
    t.string_list(eff["stack"], f"{where}.stack")
