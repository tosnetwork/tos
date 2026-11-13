# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""codec harness: decoding verdicts for bags of cells and TL-B types (schema/harness/codec-v1.schema.json)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, cast

import fixture_types as t

NAME = "codec"
TYPED = frozenset(
    {
        "Account",
        "AccountStorage",
        "Block",
        "BlockInfo",
        "Coins",
        "CurrencyCollection",
        "ExtraCurrencyCollection",
        "McStateExtra",
        "Message",
        "MessageRelaxed",
        "MsgAddressInt",
        "ShardAccount",
        "ShardState",
        "ShardStateUnsplit",
        "StateInit",
        "StorageUsed",
        "Transaction",
        "ValidatorDescr",
        "ValidatorSet",
    }
)
SPECIAL = frozenset(
    {"cell", "VarUInteger", "account_storage", "config", "ConfigParam", "ConfigParams"}
)
TYPES = TYPED | SPECIAL
REASONS = frozenset({"boc", "roots", "tlb", "handwritten", "semantic", "range"})
BITS_RE = re.compile(r"^[01]{0,1023}$")
ADDRESS_RE = re.compile(r"^[0-9a-f]{64}$")

CONTEXT_REQUIRED = frozenset({"type"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED | {
    "boc",
    "bits",
    "n",
    "op",
    "value",
    "mode",
    "max_cells",
    "proof_child",
    "path",
    "now",
    "special",
    "workchain",
    "address",
    "relax",
    "old_mparams",
    "old_mparams_proof_child",
}
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "accepted": frozenset({"outcome", "root_hashes", "reserialized_sha256", "facts"}),
    "rejected": frozenset({"outcome", "reason", "root_hashes", "facts"}),
}
# Fields each type may carry besides type, mode and max_cells.
TYPE_FIELDS: dict[str, frozenset[str]] = {
    "VarUInteger": frozenset({"n", "op", "bits", "value"}),
    "account_storage": frozenset(
        {"boc", "bits", "now", "special", "workchain", "address", "proof_child", "path"}
    ),
    "config": frozenset(
        {
            "boc",
            "bits",
            "address",
            "relax",
            "old_mparams",
            "old_mparams_proof_child",
            "proof_child",
            "path",
        }
    ),
    "ConfigParam": frozenset({"boc", "bits", "n", "proof_child", "path"}),
    "ConfigParams": frozenset({"boc", "bits", "address", "proof_child", "path"}),
    "cell": frozenset({"boc", "bits"}),
}
TYPED_FIELDS = frozenset({"boc", "bits", "proof_child", "path"})


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    kind = ctx["type"]
    if not isinstance(kind, str) or kind not in TYPES:
        raise t.FixtureError(f"{where}.type: unknown {kind!r}")
    allowed = TYPE_FIELDS.get(kind, TYPED_FIELDS) | {"type", "mode", "max_cells"}
    t.keys(ctx, {"type"}, set(allowed), where)
    if "mode" in ctx:
        t.integer(ctx["mode"], f"{where}.mode", 0, 31)
    if "max_cells" in ctx:
        t.integer(ctx["max_cells"], f"{where}.max_cells", 1, 1 << 24)
    for key in ("proof_child", "special", "relax", "old_mparams_proof_child"):
        if key in ctx:
            t.boolean(ctx[key], f"{where}.{key}")
    if kind == "VarUInteger":
        t.integer(ctx.get("n"), f"{where}.n", 1, 32)
        op = ctx.get("op", "read")
        if op == "read":
            t.keys(
                ctx, {"type", "n", "bits"}, {"type", "n", "op", "bits", "mode", "max_cells"}, where
            )
            t.text(ctx["bits"], BITS_RE, f"{where}.bits")
        elif op == "write":
            t.keys(ctx, {"type", "n", "op", "value"}, {"type", "n", "op", "value"}, where)
            t.text(ctx["value"], t.INT_TEXT_RE, f"{where}.value")
        else:
            raise t.FixtureError(f"{where}.op: read or write")
        return
    if ("boc" in ctx) == ("bits" in ctx):
        raise t.FixtureError(f"{where}: exactly one of boc and bits")
    if "boc" in ctx:
        t.boc(ctx["boc"], f"{where}.boc")
    else:
        t.text(ctx["bits"], BITS_RE, f"{where}.bits")
    if "path" in ctx:
        for i, step in enumerate(t.array(ctx["path"], f"{where}.path", 64)):
            t.integer(step, f"{where}.path[{i}]", 0, 3)
    if "old_mparams" in ctx:
        t.boc(ctx["old_mparams"], f"{where}.old_mparams")
    if "address" in ctx:
        t.text(ctx["address"], ADDRESS_RE, f"{where}.address")
    if kind == "account_storage":
        t.integer(ctx.get("now"), f"{where}.now", 0, 0xFFFFFFFF)
        if "workchain" in ctx:
            t.integer(ctx["workchain"], f"{where}.workchain", -128, 127)
    if kind == "config" and "address" not in ctx:
        raise t.FixtureError(f"{where}: config needs address")
    if kind == "ConfigParam":
        t.integer(ctx.get("n"), f"{where}.n", 0, 0xFFFFFFFF)


def fact_value(value: object, where: str) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        t.string_list(cast(list[Any], value), where)
        return
    raise t.FixtureError(f"{where}: scalar or list of strings required")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    outcome = t.outcome_shape(eff, EFFECT_SHAPES, where)
    for i, root in enumerate(t.array(eff["root_hashes"], f"{where}.root_hashes")):
        t.cell_hash(root, f"{where}.root_hashes[{i}]")
    if outcome == "accepted":
        t.text(eff["reserialized_sha256"], t.BLOB_RE, f"{where}.reserialized_sha256")
    elif eff["reason"] not in REASONS:
        raise t.FixtureError(f"{where}.reason: unknown {eff['reason']!r}")
    for key, value in t.obj(eff["facts"], f"{where}.facts").items():
        fact_value(value, f"{where}.facts.{key}")
