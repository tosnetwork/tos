# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""fee harness: fee and gas arithmetic from explicit prices (schema/harness/fee-v1.schema.json)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "fee"
U64_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
U128_RE = re.compile(r"^(0|[1-9][0-9]{0,38})$")
DECIMAL_RE = re.compile(r"^-?[0-9]{1,80}$")

KIND_FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "storage": (
        frozenset({"now", "last_paid", "cells", "bits", "special", "masterchain", "periods"}),
        frozenset(),
    ),
    "gas_purchase": (
        frozenset({"gas_price", "gas_limit", "flat_gas_limit", "flat_gas_price", "balance"}),
        frozenset(),
    ),
    "forward": (
        frozenset(
            {
                "lump_price",
                "bit_price",
                "cell_price",
                "ihr_factor",
                "first_frac",
                "next_frac",
                "cells",
                "bits",
            }
        ),
        frozenset({"ihr_disabled"}),
    ),
}
PERIOD_KEYS = frozenset({"since", "bit_price", "cell_price", "mc_bit_price", "mc_cell_price"})
CONTEXT_REQUIRED = frozenset({"kind"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED.union(*(a | b for a, b in KIND_FIELDS.values()))
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "storage": frozenset({"outcome", "fee"}),
    "gas_purchase": frozenset({"outcome", "threshold", "gas_bought", "fee", "simple_fee"}),
    "forward": frozenset(
        {
            "outcome",
            "fwd_fee",
            "fwd_fee_256",
            "ihr_fwd_fee",
            "ihr_fee",
            "first_part",
            "first_part_256",
            "next_part_256",
        }
    ),
}
U32_FIELDS = frozenset({"now", "last_paid", "since", "ihr_factor", "first_frac", "next_frac"})
BOOL_FIELDS = frozenset({"special", "masterchain", "ihr_disabled"})


def scalar(value: object, key: str, where: str) -> None:
    if key in U32_FIELDS:
        t.integer(value, where, 0, 0xFFFFFFFF)
    elif key in BOOL_FIELDS:
        t.boolean(value, where)
    elif key == "balance":
        if int(t.text(value, U128_RE, where)) >> 128:
            raise t.FixtureError(f"{where}: more than 128 bits")
    elif int(t.text(value, U64_RE, where)) >> 64:
        raise t.FixtureError(f"{where}: more than 64 bits")


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    kind = ctx["kind"]
    if not isinstance(kind, str) or kind not in KIND_FIELDS:
        raise t.FixtureError(f"{where}.kind: unknown {kind!r}")
    required, optional = KIND_FIELDS[kind]
    t.keys(ctx, set(required | {"kind"}), set(required | optional | {"kind"}), where)
    for key, value in ctx.items():
        if key == "kind":
            continue
        if key == "periods":
            for i, period in enumerate(t.array(value, f"{where}.periods", 64)):
                item = t.obj(period, f"{where}.periods[{i}]")
                t.keys(item, set(PERIOD_KEYS), set(PERIOD_KEYS), f"{where}.periods[{i}]")
                for name, field in item.items():
                    scalar(field, name, f"{where}.periods[{i}].{name}")
        else:
            scalar(value, key, f"{where}.{key}")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    t.outcome_shape(eff, EFFECT_SHAPES, where)
    for key, value in eff.items():
        if key == "outcome":
            continue
        if value is None and key == "fee" and eff["outcome"] == "storage":
            continue
        t.text(value, DECIMAL_RE, f"{where}.{key}")
