#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Shrink a context while two targets still disagree on it (docs/fuzz.md).

    minimize.py --reference <cli> --target <cli> <mismatch file | context file> [--out <file>]
        [--max-rounds N]

The input is a fuzz mismatch file or a file holding one context JSON. Each round builds every candidate
reduction of the current context, runs them in one batch through both programs and keeps the first that
still mismatches (the reference must not refuse it). It stops when no candidate mismatches.

vm reductions: drop c7, data, libraries and flags, drop or simplify stack items and tuple elements, lower
the gas values, cut the code to data prefixes, drop references and hoist subtrees. txn reductions: drop
libraries and prev_blocks, drop the message's StateInit, replace the message body by an empty or shorter
one. The result is written as a context file (``--out``) or printed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402
import fuzz_boc as boc  # noqa: E402

Json = dict[str, Any]
Runner = Callable[[Sequence[Json]], list[bool]]
DEFAULT_MAX_ROUNDS = 500


def size(context: Mapping[str, Any]) -> int:
    return len(json.dumps(context, separators=(",", ":"), sort_keys=True))


def cell_weight(value: object) -> int:
    """Bits and references of the cells in a context's reducible fields (stack items, c7, code, data,
    message); the large configuration and account cells are left out."""
    if isinstance(value, list):
        return sum(cell_weight(v) for v in cast(list[Any], value))
    if isinstance(value, dict):
        item = cast(Json, value)
        if item.get("type") in ("cell", "slice") and isinstance(item.get("boc"), str):
            return cell_weight(item["boc"])
        return cell_weight(item.get("items", []))
    if isinstance(value, str):
        try:
            return boc.from_b64(value).tree_size()
        except boc.BocError:
            return 0
    return 0


def measure(context: Mapping[str, Any]) -> tuple[int, int, int]:
    """Cell content first, then text size, then the gas values; a candidate is kept only when smaller."""
    weight = sum(cell_weight(context.get(k)) for k in ("code", "data", "message", "stack", "c7"))
    gas = context.get("gas")
    total = (
        sum(v for v in cast(Json, gas).values() if isinstance(v, int))
        if isinstance(gas, dict)
        else 0
    )
    return weight, size(context), total


def simpler_items(item: Mapping[str, Any], depth: int = 0) -> Iterator[Json]:
    kind = item.get("type")
    if kind != "null":
        yield {"type": "null"}
    if kind == "int" and item.get("value") not in ("0",):
        yield {"type": "int", "value": "0"}
    if kind == "tuple" and depth < 4:
        items = cast(list[Json], item.get("items", []))
        for i in range(len(items)):
            yield {"type": "tuple", "items": items[:i] + items[i + 1 :]}
        for i, sub in enumerate(items):
            for smaller in simpler_items(sub, depth + 1):
                yield {"type": "tuple", "items": [*items[:i], smaller, *items[i + 1 :]]}
    if kind in ("cell", "slice"):
        try:
            cell = boc.from_b64(item["boc"])
        except boc.BocError:
            return
        for smaller in boc.cell_variants(cell):
            yield {"type": kind, "boc": boc.to_b64(smaller)}


def vm_candidates(ctx: Json) -> Iterator[Json]:
    for key in ("c7", "data", "libraries", "flags"):
        if key in ctx:
            yield {k: v for k, v in ctx.items() if k != key}
    stack = cast(list[Json], ctx["stack"])
    if stack:
        yield dict(ctx, stack=[])
    for i in range(len(stack)):
        yield dict(ctx, stack=stack[:i] + stack[i + 1 :])
    try:
        code = boc.from_b64(ctx["code"])
    except boc.BocError:
        code = None
    if code is not None:
        for smaller in boc.cell_variants(code):
            yield dict(ctx, code=boc.to_b64(smaller))
    gas = cast(Json, ctx["gas"])
    if "credit" in gas:
        yield dict(ctx, gas={k: v for k, v in gas.items() if k != "credit"})
    if gas["max"] != gas["limit"]:
        yield dict(ctx, gas=dict(gas, max=gas["limit"]))
    for key in ("limit", "max"):
        value = cast(int, gas[key])
        # Smallest first: the first candidate that still mismatches is kept.
        for smaller in sorted({0, value // 2, value * 9 // 10, value - 1}):
            if 0 <= smaller < value:
                yield dict(ctx, gas=dict(gas, **{key: smaller}))
    for i, item in enumerate(stack):
        for smaller in simpler_items(item):
            yield dict(ctx, stack=[*stack[:i], smaller, *stack[i + 1 :]])
    if "c7" in ctx:
        for smaller in simpler_items(cast(Json, ctx["c7"])):
            if smaller.get("type") == "tuple":
                yield dict(ctx, c7=smaller)
    if "data" in ctx:
        try:
            data = boc.from_b64(ctx["data"])
        except boc.BocError:
            return
        for smaller in boc.cell_variants(data):
            yield dict(ctx, data=boc.to_b64(smaller))


def body_variants(body: boc.Cell) -> Iterator[boc.Cell]:
    if body.bits or body.refs:
        yield boc.Cell.make([])
    yield from boc.cell_variants(body)


def txn_candidates(ctx: Json) -> Iterator[Json]:
    for key in ("libraries", "prev_blocks"):
        if key in ctx:
            yield {k: v for k, v in ctx.items() if k != key}
    if "message" not in ctx:
        return
    try:
        message = boc.from_b64(ctx["message"])
        layout = boc.message_layout(message)
        body = boc.message_body(message, layout)
    except boc.BocError:
        return
    if layout.has_init:
        yield dict(ctx, message=boc.to_b64(boc.with_body(message, layout, body, keep_init=False)))
    for smaller in body_variants(body):
        try:
            yield dict(ctx, message=boc.to_b64(boc.with_body(message, layout, smaller)))
        except boc.BocError:
            continue


CANDIDATES: dict[str, Callable[[Json], Iterator[Json]]] = {
    "vm": vm_candidates,
    "txn": txn_candidates,
}


def cli_runner(reference: str, target: str, harness: str) -> Runner:
    def mismatches(contexts: Sequence[Json]) -> list[bool]:
        if not contexts:
            return []
        a = c.run_target(reference, harness, contexts)
        b = c.run_target(target, harness, contexts)
        return [not c.is_refusal(x) and x != y for x, y in zip(a, b, strict=True)]

    return mismatches


def minimize(
    harness: str, context: Json, still_mismatches: Runner, max_rounds: int
) -> tuple[Json, int]:
    """The smallest context reached and the number of rounds that made progress."""
    if not still_mismatches([context])[0]:
        raise c.FixtureError("the targets agree on the input context; nothing to minimize")
    current = context
    progress = 0
    for _ in range(max_rounds):
        seen: set[str] = set()
        candidates: list[Json] = []
        for candidate in CANDIDATES[harness](current):
            key = json.dumps(candidate, sort_keys=True)
            if key not in seen and measure(candidate) < measure(current):
                seen.add(key)
                candidates.append(candidate)
        verdicts = still_mismatches(candidates)
        chosen = next((cand for cand, bad in zip(candidates, verdicts, strict=True) if bad), None)
        if chosen is None:
            break
        current = chosen
        progress += 1
    return current, progress


def load_input(path: Path, harness: str | None) -> tuple[str, Json]:
    document = cast(Json, json.loads(path.read_text()))
    if document.get("format") == "fuzz-mismatch-v1":
        return document["harness"], cast(Json, document["context"])
    if harness is None:
        raise c.FixtureError("a plain context file needs --harness")
    return harness, document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--harness", choices=sorted(CANDIDATES))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--max-rounds", type=int, default=DEFAULT_MAX_ROUNDS)
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    try:
        harness, context = load_input(args.input, args.harness)
        if harness not in CANDIDATES:
            raise c.FixtureError(f"no reductions for harness {harness}")
        c.validate_context(harness, context)
        runner = cli_runner(args.reference, args.target, harness)
        result, rounds = minimize(harness, context, runner, args.max_rounds)
        text = json.dumps(result, separators=(",", ":"), sort_keys=True)
        print(
            f"minimized {size(context)} -> {size(result)} bytes in {rounds} rounds", file=sys.stderr
        )
        if args.out:
            args.out.write_text(text + "\n")
        else:
            print(text)
        return 0
    except (c.FixtureError, json.JSONDecodeError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
