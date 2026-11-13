#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Explain one disagreement between two targets (docs/fuzz.md).

    debug_mismatch.py --reference <cli> --target <cli> <mismatch file>
    debug_mismatch.py --reference <cli> --target <cli> --fixture <harness>/<family>/<fixture id>
        [--vectors <dir>]
    debug_mismatch.py --reference <cli> --target <cli> --first-of <dir> [--expect-trace on|off]

Runs the context through both programs, prints the field differences of the two effects (the stack item by
item) and, for the vm harness, asks both programs for the step trace (context flag ``"trace": true``, only
answered by builds with TOS_VM_STEP_TRACE) and prints the first step where the traces diverge. The trace
is a diagnosis aid and never part of the compared effects; this tool checks that requesting it leaves the
effects unchanged.

``--expect-trace on`` exits 0 only when both traces are present, leave the effects unchanged and, if the
effects differ, locate a first diverging step; ``--expect-trace off`` exits 0 only when the reference
refuses the trace request (a build without the hook).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402

Json = dict[str, Any]
VECTORS = Path(__file__).resolve().parent.parent / "vectors"
CONTEXT_EVENTS = 3


def load_mismatch(path: Path) -> tuple[str, Json, Json | None]:
    document = cast(Json, json.loads(path.read_text()))
    if document.get("format") != "fuzz-mismatch-v1":
        raise c.FixtureError(f"{path}: not a fuzz mismatch file")
    return document["harness"], document["context"], document.get("effects")


def load_fixture(fixture: str, vectors: Path) -> tuple[str, Json, Json | None]:
    parts = fixture.split("/", 2)
    if len(parts) != 3:
        raise c.FixtureError("--fixture takes <harness>/<family>/<fixture id>")
    harness, family, fixture_id = parts
    loaded = c.load_family(vectors / harness / "fixtures" / f"{family}.jsonl")
    for record, context in zip(loaded.fixtures, loaded.contexts(), strict=True):
        if record["metadata"]["fixture_id"] == fixture_id:
            return harness, context, {"frozen": record["effects"]}
    raise c.FixtureError(f"no fixture {fixture}")


def first_mismatch_file(directory: Path) -> Path:
    files = sorted(p for p in directory.rglob("*.json") if "fuzz-mismatches" in p.parts)
    if not files:
        raise c.FixtureError(f"no mismatch files under {directory}")
    return files[0]


def field_diff(reference: Mapping[str, Any], target: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    for key in sorted(set(reference) | set(target)):
        a, b = reference.get(key), target.get(key)
        if a == b:
            continue
        if isinstance(a, list) and isinstance(b, list):
            left, right = cast(list[Any], a), cast(list[Any], b)
            lines.append(f"{key}: {len(left)} items vs {len(right)} items")
            for i in range(max(len(left), len(right))):
                x = left[i] if i < len(left) else "<absent>"
                y = right[i] if i < len(right) else "<absent>"
                if x != y:
                    lines.append(f"  [{i}] reference {json.dumps(x)}")
                    lines.append(f"  [{i}] target    {json.dumps(y)}")
        else:
            lines.append(f"{key}: reference {json.dumps(a)} target {json.dumps(b)}")
    return lines


def first_divergence(a: Sequence[Any], b: Sequence[Any]) -> int | None:
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i
    return None if len(a) == len(b) else min(len(a), len(b))


def describe_event(event: object) -> str:
    return "<end of trace>" if event is None else json.dumps(event, sort_keys=True)


def trace_report(
    reference: Mapping[str, Any], target: Mapping[str, Any]
) -> tuple[list[str], int | None]:
    a = cast(list[Any], reference["trace"]["events"])
    b = cast(list[Any], target["trace"]["events"])
    lines = [f"trace: reference {len(a)} events, target {len(b)} events"]
    if reference["trace"].get("truncated") or target["trace"].get("truncated"):
        lines.append("trace: truncated; a divergence after the cap is not visible")
    at = first_divergence(a, b)
    if at is None:
        lines.append("trace: no diverging step")
        return lines, None
    lines.append(f"trace: first diverging event #{at}")
    for i in range(max(0, at - CONTEXT_EVENTS), at):
        lines.append(f"  same      #{i} {describe_event(a[i])}")
    lines.append(f"  reference #{at} {describe_event(a[at] if at < len(a) else None)}")
    lines.append(f"  target    #{at} {describe_event(b[at] if at < len(b) else None)}")
    return lines, at


def diagnose(
    reference_cli: str, target_cli: str, harness: str, context: Json, expect_trace: str | None
) -> int:
    ref_effects = c.run_target(reference_cli, harness, [context])[0]
    target_effects = c.run_target(target_cli, harness, [context])[0]
    print(f"reference {json.dumps(ref_effects, sort_keys=True)[:2000]}")
    print(f"target    {json.dumps(target_effects, sort_keys=True)[:2000]}")
    differs = ref_effects != target_effects
    for line in field_diff(ref_effects, target_effects) if differs else ["effects are equal"]:
        print(line)
    if harness != "vm":
        return 0 if expect_trace is None else 1
    traced = dict(context, trace=True)
    ref_traced = c.run_target(reference_cli, harness, [traced])[0]
    target_traced = c.run_target(target_cli, harness, [traced])[0]
    have = ["trace" in ref_traced, "trace" in target_traced]
    for name, response, present in (
        ("reference", ref_traced, have[0]),
        ("target", target_traced, have[1]),
    ):
        if not present:
            print(f"trace: unavailable from the {name}: {json.dumps(response)[:300]}")
    if expect_trace == "off":
        refused = c.is_refusal(ref_traced) and "trace" in str(ref_traced["harness_error"])
        print("trace request refused as expected" if refused else "trace request NOT refused")
        return 0 if refused else 1
    if not all(have):
        return 1 if expect_trace == "on" else 0
    unchanged = True
    for name, plain, response in (
        ("reference", ref_effects, ref_traced),
        ("target", target_effects, target_traced),
    ):
        stripped = {k: v for k, v in response.items() if k != "trace"}
        if stripped != plain:
            unchanged = False
            print(f"trace: requesting the trace changed the {name}'s effects")
    lines, at = trace_report(ref_traced, target_traced)
    for line in lines:
        print(line)
    if expect_trace == "on":
        located = at is not None or not differs
        return 0 if unchanged and located else 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--target", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("mismatch", nargs="?", type=Path)
    source.add_argument("--fixture")
    source.add_argument("--first-of", type=Path)
    parser.add_argument("--vectors", type=Path, default=VECTORS)
    parser.add_argument("--expect-trace", choices=["on", "off"])
    args = parser.parse_args(argv)
    try:
        if args.fixture:
            harness, context, recorded = load_fixture(args.fixture, args.vectors)
        else:
            path = first_mismatch_file(args.first_of) if args.first_of else args.mismatch
            print(f"mismatch file {path}")
            harness, context, recorded = load_mismatch(path)
        if recorded is not None:
            print(f"recorded  {json.dumps(recorded, sort_keys=True)[:2000]}")
        return diagnose(args.reference, args.target, harness, context, args.expect_trace)
    except (c.FixtureError, json.JSONDecodeError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
