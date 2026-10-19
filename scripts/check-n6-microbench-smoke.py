#!/usr/bin/env python3
"""Run and validate the deterministic N6 CI microbench subset."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"N6_MICROBENCH_SMOKE_FAILURE: {message}")


parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path)
parser.add_argument("--result", type=Path)
parser.add_argument("--baseline", type=Path, required=True)
parser.add_argument("--vectors", type=Path, required=True)
args = parser.parse_args()
if (args.binary is None) == (args.result is None):
    fail("exactly one of --binary or --result is required")

temporary: tempfile.TemporaryDirectory[str] | None = None
if args.binary is not None:
    if not args.binary.is_file():
        fail(f"benchmark binary is missing: {args.binary}")
    temporary = tempfile.TemporaryDirectory(prefix="n6-microbench-smoke-")
    result_path = Path(temporary.name) / "result.json"
    subprocess.run([str(args.binary), "--output", str(result_path), "--samples", "100"], check=True)
else:
    result_path = args.result

baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
result = json.loads(result_path.read_text(encoding="utf-8"))
if result.get("schema_version") != baseline.get("schema_version"):
    fail("result and baseline schema versions differ")
samples = result.get("samples")
if not isinstance(samples, int) or samples < baseline["minimum_samples"]:
    fail(f"timing sample count {samples!r} is below {baseline['minimum_samples']}")

rows: dict[int, dict[str, str]] = {}
with args.vectors.open(encoding="utf-8") as source:
    header: list[str] | None = None
    for line in source:
        if line.startswith("#") or not line.strip():
            continue
        values = line.rstrip("\n").split("\t")
        if header is None:
            header = values
            continue
        row = dict(zip(header, values, strict=True))
        rows[int(row["signers"])] = row
expected_sizes = {
    "n5_13_boc_21": int(rows[21]["block_signatures_boc"]),
    "n5_13_boc_100": int(rows[100]["block_signatures_boc"]),
    "block_proof_boc_21": int(rows[21]["block_proof_boc"]),
    "block_proof_boc_100": int(rows[100]["block_proof_boc"]),
}
for vector, expected in expected_sizes.items():
    actual = result.get("exact_sizes", {}).get(vector)
    if actual != expected:
        fail(f"size vector {vector} changed: expected {expected}, got {actual}")

operations = result.get("operations", {})
if operations.get("single_sign", {}).get("iterations") != samples:
    fail("single_sign operation count drifted")
for operation, per_sample in baseline["verify_calls_per_sample"].items():
    expected = samples * per_sample
    actual = operations.get(operation, {}).get("verify_calls")
    if actual != expected:
        fail(f"operation count drift for {operation}: expected {expected}, got {actual}")

cap = result.get("structural_cap", {})
if (
    cap.get("maximum") != baseline["structural_cap"]["maximum"]
    or cap.get("tested") != baseline["structural_cap"]["tested"]
    or cap.get("refused") is not True
):
    fail(
        f"structural cap was not enforced: maximum={cap.get('maximum')} "
        f"tested={cap.get('tested')} refused={cap.get('refused')}"
    )


def p95(operation: str) -> float:
    value = operations.get(operation, {}).get("timing", {}).get("p95_us")
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        fail(f"{operation} has no positive p95")
    return float(value)


single_verify = p95("single_verify")
timing = baseline["large_timing_regression"]
ratios = {
    "single_sign_over_single_verify_p95": p95("single_sign") / single_verify,
    "certificate_verify_21_per_signature_over_single_verify_p95": p95("certificate_verify_21")
    / (21 * single_verify),
    "certificate_verify_100_per_signature_over_single_verify_p95": p95("certificate_verify_100")
    / (100 * single_verify),
    "proof_verify_21_per_signature_over_single_verify_p95": p95("proof_verify_21")
    / (21 * single_verify),
    "lite_verify_21_per_signature_over_single_verify_p95": p95("lite_verify_21")
    / (21 * single_verify),
}
for name, ratio in ratios.items():
    if ratio > timing[name]:
        fail(
            f"large timing regression {name}: normalized p95 {ratio:.3f} exceeds {timing[name]:.3f}"
        )

print(
    "N6_MICROBENCH_SMOKE_OK: exact sizes, verification counts, structural cap, and repeated-sample large-regression bounds hold"
)
