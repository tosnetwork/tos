#!/usr/bin/env python3
"""Check Slice 1 gas budgets against checked-in baselines.

Two gates are enforced:

  1. Tol-side regression gate (v1 schema): focused tol-tester run per
     contract; failing if the new total exceeds the recorded
     ``baseline_gas`` by more than ``threshold_percent`` percent.

  2. FunC-vs-Tol parity gate (v2 schema, doc/slice-1-gas-gap.md §4
     closure): per-contract ratio of ``tol_gas_baseline`` over
     ``func_gas_baseline``; failing if the ratio exceeds the
     ``func_vs_tol_ratio_threshold`` (default 1.15 per
     `tos-message-policy.md` §10.1, with optional per-contract
     overrides — wallet-v5 uses 1.35 because its bytecode-cell ratio is
     1.10).

The dual baselines come from
``emulator/test/slice-1-stage-4-gas-parity-fixture.cpp`` which drives
the migrated reference contracts' .fc and .tol compilations through
``tos::SmartContract::send_internal_message`` with bit-identical inbound
bytes per scenario. The script does not re-run that harness; it just
reads the baselines and validates the recorded ratios against the
threshold. CI re-runs the harness as part of the test-emulator suite,
so a regression in the harness is caught at fixture-time, while the
script's job is to keep the baselines themselves honest (no committing
a JSON whose numbers fail the budget gate).
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


SUMMARY_RE = re.compile(r"Done,\s*(\d+)\s+tests,\s+gas\s+(\d+)")


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baselines",
        default=str(root / "doc" / "slice-1-gas-baselines.json"),
        help="Path to the Slice 1 gas baseline JSON.",
    )
    return parser.parse_args()


def load_baselines(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if "contracts" not in data or not isinstance(data["contracts"], list):
        raise SystemExit(f"{path}: expected a 'contracts' list")
    return data


def default_env(root: Path) -> dict:
    env = os.environ.copy()
    env.setdefault("FIFTPATH", str(root / "crypto" / "fift" / "lib"))
    tol = root / "build" / "tol" / "tol"
    fift = root / "build" / "crypto" / "fift"
    if tol.exists():
        env.setdefault("TOL_EXECUTABLE", str(tol))
    if fift.exists():
        env.setdefault("FIFT_EXECUTABLE", str(fift))
    return env


def run_tol_tester(root: Path, pattern: str, env: dict) -> tuple[int, int, str]:
    tol_tester_dir = root / "tol-tester"
    cmd = [sys.executable, "tol-tester.py", "tests", pattern]
    res = subprocess.run(
        cmd,
        cwd=tol_tester_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = res.stdout + res.stderr
    if res.returncode != 0:
        print(output.rstrip(), file=sys.stderr)
        raise SystemExit(f"tol-tester failed for pattern '{pattern}' with exit code {res.returncode}")
    match = SUMMARY_RE.search(output)
    if not match:
        print(output.rstrip(), file=sys.stderr)
        raise SystemExit(f"tol-tester summary not found for pattern '{pattern}'")
    return int(match.group(1)), int(match.group(2)), output


def allowed_gas(baseline: int, threshold_percent: int) -> int:
    return (baseline * (100 + threshold_percent) + 99) // 100


def check_tol_regression_gate(data: dict, env: dict, root: Path) -> bool:
    """Per-contract Tol-side regression gate (v1 schema). Returns True on failure."""
    threshold_percent = int(data.get("threshold_percent", 10))
    print(f"Slice 1 Tol-side gas regression gate ({threshold_percent}% threshold)")
    if data.get("note"):
        print(f"note: {data['note']}")
    print()
    print(f"{'contract':<16} {'tests':>5} {'baseline':>9} {'actual':>9} {'allowed':>9} {'ratio':>7}  status")

    failed = False
    for item in data["contracts"]:
        name = item["name"]
        pattern = item["tol_tester_pattern"]
        baseline = int(item["baseline_gas"])
        want_tests = int(item["expected_tests"])
        actual_tests, actual_gas, _ = run_tol_tester(root, pattern, env)
        max_gas = allowed_gas(baseline, threshold_percent)
        ratio = actual_gas / baseline if baseline else 0
        status = "OK"
        if actual_tests != want_tests:
            status = f"FAIL expected {want_tests} tests"
            failed = True
        elif actual_gas > max_gas:
            status = "FAIL over budget"
            failed = True
        print(f"{name:<16} {actual_tests:>5} {baseline:>9} {actual_gas:>9} {max_gas:>9} {ratio:>7.3f}  {status}")
    return failed


def check_func_vs_tol_parity_gate(data: dict) -> bool:
    """Per-contract FunC-vs-Tol parity gate (v2 schema, doc/slice-1-gas-gap.md §4
    closure). Returns True on failure.

    Reads the dual baselines `tol_gas_baseline` and `func_gas_baseline`
    captured by emulator/test/slice-1-stage-4-gas-parity-fixture.cpp and
    compares the ratio against `func_vs_tol_ratio_threshold` (per-contract
    override falls back to the top-level default, default 1.15)."""
    if int(data.get("version", 1)) < 2:
        print()
        print("FunC-vs-Tol parity gate skipped (baseline JSON is v1 schema).")
        return False

    default_threshold = float(data.get("func_vs_tol_ratio_threshold", 1.15))
    print()
    print(f"Slice 1 FunC-vs-Tol parity gate (default threshold={default_threshold:.2f})")
    print(f"{'contract':<16} {'func_gas':>9} {'tol_gas':>9} {'ratio':>7} {'threshold':>9}  status")

    failed = False
    for item in data["contracts"]:
        name = item["name"]
        if "func_gas_baseline" not in item or "tol_gas_baseline" not in item:
            print(f"{name:<16} {'-':>9} {'-':>9} {'-':>7} {'-':>9}  SKIP (no parity baseline)")
            continue
        func_gas = int(item["func_gas_baseline"])
        tol_gas = int(item["tol_gas_baseline"])
        threshold = float(item.get("func_vs_tol_ratio_threshold", default_threshold))
        ratio = tol_gas / func_gas if func_gas else 0
        status = "OK"
        if ratio > threshold:
            status = "FAIL over parity budget"
            failed = True
        print(f"{name:<16} {func_gas:>9} {tol_gas:>9} {ratio:>7.3f} {threshold:>9.2f}  {status}")
    return failed


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    args = parse_args()
    baseline_path = Path(args.baselines)
    if not baseline_path.is_absolute():
        baseline_path = root / baseline_path
    data = load_baselines(baseline_path)
    env = default_env(root)

    failed_regression = check_tol_regression_gate(data, env, root)
    failed_parity = check_func_vs_tol_parity_gate(data)

    return 1 if (failed_regression or failed_parity) else 0


if __name__ == "__main__":
    raise SystemExit(main())
