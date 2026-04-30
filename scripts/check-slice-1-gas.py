#!/usr/bin/env python3
"""Check Slice 1 focused Tol gas totals against a checked-in baseline."""

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


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    args = parse_args()
    baseline_path = Path(args.baselines)
    if not baseline_path.is_absolute():
        baseline_path = root / baseline_path
    data = load_baselines(baseline_path)
    threshold_percent = int(data.get("threshold_percent", 10))
    env = default_env(root)

    print(f"Slice 1 gas regression gate ({threshold_percent}% threshold)")
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

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
