#!/usr/bin/env python3
"""Validate and run Slice 3 deterministic replay fixtures.

Stage 1 deliberately keeps the runner small: fixture JSON is validated
with Python stdlib checks, then the C++ emulator replay fixture is run
through ``test-emulator --filter Slice3Replay``. Later Slice 3 stages
add more fixture files; this script is the stable CI entrypoint.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


REQUIRED_TOP = {
    "version",
    "schema",
    "fixture_id",
    "contract",
    "source_baseline",
    "runner",
    "cases",
}


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixtures-dir",
        default=str(root / "emulator" / "test" / "slice-3-replay-fixtures"),
        help="Directory containing Slice 3 replay fixture JSON files.",
    )
    parser.add_argument(
        "--test-emulator",
        default=str(root / "build" / "test-emulator"),
        help="Path to the built test-emulator binary.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate JSON fixtures; do not execute test-emulator.",
    )
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise SystemExit(f"{path}: invalid JSON: {e}") from e


def validate_fixture(path: Path) -> str:
    data = load_json(path)
    missing = sorted(REQUIRED_TOP - set(data))
    require(not missing, f"{path}: missing top-level keys: {', '.join(missing)}")
    require(data["version"] == 1, f"{path}: version must be 1")
    require(data["schema"] == "slice-3-replay-fixture", f"{path}: unexpected schema")
    require(isinstance(data["fixture_id"], str) and data["fixture_id"], f"{path}: fixture_id must be non-empty")

    contract = data["contract"]
    for key in ("name", "tol_file", "compiled_boc", "storage_builder"):
        require(isinstance(contract.get(key), str) and contract[key], f"{path}: contract.{key} must be non-empty")

    runner = data["runner"]
    require(isinstance(runner.get("emulator_filter"), str) and runner["emulator_filter"], f"{path}: missing runner.emulator_filter")
    require(isinstance(runner.get("tol_tester_patterns"), list), f"{path}: runner.tol_tester_patterns must be a list")

    cases = data["cases"]
    require(isinstance(cases, list) and cases, f"{path}: cases must be a non-empty list")
    saw_negative_generator = False
    for i, case in enumerate(cases):
        prefix = f"{path}: cases[{i}]"
        for key in ("name", "kind", "initial_c4", "inbound", "expected"):
            require(key in case, f"{prefix}: missing {key}")
        require(case["kind"] in ("emulator-replay", "deterministic-negative-generator"), f"{prefix}: unknown kind")
        saw_negative_generator = saw_negative_generator or case["kind"] == "deterministic-negative-generator"
        initial_c4 = case["initial_c4"]
        require(isinstance(initial_c4.get("builder"), str) and initial_c4["builder"], f"{prefix}: initial_c4.builder required")
        require(isinstance(initial_c4.get("expect_unchanged"), bool), f"{prefix}: initial_c4.expect_unchanged must be bool")
        body = case["inbound"].get("body")
        require(isinstance(body, dict), f"{prefix}: inbound.body must be object")
        require(isinstance(body.get("builder"), str) and body["builder"], f"{prefix}: inbound.body.builder required")
        if case["kind"] == "deterministic-negative-generator":
            generator = body.get("generator")
            require(isinstance(generator, dict), f"{prefix}: generator required")
            require(isinstance(generator.get("name"), str) and generator["name"], f"{prefix}: generator.name required")
            require(isinstance(generator.get("seed"), int) and generator["seed"] >= 0, f"{prefix}: generator.seed must be >= 0")
            require(isinstance(generator.get("count"), int) and generator["count"] > 0, f"{prefix}: generator.count must be > 0")
        expected = case["expected"]
        require(isinstance(expected.get("exit_code"), int), f"{prefix}: expected.exit_code must be int")
        require(isinstance(expected.get("actions"), int) and expected["actions"] >= 0, f"{prefix}: expected.actions must be >= 0")
        require(isinstance(expected.get("max_gas_used"), int) and expected["max_gas_used"] > 0, f"{prefix}: expected.max_gas_used must be > 0")

    require(saw_negative_generator, f"{path}: at least one deterministic-negative-generator case is required")
    return str(data["fixture_id"])


def run_emulator(test_emulator: Path) -> None:
    require(test_emulator.exists(), f"{test_emulator}: test-emulator binary does not exist; build it first")
    res = subprocess.run(
        [str(test_emulator), "--filter", "Slice3Replay"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = res.stdout + res.stderr
    if res.returncode != 0 and output:
        print(output.rstrip())
    require(res.returncode == 0, f"test-emulator Slice3Replay failed with exit code {res.returncode}")
    pass_line = next((line for line in reversed(output.splitlines()) if "test(s) passed" in line), None)
    if pass_line:
        print(f"Slice3Replay emulator: {pass_line.strip()}")


def main() -> int:
    args = parse_args()
    fixtures_dir = Path(args.fixtures_dir)
    require(fixtures_dir.is_dir(), f"{fixtures_dir}: fixture directory not found")

    fixture_ids = []
    for path in sorted(fixtures_dir.glob("*.json")):
        fixture_ids.append(validate_fixture(path))
    require(fixture_ids, f"{fixtures_dir}: no fixture JSON files found")
    print(f"Validated {len(fixture_ids)} Slice 3 replay fixture(s): {', '.join(fixture_ids)}")

    if not args.validate_only:
        run_emulator(Path(args.test_emulator))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
