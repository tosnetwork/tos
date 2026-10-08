"""Execute and account for the entire configured native CTest registry."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# This floor is independent of CTest selection. Additional registered tests must
# also execute; the floor is NOT an allowlist or a replacement for the registry.
REQUIRED = frozenset(
    {
        "test-ed25519",
        "test-bigint",
        "test-vm",
        "test-fift",
        "test-cells",
        "test-smartcont",
        "test-net",
        "test-tdactor",
        "test-tdutils",
        "test-toslib-offline",
        "test-func",
        "test-func-legacy",
        "test-tol",
    }
)


def registered_names(payload: object, required: frozenset[str] = REQUIRED) -> set[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("tests"), list):
        raise ValueError("Invalid CTest registry")
    tests = payload["tests"]
    if not tests:
        raise ValueError("Empty CTest registry")
    names = set()
    for test in tests:
        if not isinstance(test, dict):
            raise ValueError("Invalid CTest entry")
        name = test.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("Missing or duplicate CTest name")
        if not isinstance(test.get("command"), list) or not test["command"]:
            raise ValueError(f"CTest executable was not built: {name}")
        properties = test.get("properties", [])
        if not isinstance(properties, list):
            raise ValueError(f"Invalid CTest properties: {name}")
        for prop in properties:
            if not isinstance(prop, dict):
                raise ValueError(f"Invalid CTest property: {name}")
            if prop.get("name") == "DISABLED" and str(prop.get("value")).lower() not in {
                "false", "off", "0", "no", ""
            }:
                raise ValueError(f"Disabled native test: {name}")
        names.add(name)
    missing = required - names
    if missing:
        raise ValueError(f"Required native tests missing: {sorted(missing)}")
    return names


def verify_results(path: Path, expected: set[str]) -> int:
    if not expected:
        raise ValueError("Empty expected native test set")
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    observed = set()
    for case in cases:
        name = case.get("name")
        if not name or name in observed:
            raise ValueError("Missing or duplicate result name")
        observed.add(name)
        if case.get("status") != "run":
            raise ValueError(f"Native test did not run: {name}")
        if any(case.find(tag) is not None for tag in ("failure", "error", "skipped")):
            raise ValueError(f"Native test failed or was skipped: {name}")
    if observed != expected:
        raise ValueError(
            f"CTest execution differs from registration: "
            f"missing={sorted(expected - observed)} unexpected={sorted(observed - expected)}"
        )
    return len(cases)


def run_suite(build: Path, required: frozenset[str] = REQUIRED) -> int:
    build = build.resolve(strict=True)
    evidence = build / "ci-native-results"
    evidence.mkdir(exist_ok=True)
    results = evidence / "results.xml"
    summary = evidence / "summary.json"
    # Never let a failed/repeated run inherit an old green receipt.
    results.unlink(missing_ok=True)
    summary.unlink(missing_ok=True)
    registry = subprocess.run(
        ["ctest", "--test-dir", str(build), "--show-only=json-v1"],
        text=True, capture_output=True, check=True, timeout=120,
    )
    (evidence / "registry.json").write_text(registry.stdout, encoding="utf-8")
    names = registered_names(json.loads(registry.stdout), required)
    print(f"Executing all {len(names)} registered native tests", flush=True)
    result = subprocess.run(
        [
            "ctest", "--test-dir", str(build), "--output-on-failure",
            "--timeout", "1800", "--no-tests=error", "--output-junit", str(results),
        ],
        check=False,
    )
    if result.returncode:
        return result.returncode if result.returncode > 0 else 1
    count = verify_results(results, names)
    summary.write_text(
        json.dumps({"registered": len(names), "executed": count, "passed": True}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(f"Native CTest coverage verified: {count}/{len(names)} executed successfully")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    args = parser.parse_args()
    try:
        return run_suite(args.build_dir)
    except (OSError, ValueError, subprocess.SubprocessError, ET.ParseError) as error:
        print(f"Native test coverage failure: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
