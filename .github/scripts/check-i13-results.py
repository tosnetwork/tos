#!/usr/bin/env python3
"""Fail closed on missing, skipped, duplicate or unsuccessful private checks."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

EXPECTED = {
    "test-workchain-construction-isolation-gates",
    "test-workchain-i13-acceptance-gates",
    "test-workchain-i13-usage-acceptance-gates",
    "test-workchain-execution-ledger-gates",
}


def check(mode, path, repository):
    if mode == "registered":
        tests = json.loads(path.read_text())["tests"]
        names = [test["name"] for test in tests]
        for test in tests:
            command = test.get("command", [])
            driver = test["name"].removeprefix("test-").removesuffix("-gates") + ".py"
            expected_driver = repository / "crypto" / "test" / driver
            if len(command) < 2 or Path(command[1]).resolve() != expected_driver.resolve():
                raise ValueError(f"wrong driver for {test['name']}: {command!r}")
    elif mode == "executed":
        root = ET.parse(path).getroot()
        tests = list(root.iter("testcase"))
        names = [test.attrib["name"] for test in tests]
        for test in tests:
            if test.get("status") != "run" or any(
                test.find(tag) is not None for tag in ("skipped", "failure", "error")
            ):
                raise ValueError(f"not successfully run: {ET.tostring(test, encoding='unicode')}")
    else:
        raise ValueError(f"unknown mode: {mode}")
    if len(names) != 4 or set(names) != EXPECTED:
        raise ValueError(f"expected exactly four named checks, observed {names!r}")
    print(f"{mode}: exactly 4 private I13 checks: {sorted(names)}")


if __name__ == "__main__":
    repository = Path(sys.argv[3]) if len(sys.argv) == 4 else Path(__file__).resolve().parents[2]
    check(sys.argv[1], Path(sys.argv[2]), repository)
