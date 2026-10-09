#!/usr/bin/env python3
"""Check that a CTest selection names exactly the tests it is meant to run.

`ctest --no-tests=error` refuses an empty selection, but a regex or label
selection that silently loses one of several tests still runs the rest and
passes. This compares the registered tests with a pinned expectation before
anything runs.

  --label L --exact NAME...   the tests carrying label L are exactly NAME...
  --expected-file F           every name in F (one per line) is registered, and
                              the anchored regex built from F selects exactly
                              that many tests; with --print-regex the regex is
                              printed on success for the caller to run.

Standard library only: it runs on a bare CI runner before anything is installed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


class InventoryError(Exception):
    pass


def registered(build_dir: Path, *selection: str) -> list[str]:
    command = ["ctest", "--test-dir", str(build_dir), "--show-only=json-v1", *selection]
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise InventoryError(f"{' '.join(command)} failed: {error}") from error
    try:
        tests = json.loads(completed.stdout)["tests"]
    except (ValueError, KeyError) as error:
        raise InventoryError(f"cannot read the ctest test list: {error}") from error
    return [test["name"] for test in tests]


def read_expected(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InventoryError(f"cannot read {path}: {error}") from error
    names = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    if not names:
        raise InventoryError(f"{path} names no test")
    if len(set(names)) != len(names):
        raise InventoryError(f"{path} names a test twice")
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise InventoryError(f"{path}: {name!r} is not a plain test name")
    return names


def selection_regex(names: list[str]) -> str:
    # Names are limited to [A-Za-z0-9_.+-], so only '.' and '+' need escaping for CTest.
    return "^(" + "|".join(re.sub(r"([.+])", r"\\\1", name) for name in names) + ")$"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--label")
    parser.add_argument("--exact", nargs="+")
    parser.add_argument("--expected-file", type=Path)
    parser.add_argument("--print-regex", action="store_true")
    args = parser.parse_args()

    try:
        if args.label is not None:
            if not args.exact or args.expected_file is not None:
                raise InventoryError("--label needs --exact and excludes --expected-file")
            actual = sorted(registered(args.build_dir, "-L", args.label))
            if actual != sorted(args.exact):
                raise InventoryError(
                    f"label {args.label} selects {actual}, expected exactly {sorted(args.exact)}"
                )
            print(f"label {args.label} selects exactly {actual}", file=sys.stderr)
            return 0
        if args.expected_file is None:
            raise InventoryError("give --label or --expected-file")
        expected = read_expected(args.expected_file)
        actual = set(registered(args.build_dir))
        missing = sorted(set(expected) - actual)
        if missing:
            raise InventoryError(f"expected tests are not registered: {missing}")
        regex = selection_regex(expected)
        selected = registered(args.build_dir, "-R", regex)
        if sorted(selected) != sorted(expected):
            raise InventoryError(f"{regex} selects {sorted(selected)}, expected {sorted(expected)}")
        print(f"all {len(expected)} expected tests are registered and selected", file=sys.stderr)
        if args.print_regex:
            print(regex)
        return 0
    except InventoryError as error:
        print(f"CTEST_INVENTORY_FAILURE: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
