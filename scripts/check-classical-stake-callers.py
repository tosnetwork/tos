#!/usr/bin/env python3
"""Inventory retained literal Fift election-tool dependencies.

This is deliberately narrower than "all classical stake producers": it
discovers references to the two base Fift tools and their library word in
executable source files. Rust legacy vectors and prose are not callers.
"""

from __future__ import annotations

import sys
from pathlib import Path

MARKERS = (
    "validator-elect-req.fif",
    "validator-elect-signed.fif",
    "validator-elect-req>B",
)
EXPECTED: dict[str, dict[str, int]] = {
    "crypto/smartcont/validator-elect-req.fif": {"validator-elect-req>B": 1},
    "crypto/smartcont/validator-elect-signed.fif": {"validator-elect-req>B": 1},
    "crypto/fift/lib/Validator.fif": {
        "validator-elect-signed.fif": 1,
        "validator-elect-req>B": 1,
    },
    "crypto/smartcont/single-nominator-pool/validator-elect-signed.fif": {
        "validator-elect-req>B": 1,
    },
    "crypto/smartcont/liquid-staking/controller-elect-signed.fif": {
        "validator-elect-req>B": 1,
    },
    "crypto/test/test-smartcont.cpp": {
        "validator-elect-req.fif": 1,
        "validator-elect-signed.fif": 2,
    },
    "crypto/test/fift/validator-proposal-test.fif": {"validator-elect-req>B": 1},
    "crypto/test/fift/validator-proposal-legacy-parity.fif": {
        "validator-elect-req>B": 1,
    },
}
SUFFIXES = {".py", ".fif", ".fc", ".cpp", ".rs"}
# This source guard quotes the retired Fift filenames to forbid their use in
# Stage A; it is not an executable Fift caller. Exclude only this known guard
# so an unrelated new script containing the literal still fails the inventory.
NON_CALLER_SOURCE_GUARDS = {
    "scripts/check-pq-election-fixture-source.py",
    # This guard quotes the retired names only to forbid them in the
    # multi-nominator lifecycle route; it does not invoke either Fift tool.
    "scripts/check-nominator-pool-pq-route.py",
}


def fail(message: str) -> None:
    raise RuntimeError(f"CLASSICAL_STAKE_CALLERS_FAILURE: {message}")


def discover(root: Path) -> dict[str, dict[str, int]]:
    found = {}
    for directory in ("crypto", "scripts", "tosctl/src"):
        for path in (root / directory).rglob("*"):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            if relative == "scripts/check-classical-stake-callers.py" or relative in NON_CALLER_SOURCE_GUARDS:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            matches = {marker: source.count(marker) for marker in MARKERS if marker in source}
            if matches:
                found[relative] = matches
    return found


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else Path(__file__).resolve().parents[1]
    actual = discover(root)
    missing = sorted(set(EXPECTED) - set(actual))
    unexpected = sorted(set(actual) - set(EXPECTED))
    wrong = {
        path: {"expected": EXPECTED[path], "actual": actual[path]}
        for path in sorted(set(EXPECTED) & set(actual))
        if actual[path] != EXPECTED[path]
    }
    if missing or unexpected or wrong:
        fail(f"literal Fift caller inventory changed: missing={missing} unexpected={unexpected} wrong={wrong}")
    document = (root / "doc/pq-native/T2-PQ-LAUNCH-GATE-MIGRATION.md").read_text()
    undocumented = sorted(path for path in EXPECTED if f"`{path}`" not in document)
    if undocumented:
        fail(f"retained literal Fift callers absent from migration map: {undocumented}")
    print(
        f"CLASSICAL_STAKE_CALLERS_OK: {len(EXPECTED)} exact executable files retain the inventoried "
        "validator-elect Fift path/word literals; the migration map names each"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
