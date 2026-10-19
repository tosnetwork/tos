"""Check complete result rows against intended outcomes and exact cross-VM parity.

Usage: compare.py <scenarios.tsv> <cpp.tsv> <rust.tsv> [frozen-expected.tsv]
"""

import sys
from pathlib import Path


def read(path, fields):
    rows = [line.split("\t") for line in Path(path).read_text().splitlines()]
    assert rows and all(len(row) == fields for row in rows), f"invalid rows: {path}"
    assert len({row[0] for row in rows}) == len(rows), f"duplicate ids: {path}"
    return rows


def main(scenarios, cpp, rust, expected=None):
    inputs = read(scenarios, 9)
    outputs = [read(cpp, 4), read(rust, 4)]
    ids = [row[0] for row in inputs]
    for path, rows in zip((cpp, rust), outputs):
        assert [row[0] for row in rows] == ids, f"missing/reordered/extra rows: {path}"
        for scenario, row in zip(inputs, rows):
            name, exit_code, gas, result = row
            actual = (int(exit_code), int(result))
            outcome = scenario[3]
            want = (
                (0, -1) if outcome == "V" else (0, 0) if outcome == "I" else (int(outcome[1:]), 99)
            )
            assert actual == want, f"{path}: {name}: expected {want}, got {actual}"
            assert int(gas) > 0, f"{path}: {name}: missing gas charge"
    assert outputs[0] == outputs[1], "C++/Rust exit, gas or result mismatch"
    if expected is not None:
        assert outputs[0] == read(expected, 4), "frozen exit, gas or result mismatch"
    print(f"PASS: {len(inputs)} expected outcomes and exact C++/Rust rows")


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("assertion-enabled Python is required")
    main(*sys.argv[1:])
