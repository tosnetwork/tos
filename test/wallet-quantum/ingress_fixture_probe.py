"""Replay actual fee envelope fixtures and explicit byte/depth boundaries at node parsing."""

import argparse
import json
import platform
import statistics
import subprocess
from pathlib import Path

from admission_envelope_probe import padded, replace_signature
from admission_forgery_timing import select_routes
from benchmark_transactions import fingerprint
from fee_tx_parity import Cell, from_boc


def deep(message, depth):
    tail = Cell()
    for index in range(depth - 4):
        # Populate cached hash/depth bottom-up, avoiding Python recursion limits.
        tail.hash
        tail = Cell().uint(index, 32).ref(tail)
    tail.hash
    result = replace_signature(message, tail)
    if result.depth != depth:
        raise ValueError("fixture depth mismatch")
    return result


def check(text, expected, iterations):
    rows = text.splitlines()
    if len(rows) != len(expected) or not rows:
        raise ValueError("missing parser results")
    results = []
    for row, case in zip(rows, expected, strict=True):
        fields = row.split("\t")
        if len(fields) != 5 or fields[0] != case["name"]:
            raise ValueError("parser result alignment mismatch")
        status, reason, root = fields[1:4]
        reason = bytes.fromhex(reason).decode() if reason != "-" else ""
        if status != case["status"] or reason != case["reason"]:
            raise ValueError(f"parser boundary mismatch: {case['name']}: {status}: {reason}")
        if root != case["root"]:
            raise ValueError("parser returned a different message root")
        samples = [int(value) for value in fields[4].split(",")]
        if len(samples) != iterations or any(value <= 0 for value in samples):
            raise ValueError("missing parser timings")
        results.append({**case, "samples_ns": samples, "median_ns": statistics.median(samples)})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--envelopes", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.envelopes / "20000/fixtures/scenarios.tsv"
    rows = [line.split("\t") for line in source.read_text().splitlines()]
    if len(rows) != 15:
        raise ValueError("expected all three envelope classes and their size controls")
    for kind, original in sorted(select_routes(args.fixtures).items()):
        message = from_boc(bytes.fromhex(original[4]))
        variants = [("bytes-65536", padded(message, 1024, 65536))]
        variants += [(f"depth-{depth}", deep(message, depth)) for depth in (511, 512, 513)]
        for name, candidate in variants:
            rows.append(
                [f"class-{kind}-{name}", *original[1:4], candidate.boc().hex(), original[5]]
            )
    expected = []
    for row in rows:
        message_bytes = bytes.fromhex(row[4])
        message = from_boc(message_bytes)
        # Warm the deep cell chain's cached properties iteratively.
        visited, stack = [], [message]
        while stack:
            cell = stack.pop()
            visited.append(cell)
            stack.extend(cell.refs)
        for cell in reversed(visited):
            cell.hash
        reason = (
            "external message too large, rejecting"
            if len(message_bytes) > 65535
            else "external message is too deep"
            if message.depth >= 512
            else ""
        )
        expected.append(
            {
                "name": row[0],
                "bytes": len(message_bytes),
                "depth": message.depth,
                "status": "reject" if reason else "ok",
                "reason": reason,
                "root": "-" if reason else message.hash.hex(),
            }
        )
    scenarios = args.output / "scenarios.tsv"
    scenarios.write_text("\n".join("\t".join(row) for row in rows) + "\n")
    result = subprocess.run(
        [str(args.driver.resolve()), str(scenarios), str(args.iterations)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    (args.output / "driver.log").write_text(result.stderr)
    (args.output / "driver.tsv").write_text(result.stdout)
    if result.returncode:
        raise ValueError(f"native parser driver failed: {result.returncode}")
    results = check(result.stdout, expected, args.iterations)
    (args.output / "results.json").write_text(
        json.dumps(
            {
                "scope": "Actual node structural parser only; no masterchain state, wallet authentication or network transport",
                "timing_scope": "create_ext_message call only; input buffer copy and returned object cleanup excluded; sequential warm-cache samples",
                "platform": platform.platform(),
                "iterations": args.iterations,
                "warmups": 3,
                "results": results,
                "driver": fingerprint(args.driver),
                "source_envelopes": fingerprint(source),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"{len(results)} structural parser fixtures checked; wallet authorization not implied")


if __name__ == "__main__":
    main()
