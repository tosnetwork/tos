#!/usr/bin/env python3
"""Red-before controls for checking imported wallet-index history.

Each mutation restores an earlier, weaker rule in the lineage check: a creation
treated as complete history, one global window bound instead of each shard's
own, rows accepted without hash links, a head not anchored in the checked
state, or a history cut inside the window. The named tests must fail with the
mutation and pass again once the source is restored. The source is restored in
`finally` and its hash is checked.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "validator-engine/wallet-index-lineage.cpp"
TARGET = "test-wallet-index"

MUTATIONS = [
    (
        "absent-and-empty-is-verified",
        "  if (!head) {\n",
        '  if (!head) {\n    if (links.empty()) {\n      return {LineageVerdict::OutsideWindow, ""};\n    }\n',
        ["OmittedHistoryOfAnAbsentAccountNeedsBlocks"],
    ),
    (
        "creation-is-complete",
        """      return {LineageVerdict::NeedsBlocks, i + 1 < links.size() ? "rows precede an account creation in the window"
                                                                : "history starts inside the window"};""",
        '      return {LineageVerdict::Complete, ""};',
        [
            "RecreatedAccountWithoutItsFirstIncarnationNeedsBlocks",
            "AccountCreatedInTheWindowNeedsBlocks",
        ],
    ),
    (
        "global-highest-bound",
        "  return bound.value();\n}",
        "  uint64_t global = 0;\n  for (const auto& tip : tips) {\n    global = std::max(global, tip.end_lt);\n  }\n"
        "  return global;\n}",
        ["WindowBoundFollowsEachShardUnderSkewedProgress"],
    ),
    (
        "global-lowest-bound",
        "  return bound.value();\n}",
        "  uint64_t global = bound.value();\n  for (const auto& tip : tips) {\n"
        "    global = std::min(global, tip.end_lt);\n  }\n  return global;\n}",
        ["WindowBoundFollowsEachShardUnderSkewedProgress"],
    ),
    (
        "unlinked-rows",
        "    if (next.lt != link.prev_lt || next.hash != link.prev_hash) {",
        "    if (false) {",
        ["TamperedRowIsRefused", "OmittedMiddleRowIsRefused"],
    ),
    (
        "unanchored-head",
        "  if (links.front().lt != head.value().last_trans_lt || links.front().hash != head.value().last_trans_hash) {",
        "  if (false) {",
        ["TamperedNewestRowIsRefused"],
    ),
    (
        "truncation-accepted",
        '      return refused("history is truncated inside the window");',
        '      return {LineageVerdict::Complete, ""};',
        ["TruncatedInWindowHistoryIsRefused"],
    ),
]


def build(build_dir: Path, jobs: int, log: Path) -> None:
    with log.open("ab") as out:
        subprocess.run(
            ["cmake", "--build", str(build_dir), "--target", TARGET, "-j", str(jobs)],
            check=True,
            stdout=out,
            stderr=subprocess.STDOUT,
        )


def run(build_dir: Path, test: str) -> tuple[int, str]:
    result = subprocess.run(
        [str(build_dir / TARGET), "--filter", "WalletIndexLineage_" + test],
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return result.returncode, result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    log = build_dir / "wallet-index-lineage-controls.log"
    log.write_bytes(b"")
    original = SOURCE.read_bytes()
    original_sha = hashlib.sha256(original).hexdigest()
    results = []
    failed = False
    build(build_dir, args.jobs, log)
    for _, _, _, tests in MUTATIONS:
        for test in tests:
            status, output = run(build_dir, test)
            if status != 0 or "FAIL" in output:
                print(f"baseline test {test} does not pass:\n{output}", file=sys.stderr)
                return 1
    try:
        for name, before, after, tests in MUTATIONS:
            text = original.decode()
            if text.count(before) != 1:
                raise RuntimeError(f"mutation {name}: anchor is not unique")
            SOURCE.write_text(text.replace(before, after, 1))
            build(build_dir, args.jobs, log)
            for test in tests:
                status, output = run(build_dir, test)
                red = status != 0
                results.append({"mutation": name, "test": test, "exit_status": status, "red": red})
                if not red:
                    failed = True
                    print(f"mutation {name} left {test} passing:\n{output}", file=sys.stderr)
            SOURCE.write_bytes(original)
    finally:
        SOURCE.write_bytes(original)
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != original_sha:
        raise RuntimeError("lineage source was not restored")
    build(build_dir, args.jobs, log)
    for _, _, _, tests in MUTATIONS:
        for test in tests:
            status, output = run(build_dir, test)
            results.append(
                {"mutation": "restored", "test": test, "exit_status": status, "red": status != 0}
            )
            if status != 0:
                failed = True
                print(f"restored source fails {test}:\n{output}", file=sys.stderr)
    print(json.dumps({"source_sha256": original_sha, "results": results}, indent=2))
    if failed:
        return 1
    print("WALLET_INDEX_LINEAGE_CONTROLS_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
