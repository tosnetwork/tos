#!/usr/bin/env python3
"""Compile mutations of the consensus roster authority and require named failures.

seat_consensus_roster is the boundary that makes the authenticated committee the
roster a P0-active session seats. Each rule it enforces has a case built to
notice its removal:

  * an active session with no committee is a refusal, never the historical set;
  * an active session seats the committee, not the historical set;
  * a released session seats nothing.

A mutation that only breaks compilation, or crashes, does not count. Each must
fail a named behavioural assertion, and the baseline is restored afterwards.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from mutation_support import replace_once

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "validator/auth/consensus-roster.cpp"
TARGET = "test-p0-consensus-roster-mutant"

MUTATIONS = [
    # An active session with no committee falls back to the historical set.
    # This is the fallback the design forbids: a security refusal becoming a
    # bypass. The refusal case must notice.
    ("active-no-session-refused", "active_without_a_session_is_refused",
     '  if (!owner)\n    return Error{"consensus-roster-unauthenticated"};',
     '  if (!owner)\n    return ConsensusRoster::historical(historical);'),
    # An active session seats the historical set instead of the committee. The
    # positive case pins that the members come from the committee.
    ("active-seats-committee", "authenticated_roster_is_the_committee",
     "  return ConsensusRoster::authenticated(*owner);",
     "  (void)owner;\n  return ConsensusRoster::historical(historical);"),
    # The authenticated roster is built from the historical set's members
    # rather than the committee's transport order.
    ("committee-transport-order", "authenticated_roster_is_the_committee",
     "context.value()->committee().transport_order(),",
     "std::vector<tos::ValidatorDescr>{},"),
    # A released session is refused with a different, weaker code, so the exact
    # "session-released" contract the release case asserts is broken without a
    # crash.
    ("released-session-code", "a_released_session_seats_nothing",
     "  if (!context.ok())\n    return context.error();",
     '  if (!context.ok())\n    return Error{"consensus-roster-released"};'),
    # The adapter must carry the committee's catchain, not a zero/default. The
    # preserve case pins the catchain against the committee. (The adapter's
    # released refusal is the roster's released guard one layer down, already
    # covered by released-session-code above.)
    ("adapter-catchain", "authenticated_validator_set_preserves_the_committee",
     "return td::make_ref<block::ValidatorSet>(roster.value().catchain(), shard,",
     "return td::make_ref<block::ValidatorSet>(roster.value().catchain() + 1, shard,"),
]


def build(build_dir: Path) -> bool:
    return subprocess.run(["cmake", "--build", str(build_dir), "--target", TARGET, "-j8"],
                          capture_output=True, text=True, check=False).returncode == 0


def run(build_dir: Path, owner: Path, committee: Path, work: Path) -> subprocess.CompletedProcess:
    binary = build_dir / "validator/auth" / TARGET
    return subprocess.run([str(binary), str(owner.resolve()), str(committee.resolve()), str(work.resolve())],
                          capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=Path("build-p0"))
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    report = []
    try:
        if not build(args.build):
            print("BASELINE-BUILD-FAILED", file=sys.stderr)
            return 1
        baseline = run(args.build, args.owner, args.committee, args.work / "baseline")
        if baseline.returncode != 0:
            print("BASELINE-NOT-PASSING", file=sys.stderr)
            print(baseline.stdout + baseline.stderr, file=sys.stderr)
            return 1

        for guard, case, before, after in MUTATIONS:
            SOURCE.write_text(replace_once(original, before, after))
            edited = SOURCE.read_text() != original
            compiled = build(args.build)
            result = run(args.build, args.owner, args.committee, args.work / guard) if compiled else None
            verdict = [line for line in (result.stderr.splitlines() if result else []) if line.startswith("ASSERTION")]
            SOURCE.write_text(original)
            entry = {
                "guard": guard, "case": case, "edit_reached_source": edited, "compiled": compiled,
                "named_assertion_failed": verdict == ["ASSERTION: " + case],
                "source_unchanged": SOURCE.read_text() == original,
            }
            report.append(entry)
            if not (entry["edit_reached_source"] and entry["compiled"]
                    and entry["named_assertion_failed"] and entry["source_unchanged"]):
                print(json.dumps(entry), file=sys.stderr)
                print("SURVIVED-OR-MISNAMED", file=sys.stderr)
                return 1
            print("KILLED:", guard, "--", case, flush=True)
    finally:
        SOURCE.write_text(original)
        build(args.build)

    restored = SOURCE.read_text() == original and build(args.build)
    args.out.write_text(json.dumps({"consensus_roster_mutations": report, "restored_baseline": restored},
                                   indent=1) + "\n")
    return 0 if restored else 1


if __name__ == "__main__":
    sys.exit(main())
