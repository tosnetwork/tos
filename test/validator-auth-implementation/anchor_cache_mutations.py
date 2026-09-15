"""Remove one guard of the node-lifetime anchor cache at a time.

This cache is consulted instead of the archive, so a guard that can be removed
without a named case failing is a guard nothing depends on. Each mutation must
compile, reach the file, and fail its own named case. The history-resolution
queue shares this boundary and runs its own isolated mutation harness afterwards.
The frozen-manager source binding is checked here too so the tested queue cannot
be left unused after the temporary focused workflow is gone.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/native-anchor-cache.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-anchor-cache")

MUTATIONS = [
    ("coordinate-binding", "misfiled-anchor-refused",
     '  if (anchor.seqno_ != at)\n    return Error{"anchor-cache-binding"};',
     ''),
    ("complete-anchor", "incomplete-anchor-refused",
     '  if (anchor.root_ == Hash{} || anchor.file_ == Hash{} || anchor.state_ == Hash{})\n'
     '    return Error{"anchor-cache-incomplete"};',
     ''),
    ("conflict-refusal", "conflicting-answer-refused",
     '  if (found != anchors_.end())\n'
     '    return found->second == anchor ? Result<bool>(true) : Result<bool>(Error{"anchor-cache-conflict"});',
     '  if (found != anchors_.end()) {\n'
     '    anchors_.erase(found);\n'
     '  }'),
    ("growth-bound", "cache-stays-bounded",
     '  while (anchors_.size() > limit_)\n    anchors_.erase(anchors_.begin());',
     ''),
    # The completeness check is asserted by two cases; this names the one the
    # suite stops on first, since a mutation that fails a different case is
    # not evidence about the case it was aimed at.
    ("complete-set", "empty-cache-is-entirely-missing",
     '    if (found == anchors_.end())\n      return Error{"anchor-cache-incomplete-set"};',
     '    if (found == anchors_.end())\n      continue;'),
]


def build() -> bool:
    return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-anchor-cache", "-j48"],
                          capture_output=True, text=True, check=False).returncode == 0


def run() -> subprocess.CompletedProcess:
    return subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    if run().returncode != 0:
        print("BASELINE-NOT-PASSING")
        return 1

    records, failures = [], 0
    for guard, case, before, after in MUTATIONS:
        if original.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})")
            failures += 1
            continue
        SOURCE.write_text(original.replace(before, after, 1))
        reached = before not in SOURCE.read_text()
        compiled = build()
        named = False
        if compiled:
            result = run()
            named = result.returncode != 0 and case in (result.stderr + result.stdout)
        SOURCE.write_text(original)
        restored = build() and run().returncode == 0
        record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                  "named_assertion_failed": named, "restored_baseline": restored,
                  "source_unchanged": SOURCE.read_text() == original}
        records.append(record)
        print(json.dumps(record))
        if not all(record[k] for k in ("edit_reached_source", "compiled", "named_assertion_failed",
                                       "restored_baseline", "source_unchanged")):
            failures += 1

    queue_out = args.out / "history-resolution-queue"
    queue = subprocess.run(
        [sys.executable, "test/validator-auth-implementation/history_resolution_queue_mutations.py", str(queue_out)],
        capture_output=True, text=True, check=False)
    (args.out / "history-resolution-queue.log").write_text(
        f"exit_code={queue.returncode}\n--- stdout ---\n{queue.stdout}--- stderr ---\n{queue.stderr}")
    if queue.returncode != 0:
        failures += 1

    wiring = subprocess.run(
        [sys.executable, "test/validator-auth-implementation/check_history_resolution_queue_wiring.py"],
        capture_output=True, text=True, check=False)
    (args.out / "history-resolution-queue-wiring.log").write_text(
        f"exit_code={wiring.returncode}\n--- stdout ---\n{wiring.stdout}--- stderr ---\n{wiring.stderr}")
    if wiring.returncode != 0:
        failures += 1

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
