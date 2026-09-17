"""Compile removals in the startup admission decision; require named failures.

The decision is four lines long and it decides whether a chain starts. Each of
those lines is a condition somebody could read as redundant:

    the deferral, without which a pass runs that nothing asked for -- and a pass
    that nothing asked for retires the live groups it does not recreate and
    fences their session ids;

    the cleanup barrier, without which a group can be created before the records
    that say which consensus directories may be deleted;

    the context, without which the committee the group would run under cannot be
    derived at all;

    and clearing the deferral, without which every later arrival drives another
    pass over groups that already exist.

The retry beside them is two lines and decides whether a node that lost one read
ever validates again. So each is removed here, and the case built for it has to
notice. Each mutation is named for the first case that fails without it, because
the suite stops at its first failure and that name is what it prints.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from mutation_support import replace_once

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "validator/auth/manager-group-admission.h"
SOURCE = ROOT / "validator/auth/manager-group-admission.cpp"

MUTATIONS = [
    # A pass driven with nothing deferred. The case that says what happens with
    # nothing deferred runs first for this reason: left later, the deferral and
    # its clearing below both fail the same case and read as one rule.
    ("a-node-that-refused-nothing-drives-no-pass", HEADER, "!deferred_ || ", ""),
    # A group created before the records that own its directory.
    ("an-early-context-creates-nothing-before-the-records", HEADER, "!cleanup_loaded_ || ", ""),
    # A group admitted with no context to derive its committee from.
    ("neither-condition-alone-creates-a-group", HEADER, " || !context", ""),
    # The deferral surviving the pass it drove, so the next arrival drives
    # another one over groups that now exist.
    ("the-late-context-creates-the-groups-it-refused", HEADER,
     "    deferred_ = false;\n    return true;", "    return true;"),
    # A retry that never grows: the archive that just failed is asked again at
    # the same rate, for as long as it keeps failing.
    ("a-failed-read-is-asked-again", SOURCE, "return std::min(previous * 2.0, chain_context_retry_ceiling);",
     "return chain_context_retry_floor;"),
    # And one that grows without a ceiling, which is a stall nobody is waiting
    # for dressed as patience.
    ("a-failed-read-is-asked-again", SOURCE, "std::min(previous * 2.0, chain_context_retry_ceiling)",
     "previous * 2.0"),
]

TARGET = "test-p0-group-admission-mutant"


def build(tree: Path) -> bool:
    return subprocess.run(["cmake", "--build", str(tree), "--target", TARGET, "-j8"],
                          capture_output=True, text=True, check=False).returncode == 0


def run(tree: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(tree / "test/validator-auth-implementation" / TARGET)],
                          capture_output=True, text=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=Path("build-p0"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    tree = args.build.resolve()

    pristine = {path: path.read_text() for path in {HEADER, SOURCE}}
    report = []
    try:
        if not build(tree):
            print("BASELINE-BUILD-FAILED", file=sys.stderr)
            return 1
        baseline = run(tree)
        if baseline.returncode != 0:
            print("BASELINE-NOT-PASSING", file=sys.stderr)
            print(baseline.stdout + baseline.stderr, file=sys.stderr)
            return 1

        for label, path, before, after in MUTATIONS:
            path.write_text(replace_once(pristine[path], before, after))
            edited = path.read_text() != pristine[path]
            compiled = build(tree)
            result = run(tree) if compiled else None
            verdict = [line for line in (result.stderr.splitlines() if result else []) if line.startswith("ASSERTION")]
            path.write_text(pristine[path])
            entry = {
                "guard": label,
                "source": str(path.relative_to(ROOT)),
                "removed": before.strip(),
                "edit_reached_source": edited,
                "compiled": compiled,
                "assertion_failed": bool(result and result.returncode != 0),
                "named_assertion": verdict == ["ASSERTION: " + label],
            }
            report.append(entry)
            if not (entry["edit_reached_source"] and entry["compiled"] and entry["named_assertion"]):
                print(json.dumps(entry), file=sys.stderr)
                print("SURVIVED-OR-MISNAMED", file=sys.stderr)
                return 1
            print("KILLED:", label, "--", before.strip()[:48], flush=True)
    finally:
        for path, text in pristine.items():
            path.write_text(text)
        build(tree)

    restored = all(path.read_text() == text for path, text in pristine.items())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"group_admission_mutations": report, "restored_baselines": restored},
                                   indent=1) + "\n")
    return 0 if restored else 1


if __name__ == "__main__":
    sys.exit(main())
