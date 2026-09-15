"""Compile adoption mutants and require isolated named failures.

Each mutation edits the copy of a production module that the mutant target
compiles, never the module the rest of the build uses, so a surviving edit
cannot leak into anything else.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tosctl/src/block/src/tests/data/config.boc"

# (guard, case, module, before, after, declared companions)
MUTATIONS = [
    (
        "registry-magic-admitted",
        "a-refused-shape-reaches-no-reader",
        "validator-auth-config",
        "      root.fetch_ulong(32) != 0x76617131 || root.fetch_ulong(16) != 1)\n",
        "      root.fetch_ulong(32) == 0xffffffff || root.fetch_ulong(16) != 1)\n",
        [],
    ),
    (
        "transition-domain-checked",
        "a-refused-transition-is-not-a-setup-failure",
        "validator-auth-config",
        '  if (old.domain != next.domain)\n    return td::Status::Error("validator-auth-domain");\n',
        "",
        [],
    ),
    (
        "registry-change-is-important",
        "a-registry-change-is-an-important-change",
        "block",
        '  // for now, all parameters are "important"\n'
        "  // at least the parameters affecting the computations of validator sets must be considered important\n"
        "  // ...\n"
        "  return true;\n",
        "  return false;\n",
        [],
    ),
]


def invoke(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)


def build(tree: Path, target: str) -> bool:
    return invoke(["cmake", "--build", str(tree), "--target", target, "-j48"]).returncode == 0


def run(binary: Path, case: str | None = None) -> subprocess.CompletedProcess[str]:
    command = [str(binary), str(FIXTURE)]
    if case:
        command.append(case)
    return invoke(command)


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (result.returncode == 0 and result.stderr == "" and
            lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"] and
            sum(line.startswith("CASE_PASS ") for line in lines) == expected)


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    if result.returncode != 1 or result.stdout.splitlines() != [f"SETUP_OK {case}"]:
        return False
    errors = result.stderr.splitlines()
    return (len(errors) == 2 and errors[0].startswith(f"DETAIL {case} ") and
            errors[1] == f"ASSERTION_FAILED {case}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build-p0")
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    tree = arguments.build
    binaries = tree / "test/validator-auth-implementation"
    arguments.out.parent.mkdir(parents=True, exist_ok=True)

    if not build(tree, "test-p0-config-adoption"):
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    baseline = binaries / "test-p0-config-adoption"
    listed = invoke([str(baseline), "--list"])
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or not cases:
        print("CASE-INVENTORY-FAILED", file=sys.stderr)
        return 1
    if not passing(run(baseline), len(cases)):
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1

    records: list[dict[str, object]] = []
    failures = 0
    for guard, case, module, before, after, companions in MUTATIONS:
        target = f"test-p0-config-adoption-{module}-mutant"
        # The mutant target compiles this copy; the shipped module is untouched.
        source = binaries / f"config-adoption-{module}-mutated.cpp"
        if not build(tree, target):
            print(f"MUTANT-BASELINE-BUILD-FAILED {guard}", file=sys.stderr)
            failures += 1
            continue
        original = source.read_text()
        if original.count(before) != 1:
            print(f"ANCHOR-NOT-UNIQUE {guard} ({original.count(before)})", file=sys.stderr)
            failures += 1
            continue
        changed = original.replace(before, after, 1)
        source.write_text(changed)
        reached = source.read_text() == changed
        compiled = build(tree, target)
        mutant = binaries / target
        named = False
        observed: list[str] = []
        if compiled:
            named = named_failure(run(mutant, case), case)
            # Every other case on its own: a combined run stops at the first
            # failure and hides whether the rest still hold.
            observed = [name for name in cases if name != case and not passing(run(mutant, name), 1)]
        source.write_text(original)
        restored = build(tree, target) and passing(run(binaries / target), len(cases))
        record = {
            "guard": guard,
            "case": case,
            "module": module,
            "declared_companions": sorted(companions),
            "observed_companions": observed,
            "edit_reached_source": reached,
            "compiled": compiled,
            "named_assertion_failed": named,
            "only_declared_cases_broke": sorted(observed) == sorted(companions),
            "restored_baseline": restored,
            "source_unchanged": source.read_text() == original,
        }
        records.append(record)
        print(json.dumps(record), flush=True)
        if not all(record[key] for key in ("edit_reached_source", "compiled", "named_assertion_failed",
                                           "only_declared_cases_broke", "restored_baseline", "source_unchanged")):
            failures += 1

    arguments.out.write_text(json.dumps(records, indent=2) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
