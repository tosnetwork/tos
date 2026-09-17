"""Compile registry persistence mutants and measure their exact case blast radius."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/smartcont/config-code.fc"
BINARY = ROOT / "build-p0/test/validator-auth-implementation/test-p0-config-contract"
FUNC = ROOT / "build-p0/crypto/func"
FIFT = ROOT / "build-p0/crypto/fift"

MUTATIONS = [
    (
        "registry-installation",
        "registry-c4-installs-parameter-46",
        "    set_conf_param(46, registry);\n",
        "    ;; registry installation removed by compiled mutation\n",
        [
            "registry-c4-replaces-old-parameter-46",
            "registry-first-checkpoint-installs-new-parameter",
            "registry-first-checkpoint-replaces-old-parameter",
            # The checkpoint case reads the installed parameter too, and has to.
            # Its claim is that the checkpoint stored is the one for the state
            # just staged rather than merely different from the stale one, and
            # comparing both against the same staged cell is what says so. A
            # mutation that stops installing the parameter therefore reaches it,
            # and that is a dependency to declare rather than an overreach to
            # narrow. The case grew that assertion after this list was last
            # written, and the job that would have said so was failing earlier.
            "a-registry-update-stores-the-staged-checkpoint",
        ],
    ),
    (
        "registry-installed-before-commit",
        "registry-first-checkpoint-installs-new-parameter",
        "    set_conf_param(46, registry);\n    commit();\n",
        "    commit();\n    set_conf_param(46, registry);\n",
        ["registry-first-checkpoint-replaces-old-parameter"],
    ),
]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)


def compile_contract(out: Path) -> bool:
    out.mkdir(parents=True, exist_ok=True)
    fif = out / "config-code.fif"
    boc = out / "config-code.boc"
    first = run([str(FUNC), "-PS", "-o", str(fif), str(ROOT / "crypto/smartcont/stdlib.fc"), str(SOURCE)])
    (out / "compile.stdout").write_text(first.stdout)
    (out / "compile.stderr").write_text(first.stderr)
    if first.returncode != 0:
        return False
    assemble = out / "assemble.fif"
    assemble.write_text(f'"Asm.fif" include\n"{fif}" include\n2 boc+>B "{boc}" B>file\n')
    second = run([str(FIFT), "-I", str(ROOT / "crypto/fift/lib"), "-s", str(assemble)])
    (out / "assemble.stdout").write_text(second.stdout)
    (out / "assemble.stderr").write_text(second.stderr)
    return second.returncode == 0 and boc.is_file() and boc.stat().st_size > 0


def invoke(boc: Path, case: str) -> subprocess.CompletedProcess[str]:
    return run([str(BINARY), str(boc), case])


def passed(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (
        result.returncode == 0
        and result.stderr == ""
        and f"CASE_PASS {case}" in result.stdout.splitlines()
        and result.stdout.splitlines()[-1:] == ["SUMMARY cases=1 passed=1"]
    )


def failed_named(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (
        result.returncode == 1
        and result.stdout.splitlines()[:1] == [f"SETUP_OK {case}"]
        and result.stderr.splitlines()[-1:] == [f"ASSERTION_FAILED {case}"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    baseline_dir = out / "baseline"
    if not compile_contract(baseline_dir):
        print("BASELINE_COMPILE_FAILED", file=sys.stderr)
        return 1
    baseline_boc = baseline_dir / "config-code.boc"
    listed = run([str(BINARY), str(baseline_boc), "--list"])
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or listed.stderr or not cases:
        print("CASE_INVENTORY_FAILED", file=sys.stderr)
        return 1
    baseline = {case: invoke(baseline_boc, case) for case in cases}
    if not all(passed(result, case) for case, result in baseline.items()):
        print("BASELINE_NOT_PASSING", file=sys.stderr)
        return 1

    records = []
    failures = 0
    try:
        for guard, named_case, before, after, declared in MUTATIONS:
            current = SOURCE.read_text()
            if current != original or current.count(before) != 1:
                print(f"ANCHOR_NOT_UNIQUE {guard} {current.count(before)}", file=sys.stderr)
                failures += 1
                continue
            changed = current.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            mutant_dir = out / guard
            compiled = compile_contract(mutant_dir)
            observed = []
            results = {}
            if compiled:
                boc = mutant_dir / "config-code.boc"
                for case in cases:
                    result = invoke(boc, case)
                    results[case] = result
                    if not passed(result, case):
                        observed.append(case)
            named_result = results.get(named_case)
            named_failed = named_result is not None and failed_named(named_result, named_case)
            observed_companions = [case for case in observed if case != named_case]
            isolated = sorted(observed_companions) == sorted(declared)

            SOURCE.write_text(original)
            restore_dir = out / f"{guard}-restored"
            restored_compiled = compile_contract(restore_dir)
            restored = restored_compiled and all(
                passed(invoke(restore_dir / "config-code.boc", case), case) for case in cases
            )
            record = {
                "guard": guard,
                "case": named_case,
                "edit_reached_source": reached,
                "compiled": compiled,
                "named_assertion_failed": named_failed,
                "declared_companions": declared,
                "observed_companions": observed_companions,
                "only_declared_cases_broke": isolated,
                "restored_baseline": restored,
                "source_unchanged": SOURCE.read_text() == original,
                "named_returncode": None if named_result is None else named_result.returncode,
                "named_stdout": "" if named_result is None else named_result.stdout,
                "named_stderr": "" if named_result is None else named_result.stderr,
            }
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(
                record[key]
                for key in (
                    "edit_reached_source",
                    "compiled",
                    "named_assertion_failed",
                    "only_declared_cases_broke",
                    "restored_baseline",
                    "source_unchanged",
                )
            ):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
