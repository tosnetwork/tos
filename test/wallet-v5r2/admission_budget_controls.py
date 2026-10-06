"""Require byte-budget and release controls to fail their native semantic tests."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--pool-controls", action="store_true", help="Requires full node test dependencies"
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    header = ROOT / "validator/impl/ext-message-admission-budget.hpp"
    pool = ROOT / "validator/impl/ext-message-pool.cpp"
    originals = {path: path.read_text() for path in (header, pool)}
    target = "test-ext-message-admission-budget"
    cases = [
        (
            "capacity",
            header,
            "!budget->try_reserve(bytes)",
            "(!budget->try_reserve(bytes) && false)",
            target,
            "ExtMessageAdmissionBudget_RejectsAggregateBytesBeforeCountLimit",
            "over.is_error()",
        ),
        (
            "release",
            header,
            "CHECK(budget_->release(bytes_));",
            "(void)bytes_;",
            target,
            "ExtMessageAdmissionBudget_MoveAndEarlyReturnReleaseExactlyOnce",
            "budget->used()",
        ),
    ]
    if args.pool_controls:
        cases.append(
            (
                "pool_charge",
                pool,
                "admission_budget_, data.size()",
                "admission_budget_, 0",
                "test-ext-message-pool",
                "ExtMessagePool_AdmissionByteBudgetRejectsAndReleases",
                "external message admission byte budget exhausted",
            )
        )
    for _, path, old, _, _, _, _ in cases:
        assert originals[path].count(old) == 1

    def run(label, executable, test):
        built = subprocess.run(
            ["cmake", "--build", str(args.build), "--target", executable, "-j", "2"],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        (args.output / f"{label}-build.log").write_text(built.stdout + built.stderr)
        assert built.returncode == 0, (built.stdout + built.stderr)[-4000:]
        result = subprocess.run(
            [str((args.build / executable).resolve()), "--filter", test],
            capture_output=True,
            text=True,
            timeout=60,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positives(label):
        code, log = run(label, target, "ExtMessageAdmissionBudget")
        assert code == 0 and "2 test(s) passed" in log, log
        if args.pool_controls:
            code, log = run(
                label + "-pool",
                "test-ext-message-pool",
                "ExtMessagePool_AdmissionByteBudgetRejectsAndReleases",
            )
            assert code == 0 and "1 test(s) passed" in log, log

    results = {}
    try:
        positives("baseline")
        for name, path, old, new, executable, test, witness in cases:
            path.write_text(originals[path].replace(old, new))
            code, log = run(name, executable, test)
            assert code != 0 and test in log and witness in log, log
            results[name] = {"exit": code, "test": test, "semantic_witness": witness}
            path.write_text(originals[path])
    finally:
        for path, source in originals.items():
            path.write_text(source)
        positives("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} admission byte-budget controls detected; restored tests pass")


if __name__ == "__main__":
    main()
