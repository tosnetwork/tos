#!/usr/bin/env python3
"""Recompile selection regressions and require the intended sandbox assertion to fail."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/smartcont/elector-code.fc"
CONDITION = "if (failed & (failed_inputs == inputs_hash))"
RETRY = "security_audit::a_failed_selection_retries_after_each_decisive_configuration_change"
MUTATIONS = [
    (
        "capped-principal",
        [
            ("int refund = original_stake;", "int refund = stake;"),
            ("throw_unless(63, total_placed == tot_stake + total_refunded);", "throw_unless(63, true);"),
        ],
        "security_audit::over_cap_principal_is_conserved_for_winners_losers_and_shared_owners",
        "owner principal not conserved",
    ),
    ("permanent-failure", [(CONDITION, "if (failed)")], RETRY, "configuration 16 changed"),
    *[
        (
            f"omit-config-{parameter}",
            [(f".store_dict(config_param({parameter}))", ".store_dict(null())")],
            RETRY,
            f"configuration {parameter} changed",
        )
        for parameter in (16, 17, 47)
    ],
    (
        "repeat-identical-failure",
        [(CONDITION, "if (false)")],
        "security_audit::identical_failed_inputs_skip_selection_and_cancel_without_double_credit",
        "unchanged selection ran again",
    ),
]


def run(command, log):
    with log.open("w") as output:
        completed = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    generated = ROOT / "build/crypto/smartcont/auto/elector-code.fif"
    return {
        "command": command,
        "exit": completed.returncode,
        "log": str(log.relative_to(ROOT)),
        "bytes": log.stat().st_size,
        "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        "generated_fif_sha256": hashlib.sha256(generated.read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("jobs must be positive")
    destination = args.out.resolve()
    destination.relative_to(ROOT)
    destination.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_text()
    build = ["cmake", "--build", "build", "--target", "gen_fif", f"-j{args.jobs}"]
    test = [
        "cargo", "test", "--manifest-path", "tosctl/src/Cargo.toml", "-p", "contracts",
        "--locked", "--test", "elector_sandbox", f"-j{args.jobs}",
    ]
    test_source = ROOT / "tosctl/src/node-control/contracts/tests/elector_security_audit/mod.rs"
    index = {
        "source_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "test_sha256": hashlib.sha256(test_source.read_bytes()).hexdigest(),
        "runs": [],
    }
    try:
        baseline_build = run(build, destination / "baseline-compile.log")
        index["baseline_compile"] = baseline_build
        if baseline_build["exit"] != 0:
            raise RuntimeError("the baseline native build must pass")
        baseline = run(test + ["security_audit", "--", "--nocapture"], destination / "baseline.log")
        index["runs"].append({"name": "baseline", **baseline})
        if baseline["exit"] != 0:
            raise RuntimeError("the baseline must pass before any mutation")
        for name, substitutions, target, assertion in MUTATIONS:
            changed = original
            for before, after in substitutions:
                if changed.count(before) != 1:
                    raise RuntimeError(f"{name}: ambiguous or missing source anchor")
                changed = changed.replace(before, after, 1)
            SOURCE.write_text(changed)
            compile_result = run(build, destination / f"{name}-compile.log")
            if compile_result["exit"] != 0:
                index["runs"].append({"name": name, "compile": compile_result})
                raise RuntimeError(f"{name}: a compile failure is not sensitivity evidence")
            result = run(test + [target, "--", "--exact", "--nocapture"], destination / f"{name}.log")
            log = (destination / f"{name}.log").read_text()
            intended = result["exit"] == 101 and assertion in log and "running 1 test" in log
            index["runs"].append({"name": name, "compile": compile_result,
                "source_sha256": hashlib.sha256(changed.encode()).hexdigest(),
                "intended_assertion": assertion, "intended_failure": intended, **result})
            print(f"{name}: exit={result['exit']}, intended={intended}", flush=True)
            if not intended:
                raise RuntimeError(f"{name}: did not fail at the intended assertion")
    finally:
        SOURCE.write_text(original)
        restored_build = run(build, destination / "restored-compile.log")
        restored = run(test + ["security_audit", "--", "--nocapture"], destination / "restored.log")
        index["restored_compile"] = restored_build
        index["restored_test"] = restored
        index["restored_source_sha256"] = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        (destination / "index.json").write_text(json.dumps(index, indent=2) + "\n")
        if restored_build["exit"] != 0 or restored["exit"] != 0:
            raise RuntimeError("restored source/build/test did not pass")


if __name__ == "__main__":
    main()
