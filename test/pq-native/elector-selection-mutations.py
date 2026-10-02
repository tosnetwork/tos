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
    (
        "capped-boundary-principal",
        [
            ("int refund = original_stake;", "int refund = stake;"),
            ("throw_unless(63, total_placed == tot_stake + total_refunded);", "throw_unless(63, true);"),
        ],
        "security_audit::every_cap_boundary_conserves_the_increment_without_consuming_historic_credits",
        "boundary principal increment",
    ),
    (
        "unbounded-registration",
        [("const pq_participant_limit = 256;", "const pq_participant_limit = 1024;")],
        "security_audit::an_additional_identity_is_refused_at_the_participant_bound_before_state_changes",
        "the 257th identity must be refused",
    ),
    (
        "omitted-claimant-fine-share",
        [("credits~credit_to(reward_addr, reward);", "credits~credit_to(reward_addr, 0);")],
        "security_audit::a_fine_is_partitioned_between_claimant_and_purse_once_with_real_transaction_fees",
        "claimant fine share",
    ),
    (
        "omitted-system-fine-share",
        [("tomis += fine_unalloc;", "tomis += 0;")],
        "security_audit::a_fine_is_partitioned_between_claimant_and_purse_once_with_real_transaction_fees",
        "system fine share",
    ),
    (
        "unsafe-installation",
        [("throw_unless(66, upgrade_ready());", "throw_unless(66, true);")],
        "security_audit::a_real_classic_book_and_creditor_survive_explicit_installation_refusal",
        "expected first transaction to be aborted, but it succeeded",
    ),
    *[
        (
            f"rollback-ignores-{claim}",
            [("return elect.null?() & credits.null?() & past.null?();", expression)],
            "security_audit::upgrades_and_rollbacks_require_a_debt_free_boundary_and_preserve_the_root",
            f"live liabilities must refuse rollback: {phase}",
        )
        for claim, expression, phase in [
            ("active-book", "return credits.null?() & past.null?();", "cached"),
            ("frozen-book", "return elect.null?() & credits.null?();", "frozen-only"),
            ("credits", "return elect.null?() & past.null?();", "credits-only"),
        ]
    ],
    (
        "missing-books-treated-as-empty",
        [("throw_unless(65, es.slice_bits() >= 3);\n"
          "  cell pq_members = es~load_dict();\n"
          "  cell pq_key_owner = es~load_dict();\n"
          "  cell pq_by_code = es~load_dict();",
          "cell pq_members = null();\n"
          "  cell pq_key_owner = null();\n"
          "  cell pq_by_code = null();\n"
          "  ifnot (es.slice_empty?()) {\n"
          "    pq_members = es~load_dict();\n"
          "    pq_key_owner = es~load_dict();\n"
          "    pq_by_code = es~load_dict();\n"
          "  }")],
        "an_election_missing_its_books_is_refused_without_losing_its_declared_principal",
        "absent books need explicit migration",
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
