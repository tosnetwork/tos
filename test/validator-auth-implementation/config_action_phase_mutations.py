"""Compile action-phase mutants and require the named sandbox evidence to fail."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/executor/src/transaction_executor.rs"
MANIFEST = ROOT / "tosctl/src/node-control/contracts/Cargo.toml"
CASES = [
    "config_persistence_action_phase::accepted_registry_persists_after_action_phase",
    "config_persistence_action_phase::refused_action_phase_rolls_registry_back",
    "config_persistence_action_phase::validator_auth_host_is_bound_to_configuration_account",
]
MUTATIONS = [
    (
        "transaction-host-injected",
        CASES[0],
        "        if let Some(binding) = params.validator_auth_host.clone() {\n"
        "            if acc.get_addr().is_some_and(|address| address == &binding.account) {\n"
        "                vm.set_validator_auth_host(binding.host);\n"
        "            }\n"
        "        }\n",
        "",
        # The binding case opens with a positive control that requires the host
        # to be installed, so removing the injection breaks it too. Measured by
        # running every other case under this mutation.
        [CASES[1], CASES[2]],
    ),
    (
        "transaction-host-account-bound",
        CASES[2],
        "            if acc.get_addr().is_some_and(|address| address == &binding.account) {\n"
        "                vm.set_validator_auth_host(binding.host);\n"
        "            }\n",
        "            vm.set_validator_auth_host(binding.host);\n",
        [],
    ),
    (
        "action-refusal-rolls-back-data",
        CASES[1],
        "        if let Some(new_data) = new_data {\n"
        "            acc_copy.set_data(new_data);\n"
        "        }\n"
        "        if !is_special && !check_account_size_limits(limits, &mut acc_copy)? {\n",
        "        if let Some(new_data) = new_data {\n"
        "            acc_copy.set_data(new_data.clone());\n"
        "            acc.set_data(new_data);\n"
        "        }\n"
        "        if !is_special && !check_account_size_limits(limits, &mut acc_copy)? {\n",
        [],
    ),
]


def run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def compile_tests(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return run(
        ["cargo", "test", "--manifest-path", str(MANIFEST), "--test", "native_registry_sandbox", "--no-run"],
        env,
    )


def run_case(case: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(MANIFEST),
            "--test",
            "native_registry_sandbox",
            case,
            "--",
            "--exact",
            "--include-ignored",
            "--nocapture",
        ],
        env,
    )


def passed(result: subprocess.CompletedProcess[str], case: str) -> bool:
    short = case.split("::")[-1]
    return result.returncode == 0 and f"CASE_PASS {short}" in result.stdout


def failed_named(result: subprocess.CompletedProcess[str], case: str) -> bool:
    short = case.split("::")[-1]
    return result.returncode != 0 and f"SETUP_OK {short}" in result.stdout and "FAILED" in result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["VALIDATOR_AUTH_CONFIG_PERSISTENCE_CELLS"] = str(args.cells.resolve())

    original = SOURCE.read_text()
    baseline_compile = compile_tests(env)
    if baseline_compile.returncode != 0:
        (out / "baseline-compile.stderr").write_text(baseline_compile.stderr)
        print("BASELINE_COMPILE_FAILED", file=sys.stderr)
        return 1
    if not all(passed(run_case(case, env), case) for case in CASES):
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
            compile_result = compile_tests(env)
            compiled = compile_result.returncode == 0
            results = {}
            observed = []
            if compiled:
                for case in CASES:
                    result = run_case(case, env)
                    results[case] = result
                    if not passed(result, case):
                        observed.append(case)
            named_result = results.get(named_case)
            named_failed = named_result is not None and failed_named(named_result, named_case)
            companions = [case for case in observed if case != named_case]
            isolated = sorted(companions) == sorted(declared)

            SOURCE.write_text(original)
            restored_compile = compile_tests(env)
            restored = restored_compile.returncode == 0 and all(
                passed(run_case(case, env), case) for case in CASES
            )
            record = {
                "guard": guard,
                "case": named_case,
                "edit_reached_source": reached,
                "compiled": compiled,
                "named_assertion_failed": named_failed,
                "declared_companions": declared,
                "observed_companions": companions,
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
