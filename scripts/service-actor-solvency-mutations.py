#!/usr/bin/env python3
"""Prove Service Actor solvency tests fail when each protection is removed."""

import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crypto/smartcont/service-actor-code.fc"
PREFIX = "solvency_"


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError(f"mutation anchor is not unique: {old!r}")
    return source.replace(old, new, 1)


def main():
    source = SOURCE.read_text()
    reserve = (
        "    reserve_obligations(pending_liability, refundable_liability, locked_storage_fees);\n"
    )
    cases = [
        (
            "admission funding",
            "admission_requires_preexisting_reserve",
            source[
                source.index(
                    "    throw_unless(err::operating_reserve_unfunded, balance >= msg_value);"
                ) : source.index(
                    "    reserve_obligations(admitted_pending, refundable_liability, admitted_locked);"
                )
            ],
            "",
        ),
        (
            "admission action reserve",
            "admission_reserves_after_fees_with_and_without_overpayment",
            "    reserve_obligations(admitted_pending, refundable_liability, admitted_locked);",
            "",
        ),
        (
            "withdrawal action reserve",
            "exact_withdrawal_cap_cannot_spend_fee_backing",
            "    throw_unless(err::insufficient_revenue, amount <= withdrawable_now);\n" + reserve,
            "    throw_unless(err::insufficient_revenue, amount <= withdrawable_now);\n",
        ),
        (
            "sweep action reserve",
            "sweep_after_real_rent_preserves_other_entries",
            "    locked_storage_fees = remaining_locked;\n" + reserve,
            "    locked_storage_fees = remaining_locked;\n",
        ),
        (
            "refund action reserve",
            "claim_preserves_other_entries_and_reserves_after_fees",
            "    reserve_obligations(pending_liability, remaining_refundable, remaining_locked);",
            "",
        ),
    ]
    # Removing all early remaining-obligation checks must fail for the compute
    # exit assertion, even though the action-phase reserve independently holds.
    claim_start = source.index("    ;; Refusing an insolvent payout")
    claim_end = source.index(
        "    reserve_obligations(pending_liability, remaining_refundable", claim_start
    )
    claim = source[claim_start:claim_end]
    check_start = claim.index(
        "    throw_unless(err::insufficient_balance, remaining >= pending_liability);"
    )
    cases.append(
        (
            "refund early floor",
            "claim_preserves_other_entries_and_reserves_after_fees",
            claim,
            claim[:check_start],
        )
    )
    cases.append(
        (
            "admission existing obligations",
            "admission_requires_existing_obligations",
            source[
                source.index(
                    "    throw_unless(err::operating_reserve_unfunded, backing >= pending_liability);"
                ) : source.index(
                    "    throw_unless(err::operating_reserve_unfunded, backing >= MINIMUM_OPERATING_RESERVE);"
                )
            ],
            "",
        )
    )
    cmd = [
        "cargo",
        "test",
        "--manifest-path",
        str(ROOT / "tosctl/src/Cargo.toml"),
        "--locked",
        "-p",
        "contracts",
        "--test",
        "service_actor_sandbox",
    ]
    env = dict(os.environ, TOS_ROOT=str(ROOT), CARGO_TERM_COLOR="never")
    env.pop("SERVICE_ACTOR_SOLVENCY_SOURCE", None)
    green = subprocess.run(cmd + [PREFIX], cwd=ROOT, env=env, capture_output=True, text=True)
    expected_tests = {PREFIX + case[1] for case in cases} | {
        PREFIX + "source_matches_embedded_code"
    }
    passed_tests = set(re.findall(r"^test (solvency_\w+) \.\.\. ok$", green.stdout, re.MULTILINE))
    if green.returncode or not expected_tests <= passed_tests:
        raise RuntimeError(
            "baseline did not pass every required test:\n" + green.stdout + green.stderr
        )
    print(f"PASS: {len(passed_tests)} unmodified solvency tests", flush=True)
    with tempfile.TemporaryDirectory(prefix="service-solvency-") as tmp:
        for include in re.findall(r'^#include "([^"\n]+)";', source, re.MULTILINE):
            (Path(tmp) / include).write_bytes((SOURCE.parent / include).read_bytes())
        for index, (label, test, old, new) in enumerate(cases):
            path = Path(tmp) / f"mutation-{index}.fc"
            path.write_text(replace_once(source, old, new))
            mutated_env = dict(env, SERVICE_ACTOR_SOLVENCY_SOURCE=str(path))
            result = subprocess.run(
                cmd + [PREFIX + test, "--", "--exact"],
                cwd=ROOT,
                env=mutated_env,
                capture_output=True,
                text=True,
            )
            output = result.stdout + result.stderr
            expected = {
                "admission funding": "expected exit code 1928, got 0",
                "admission existing obligations": "expected exit code 1928, got 0",
                "refund early floor": "expected exit code 1921, got 0",
            }.get(label, "expected first transaction to be aborted, but it succeeded")
            if (
                result.returncode == 0
                or "test result: FAILED. 0 passed; 1 failed" not in output
                or expected not in output
                or "compilation failed" in output
            ):
                raise RuntimeError(f"{label}: no valid red assertion:\n{output}")
            # Keep the bounded assertion evidence in CI logs, not every build warning.
            start = output.index("panicked at")
            assertion = output[start:].split("note: run with", 1)[0].strip()
            print(f"RED: {label}\n{assertion}", flush=True)
    print(f"PASS: {len(cases)}/{len(cases)} removed protections detected", flush=True)


if __name__ == "__main__":
    main()
