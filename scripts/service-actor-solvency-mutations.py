#!/usr/bin/env python3
"""Prove Service Actor funding tests reject specific broken settlement rules."""

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
    admission_check = (
        "    require_backing(backing, pending_liability, refundable_liability, locked_storage_fees,\n"
        "      MINIMUM_OPERATING_RESERVE, err::operating_reserve_unfunded);"
    )
    refund_check = (
        "    require_backing(remaining, pending_liability, remaining_refundable, remaining_locked,\n"
        "      0, err::insufficient_balance);"
    )
    admission_settlement = "    raw_reserve(retained, 0);\n    send_value(sender, 0, 128);"
    cases = [
        (
            "admission operating reserve",
            "admission_requires_preexisting_reserve",
            admission_check,
            "",
            "expected first transaction to be aborted, but it succeeded",
        ),
        (
            "admission existing liabilities",
            "admission_requires_existing_obligations",
            admission_check,
            "    require_backing(backing, 0, 0, 0, MINIMUM_OPERATING_RESERVE, err::operating_reserve_unfunded);",
            "expected first transaction to be aborted, but it succeeded",
        ),
        (
            "admission execution budget",
            "admission_requires_execution_budget",
            "    throw_unless(err::insufficient_execution_payment,\n      execution_payment >= ADMISSION_GAS_ALLOWANCE);",
            "",
            "expected exit code 1929, got 0",
        ),
        (
            "old admission fee subsidy",
            "admission_preserves_operator_excess",
            admission_settlement,
            "    raw_reserve(checked_add_amount(checked_add_amount(checked_add_amount(admitted_pending, refundable_liability), admitted_locked), MINIMUM_OPERATING_RESERVE), 0);\n"
            "    send_value(sender, execution_payment, 1);",
            "successful admission spent preexisting backing",
        ),
        (
            "admission action reserve",
            "admission_preserves_operator_excess",
            admission_settlement,
            "    send_value(sender, 0, 128);",
            "successful admission spent preexisting backing",
        ),
        (
            "refund priority",
            "claim_preserves_other_entries_and_reserves_after_fees",
            refund_check,
            refund_check.replace("      0,", "      MINIMUM_OPERATING_RESERVE,"),
            "expected first transaction to succeed, but it was aborted",
        ),
        (
            "refund other-customer floor",
            "claim_preserves_other_entries_and_reserves_after_fees",
            refund_check,
            "",
            "expected first transaction to be aborted, but it succeeded",
        ),
        (
            "refund action reserve",
            "claim_preserves_other_entries_and_reserves_after_fees",
            "    pay_with_change(destination, sender, backing, price);",
            "    send_value(destination, price, 1);\n    send_value(sender, 0, 128);",
            "only this operation's execution and forwarding fees reduce change",
        ),
        (
            "withdrawal action reserve",
            "exact_withdrawal_cap_cannot_spend_fee_backing",
            "    pay_with_change(owner, sender, backing, amount);",
            "    send_value(owner, amount, 1);\n    send_value(sender, 0, 128);",
            "only this operation's execution and forwarding fees reduce change",
        ),
        (
            "sweep action reserve",
            "sweep_after_real_rent_preserves_other_entries",
            "    pay_with_change(sender, sender, backing, req_cleanup_bounty);",
            "    send_value(sender, req_cleanup_bounty, 1);\n    send_value(sender, 0, 128);",
            "only this operation's execution and forwarding fees reduce change",
        ),
        (
            "exact principal instead of carry-all haircut",
            "refund_never_haircuts_principal_when_fees_rise",
            "  if (amount > 0) {\n    send_value(destination, amount, 1);\n  }\n  send_value(payer, 0, 128);",
            "  send_value(destination, 0, 128);",
            "expected first transaction to be aborted, but it succeeded",
        ),
    ]
    # Mutate each branch independently so another branch cannot mask a missing guard.
    budget_guard = (
        "    throw_unless(err::insufficient_execution_payment, msg_value >= PAYOUT_GAS_ALLOWANCE);"
    )
    for operation, next_operation in [
        ("claim_refund", "sweep_expired_request"),
        ("sweep_expired_request", "update_policy"),
        ("withdraw_revenue", None),
    ]:
        start = source.index(f"  if (op == op::{operation}) {{")
        end = (
            source.index(f"  if (op == op::{next_operation}) {{", start)
            if next_operation
            else source.index("  throw(err::unknown_op);", start)
        )
        branch = source[start:end]
        cases.append(
            (
                f"{operation} execution budget",
                "payouts_require_execution_budget",
                branch,
                replace_once(branch, budget_guard, ""),
                "expected first transaction to be aborted, but it succeeded",
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
    required = {PREFIX + case[1] for case in cases} | {PREFIX + "source_matches_embedded_code"}
    passed = set(re.findall(r"^test (solvency_\w+) \.\.\. ok$", green.stdout, re.MULTILINE))
    if green.returncode or not required <= passed:
        raise RuntimeError(
            "baseline did not pass every required test:\n" + green.stdout + green.stderr
        )
    print(f"PASS: {len(passed)} unmodified solvency tests", flush=True)
    with tempfile.TemporaryDirectory(prefix="service-solvency-") as tmp:
        for include in re.findall(r'^#include "([^"\n]+)";', source, re.MULTILINE):
            (Path(tmp) / include).write_bytes((SOURCE.parent / include).read_bytes())
        for index, (label, test, old, new, assertion) in enumerate(cases):
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
            if (
                result.returncode == 0
                or "test result: FAILED. 0 passed; 1 failed" not in output
                or assertion not in output
                or "compilation failed" in output
            ):
                raise RuntimeError(f"{label}: no valid red assertion:\n{output}")
            start = output.index("panicked at")
            evidence = output[start:].split("note: run with", 1)[0].strip()
            print(f"RED: {label}\n{evidence}", flush=True)
    print(f"PASS: {len(cases)}/{len(cases)} broken rules detected", flush=True)


if __name__ == "__main__":
    main()
