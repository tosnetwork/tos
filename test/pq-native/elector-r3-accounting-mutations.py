#!/usr/bin/env python3
"""Compile each R3 defect and require its specific native assertion to fail.

Run in an idle checkout: sources are restored in finally; tests must not run
concurrently with this runner. Logs and a compact result index go to --out.
No network or runtime account is contacted.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C = "crypto/smartcont/validator-controller-v1.fc"
P = "crypto/smartcont/nominator-pool/pool.fc"
E = "crypto/smartcont/elector-code.fc"
BASE = "security_audit::relay::"
ACCOUNTING = BASE + "r3_accounting::"
DEBT = ACCOUNTING + "explicit_debt_does_not_sweep_aborted_nonbounce_credit"
DEPOSIT = ACCOUNTING + "operating_deposits_bind_sender_nonce_expiry_and_preserve_existing_debt"
RECOVERY = ACCOUNTING + "preaccounting_abort_bounces_then_retries_actual_cash_once"
MUTANTS = [
    (
        "withdrawal-sender",
        C,
        [
            (
                "throw_unless(ctl::error::bad_action, equal_slice_bits(sender, payer));",
                "throw_unless(ctl::error::bad_action, true);",
            )
        ],
        ACCOUNTING + "operating_withdrawal_is_explicit_bounded_and_cannot_touch_pending_debt",
        "withdrawal sender binding",
    ),
    (
        "withdrawal-ledger",
        C,
        [
            (
                "ctl::save_operations(sr::sub(funds, amount), permission, limit, floor, expires, sponsor);",
                "ctl::save_operations(funds, permission, limit, floor, expires, sponsor);",
            )
        ],
        ACCOUNTING + "operating_withdrawal_is_explicit_bounded_and_cannot_touch_pending_debt",
        "withdrawal debits operating ledger",
    ),
    (
        "withdrawal-pending-guard",
        C,
        [
            (
                "throw_unless(ctl::error::bad_action, pending.null?());\n    throw_unless(sr::error, msg_value",
                "throw_unless(ctl::error::bad_action, true);\n    throw_unless(sr::error, msg_value",
            )
        ],
        ACCOUNTING + "operating_withdrawal_is_explicit_bounded_and_cannot_touch_pending_debt",
        "pending debt blocks withdrawal",
    ),
    (
        "returned-fees-to-wrong-payer",
        E,
        [("sr::message(previous_payer, fee_credit,", "sr::message(payer, fee_credit,")],
        ACCOUNTING
        + "a_second_bounce_preserves_previous_payer_credit_and_acknowledged_returns_never_repay",
        "returned retry fees belong to the previous payer",
    ),
    (
        "expired-sponsorship",
        C,
        [("(now() < expires) & (grant <= limit)", "(grant <= limit)")],
        ACCOUNTING + "sponsorship_requires_separate_explicit_funds_and_permission",
        "R3: expired cannot authorize sponsorship",
    ),
    (
        "missing-per-request-cap",
        C,
        [("(grant <= limit) & (grant <= permission)", "(grant <= permission)")],
        ACCOUNTING + "sponsorship_requires_separate_explicit_funds_and_permission",
        "R3: cap cannot authorize sponsorship",
    ),
    (
        "late-self-kick-retains-fees",
        C,
        [("if (self & (pending.null?() | (query != sequence)))", "if (false)")],
        ACCOUNTING + "current_fee_change_goes_to_inlet_and_retry_payers_not_principal_owner",
        "late automatic wakeup refunds its original sponsor",
    ),
    (
        "optional-business-payment",
        C,
        [
            (
                "send_raw_message(sr::message(sr::address(owner), sr::add(principal, callback), payment, false), 1);",
                "send_raw_message(sr::message(sr::address(owner), sr::add(principal, callback), payment, false), 3);",
            )
        ],
        BASE + "a_real_controller_payment_action_failure_keeps_ready_debt_for_public_retry",
        "failed payment action must retain READY",
    ),
    (
        "balance-derived-debt",
        C,
        [
            (
                "int principal = phase == 1 ? debt : 0;",
                "int principal = phase == 1 ? sr::sub(pair_first(get_balance()), msg_value) : 0;",
            )
        ],
        DEBT,
        "owner payment is actual debt",
    ),
    (
        "missing-transaction-floor",
        C,
        [("raw_reserve(floor, 0);", "raw_reserve(0, 0);")],
        DEBT,
        "transaction floor protects unrelated cash",
    ),
    (
        "callback-sweeps-principal",
        P,
        [
            (
                "raw_reserve(sr::sub(balance, callback), 0);",
                "raw_reserve(sr::sub(balance, msg_value), 0);",
            )
        ],
        ACCOUNTING + "current_fee_change_goes_to_inlet_and_retry_payers_not_principal_owner",
        "callback budget must not enter pool principal",
    ),
    (
        "unreserved-operating-grant",
        C,
        [
            (
                "ctl::save_operations(sr::sub(funds, grant), sr::sub(permission, grant), limit, floor, expires, sponsor);",
                "ctl::save_operations(funds, permission, limit, floor, expires, sponsor);",
            )
        ],
        ACCOUNTING + "sponsorship_requires_separate_explicit_funds_and_permission",
        "one finite operating grant is reserved",
    ),
    (
        "unbound-deposit-sender",
        C,
        [
            (
                "throw_unless(sr::error, equal_slice_bits(sender, payer));",
                "throw_unless(sr::error, true);",
            )
        ],
        DEPOSIT,
        "sender binding must reject",
    ),
    (
        "replayable-deposit",
        C,
        [
            (
                "throw_unless(ctl::error::bad_nonce, nonce == stored_nonce);",
                "throw_unless(ctl::error::bad_nonce, true);",
            )
        ],
        DEPOSIT,
        "nonce prevents a second credit",
    ),
    (
        "expired-deposit-authority",
        C,
        [
            (
                "throw_unless(ctl::error::expired, valid_until > now());",
                "throw_unless(ctl::error::expired, true);",
            )
        ],
        DEPOSIT,
        "expired root authority",
    ),
    (
        "resend-in-flight",
        E,
        [
            (
                "int payment = phase == 1 ? sr::add(amount, fee_credit) : 0;",
                "int payment = phase != 2 ? sr::add(amount, fee_credit) : 0;",
            ),
            ("  if (phase == 1) {", "  if (phase != 2) {"),
        ],
        RECOVERY,
        "in-flight retry must not repeat business payment",
    ),
    (
        "restore-gross-instead-of-cash",
        E,
        [
            ("int restored = min(amount, msg_value);", "int restored = amount;"),
            ("sr::sub(msg_value, restored), payer)", "max(0, msg_value - restored), payer)"),
        ],
        RECOVERY,
        "gross is never fabricated after a bounce",
    ),
    (
        "erase-return-capability",
        E,
        [
            (
                "int return_format = has_relay_returns ? relay_return_upgrade_format() : 0x52525633;",
                "int return_format = 0x52525633;",
            )
        ],
        BASE + "r3_r4::return_tombstones_require_the_new_upgrade_capability_and_survive_cutover",
        "return capability must reject incompatible code",
    ),
]


def build(path):
    compiler = os.environ.get("FUNC_PATH", str(ROOT / "build/crypto/func"))
    with tempfile.TemporaryDirectory() as temporary:
        output = (
            ROOT / "build/crypto/smartcont/auto/elector-code.fif"
            if path == E
            else Path(temporary) / "code.fif"
        )
        sources = [path] if path == P else ["crypto/smartcont/stdlib.fc", path]
        subprocess.run(
            [compiler, "-PS", "-o", str(output), *sources],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )


def run(test, log):
    result = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            "tosctl/src/Cargo.toml",
            "-p",
            "contracts",
            "--locked",
            "--test",
            "elector_sandbox",
            test,
            "--",
            "--exact",
            "--nocapture",
        ],
        cwd=ROOT,
        env={**os.environ, "TOS_ROOT": str(ROOT)},
        text=True,
        capture_output=True,
    )
    raw = result.stdout + result.stderr
    log.write_text(raw)
    return result.returncode, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only")
    args = parser.parse_args()
    selected = [m for m in MUTANTS if not args.only or m[0] == args.only]
    if not selected:
        parser.error("no matching mutation")
    originals = {path: (ROOT / path).read_text() for _, path, *_ in selected}
    for name, path, replacements, *_ in selected:
        for before, _ in replacements:
            if originals[path].count(before) != 1:
                raise ValueError(f"{name}: anchor must match exactly once: {before}")
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    build(E)
    for name, path, replacements, test, assertion in selected:
        baseline, raw = run(test, args.out / f"{name}-baseline.log")
        if baseline or "1 passed" not in raw:
            raise RuntimeError(f"{name}: baseline did not run and pass exactly one test")
        source = originals[path]
        try:
            for before, after in replacements:
                source = source.replace(before, after)
            (ROOT / path).write_text(source)
            build(path)  # Compilation failure cannot kill a mutation.
            code, raw = run(test, args.out / f"{name}-mutant.log")
            killed = code == 101 and "1 failed" in raw and "panicked at" in raw and assertion in raw
        finally:
            (ROOT / path).write_text(originals[path])
            build(path)
        restored, green = run(test, args.out / f"{name}-restored.log")
        if restored or "1 passed" not in green:
            raise RuntimeError(f"{name}: restored source did not pass")
        failures = [line.strip() for line in raw.splitlines() if assertion in line]
        results.append(
            dict(
                name=name,
                test=test,
                killed=killed,
                baseline=baseline,
                mutant=code,
                restored=restored,
                assertion=assertion,
                failure=failures,
                source_sha256=hashlib.sha256(originals[path].encode()).hexdigest(),
            )
        )
        (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"{'killed' if killed else 'SURVIVED'} {name}", flush=True)
        if not killed:
            raise RuntimeError(f"{name}: missing intended assertion failure; inspect retained log")


if __name__ == "__main__":
    main()
