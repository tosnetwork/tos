"""Targeted red controls against compiled mutants, never against a mock model."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/smartcont/treasury-vault-code.fc"
TEST = Path(__file__).with_name("test_native.py")
MUTATIONS = (
    (
        "control_funding",
        "throw_unless(tv::funding, msg_value >= tv::control_value);",
        ";; removed control-message funding guard",
        "test_funding_and_storage_reserve",
    ),
    (
        "guardian",
        "throw_unless(tv::sender, equal_slice_bits(sender, v_guardian));",
        ";; removed guardian guard",
        "test_required_guardian",
    ),
    (
        "single_limit",
        "throw_unless(tv::single_limit, amount <= per);",
        ";; removed per-payment ceiling",
        "test_per_payment_limit",
    ),
    (
        "window_limit",
        "throw_unless(tv::window_limit, spent <= window);",
        ";; removed window ceiling",
        "test_split_payments_hit_window_limit",
    ),
    (
        "total_limit",
        "throw_unless(tv::total_limit, cumulative <= total);",
        ";; removed cumulative ceiling",
        "test_window_refresh_does_not_refresh_total",
    ),
    (
        "timelock",
        "throw_unless(tv::timelock, now() >= ready);",
        ";; removed management delay",
        "test_management_timelock",
    ),
    (
        "nonce",
        "throw_unless(tv::nonce, s~load_uint(64) == nonce);",
        "s~load_uint(64);",
        "test_request_nonce",
    ),
    (
        "principal_reserve",
        "raw_reserve(remaining, 0);",
        ";; removed principal reserve",
        "test_action_failure_rolls_back_accounting",
    ),
    (
        "action_atomicity",
        "send_raw_message(outgoing, 1);",
        "send_raw_message(outgoing, 3);",
        "test_action_failure_rolls_back_accounting",
    ),
    (
        "cold_authority",
        "throw_unless(tv::authority, equal_slice_bits(cold, v_cold));",
        ";; removed cold authority immutability",
        "test_cold_authority_is_immutable",
    ),
)


def main():
    original = SOURCE.read_text()
    receipts = []
    for name, old, new, test in MUTATIONS:
        if original.count(old) != 1:
            raise RuntimeError(f"{name}: expected one mutation anchor, found {original.count(old)}")
        with tempfile.TemporaryDirectory(prefix=f"treasury-{name}-") as temp:
            mutant = Path(temp) / "mutant.fc"
            mutant.write_text(original.replace(old, new, 1))
            env = dict(os.environ, TREASURY_SOURCE=str(mutant))
            env.pop("TREASURY_RESULTS", None)
            result = subprocess.run(
                [sys.executable, str(TEST), f"TreasuryTests.{test}"],
                env=env,
                text=True,
                capture_output=True,
                timeout=180,
            )
            output = result.stdout + result.stderr
            # A compiler error, missing library or test discovery error is NOT
            # a successful mutation control. The exact regression must assert.
            if result.returncode == 0 or f"FAIL: {test}" not in output:
                raise RuntimeError(f"{name}: missing targeted red result\n{output[-8000:]}")
            receipts.append(
                dict(
                    name=name,
                    test=test,
                    exit_code=result.returncode,
                    source_sha256=hashlib.sha256(mutant.read_bytes()).hexdigest(),
                    targeted_failure=True,
                )
            )
            print(f"RED CONTROL {name}: {test}", flush=True)
    report = dict(
        baseline_source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(), controls=receipts
    )
    target = os.environ.get("TREASURY_MUTATION_RESULTS")
    if target:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        Path(target).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
