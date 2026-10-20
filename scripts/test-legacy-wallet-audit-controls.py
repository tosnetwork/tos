#!/usr/bin/env python3
"""Prove the legacy-wallet regressions fail against the pre-fix source.

Uses temporary source directories; never rewrites the checkout. Requires the
same native tools/environment as the contract sandbox suites. Exit zero only
when all fixed-source tests pass and each historical-source control fails at
its intended assertion. Stdout is a small durable evidence index.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "b56d8dc55cfe5a3203ac8fd22d6689384a768c39"
CASES = [
    ("H-MS-01", "multisig-code.fc", "multisig_code_sandbox", "expired_full_quotas_can_be_reclaimed_without_quorum", "exit code: 39"),
    ("M-PC-PAYOUT-01/atomic", "payment-channel-code.fc", "payment_channel_sandbox", "payout_is_atomic_and_cannot_pay_principals_twice", "expected first transaction to be aborted, but it succeeded"),
    ("M-PC-PAYOUT-01/replay", "payment-channel-code.fc", "payment_channel_sandbox", "completed_payout_refuses_repayment_after_topup", "already paid"),
    ("M-RW2-01", "new-restricted-wallet2.fif", "legacy_wallet_liveness_sandbox", "restricted_wallet_constructor_uses_seconds_and_enforces_every_unlock_boundary", "elapsed seconds"),
    ("M-HL2-01", "highload-wallet-v2-code.fc", "legacy_wallet_liveness_sandbox", "highload_expired_backlog_is_bounded_and_replay_protection_survives", "exit_code: -14"),
]

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=BASELINE)
    args = parser.parse_args()
    env = dict(os.environ, CARGO_TERM_COLOR="never")
    env.pop("TOS_AUDIT_SMARTCONT_DIR", None)
    env.setdefault("TOS_ROOT", str(ROOT))
    for finding, filename, suite, test, marker in CASES:
        command = ["cargo", "test", "--manifest-path", str(ROOT / "tosctl/src/Cargo.toml"), "--locked", "-p", "contracts", "--test", suite, test, "--", "--exact", "--nocapture"]
        green = subprocess.run(command, env=env, capture_output=True, text=True)
        if green.returncode:
            raise SystemExit(f"{finding}: fixed source failed\n{green.stdout}\n{green.stderr}")
        with tempfile.TemporaryDirectory(prefix="legacy-wallet-control-") as temp:
            target = Path(temp)
            for source in (ROOT / "crypto/smartcont").iterdir():
                if source.is_file() and source.suffix in (".fc", ".func", ".fif"):
                    shutil.copyfile(source, target / source.name)
            old = subprocess.check_output(["git", "-C", str(ROOT), "show", f"{args.baseline}:crypto/smartcont/{filename}"])
            (target / filename).write_bytes(old)
            red = subprocess.run(command, env=dict(env, TOS_AUDIT_SMARTCONT_DIR=temp), capture_output=True, text=True)
        output = red.stdout + red.stderr
        if red.returncode == 0 or marker not in output:
            raise SystemExit(f"{finding}: control did not fail at its intended assertion\n{output}")
        print(f"{finding}: fixed=0 historical={red.returncode}; assertion={marker!r}; historical_source_sha256={hashlib.sha256(old).hexdigest()}", flush=True)
    print(f"PASS: {len(CASES)} native red/green controls; historical revision {args.baseline}")

if __name__ == "__main__":
    main()
