#!/usr/bin/env python3
# Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Run actual assertion controls and restore the complete SDK suite"
)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--target-dir", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
source = root / "tools/shielded-pool-mobile/src/wallet.rs"
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)
original = source.read_text()
(out / "source-before.rs").write_text(original)


def require(value, message):
    if not value:
        raise RuntimeError(message)


full = ["cargo", "test", "--locked", "--manifest-path", "tools/shielded-pool-mobile/Cargo.toml"]
env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
cases = [
    (
        "global_dedup",
        "        .spendable_notes()\n        .try_fold",
        "        .notes.iter().filter(|note| note.spendable && !note.spent)\n        .try_fold",
        "replay_ffi::tests::complete_summary_deduplicates_across_pages_and_keeps_same_index_distinct_notes",
    ),
    (
        "spent",
        "reconcile_spent(&instance, published)",
        "reconcile_spent(&instance, &BTreeSet::new())",
        "replay_ffi::tests::complete_summary_deduplicates_across_pages_and_keeps_same_index_distinct_notes",
    ),
    (
        "amount_overflow",
        "sum.checked_add(note.amount).ok_or(Error::Limit)",
        "Ok::<u128, Error>(sum.wrapping_add(note.amount))",
        "wallet::tests::checked_balance_never_wraps_or_returns_a_partial_total",
    ),
    (
        "exhaustion",
        "Some(index) => index.checked_add(1)",
        "Some(index) => Some(index.saturating_add(1))",
        "wallet::tests::scan_exhaustion_is_explicit_and_not_an_issuable_maximum",
    ),
    (
        "output_cap",
        "    if outputs.len() > MAX_COMPLETE_OUTPUTS {\n        return Err(Error::Limit);\n    }\n",
        "",
        "wallet::tests::total_output_budget_is_checked_before_recovery",
    ),
    (
        "secret_drop",
        "            note.note_secret.zeroize();\n",
        "",
        "wallet::tests::held_secret_aggregate_is_cleared_by_actual_drop",
    ),
]
cases.append(
    (
        "payload_cap",
        "    if bytes > MAX_COMPLETE_PAYLOAD_BYTES {\n        return Err(Error::Limit);\n    }\n",
        "",
        "wallet::tests::payload_budget_is_checked_before_cloning_or_decrypting",
    )
)
results = []
try:
    for name, before, after, test in cases:
        require(original.count(before) == 1, "Mutation target changed: " + name)
        source.write_text(original.replace(before, after))
        log = out / (name + ".log")
        with log.open("wb") as stream:
            result = subprocess.run(
                full + ["--lib", test, "--", "--exact"],
                cwd=root,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=240,
            )
        text = log.read_text()
        require(
            result.returncode == 101 and ("test " + test + " ... FAILED") in text,
            "Expected failed test: " + name,
        )
        require(
            ("panicked at src/wallet.rs:" in text or "panicked at src/replay_ffi.rs:" in text)
            and "assertion" in text,
            "Expected runtime assertion: " + name,
        )
        results.append(
            {
                "name": name,
                "test": test,
                "exit_code": result.returncode,
                "assertion_failed": True,
                "log": str(log),
                "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
            }
        )
finally:
    source.write_text(original)
    with (out / "restored-full.log").open("wb") as stream:
        restored = subprocess.run(
            full, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=300
        )
    require(restored.returncode == 0, "Restored SDK suite did not pass")
    require(source.read_text() == original, "Source was not restored exactly")
    (out / "results.json").write_text(
        json.dumps(
            {
                "controls": results,
                "expected_controls": len(cases),
                "complete": len(results) == len(cases),
                "restored_sdk_exit": restored.returncode,
                "source_restored_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )
