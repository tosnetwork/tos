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
source = root / "tools/shielded-pool-mobile/src/reservations.rs"
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
        "largest_watermark",
        "let first = scanned.max(self.journal.next);",
        "let first = scanned;",
        "reservations_survive_restart_and_preserve_cached_payload",
    ),
    (
        "monotonic_ranges",
        " || first < self.next",
        "",
        "overlapping_authenticated_ranges_are_refused",
    ),
    (
        "prefix_checkpoint",
        "            if cursor.records == anchor.records && cursor != anchor {\n                return Err(StoreError::Conflict);\n            }\n",
        "",
        "authenticated_prefix_substitution_is_refused",
    ),
    (
        "prefix_digest",
        "        hash.update(frame);\n",
        "",
        "authenticated_prefix_substitution_is_refused",
    ),
    (
        "truncation",
        "        if cursor.records < anchor.records {\n            return Err(StoreError::RecoveryRequired);\n        }\n",
        "",
        "acknowledged_checkpoint_refuses_missing_or_truncated_journal",
    ),
    (
        "record_purpose",
        "cipher.open(Kind::Journal, cursor.records, &record)",
        "cipher.open(Kind::State, cursor.records, &record)",
        "journal_records_cannot_use_the_state_encryption_purpose",
    ),
    (
        "record_limit",
        " || self.journal.records >= MAX_RECORDS",
        "",
        "record_limit_is_enforced_without_resetting",
    ),
    (
        "checkpoint_before_return",
        "        self.publish(&data, &mut |_| Ok(()))?;",
        "        self.poisoned = false;",
        "reservations_survive_restart_and_preserve_cached_payload",
    ),
    (
        "failure_freeze",
        "        let next = self.journal.advance(&plain, &frame)?;\n        self.poisoned = true;",
        "        let next = self.journal.advance(&plain, &frame)?;\n        self.poisoned = false;",
        "unacknowledged_complete_tail_is_burned_before_next_reservation",
    ),
    (
        "file_limit",
        "        if size > MAX_JOURNAL_BYTES {\n            return Err(Error::Limit.into());\n        }\n",
        "",
        "file_size_limit_is_checked_before_parsing_frames",
    ),
]
results = []
try:
    for name, before, after, test in cases:
        require(original.count(before) == 1, "Mutation target changed: " + name)
        source.write_text(original.replace(before, after))
        log = out / (name + ".log")
        with log.open("wb") as stream:
            result = subprocess.run(
                full + ["--lib", "store::reservations::tests::" + test, "--", "--exact"],
                cwd=root,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=240,
            )
        text = log.read_text()
        require(
            result.returncode == 101
            and ("test store::reservations::tests::" + test + " ... FAILED") in text,
            "Expected failed test: " + name,
        )
        require(
            "panicked at src/reservation_tests.rs:" in text and "assertion" in text,
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
