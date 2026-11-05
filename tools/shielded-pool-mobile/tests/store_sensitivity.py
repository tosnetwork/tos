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
source = root / "tools/shielded-pool-mobile/src/store.rs"
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
        "directory_mode",
        "    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {",
        "    if false {",
        "directory_permissions_and_final_symlink_are_refused",
    ),
    (
        "directory_nofollow",
        "libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK",
        "libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK",
        "directory_permissions_and_final_symlink_are_refused",
    ),
    (
        "lock",
        "if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0",
        "if false",
        "directory_lock_is_exclusive_and_released_on_drop",
    ),
    (
        "file_private",
        "        if !metadata.is_file()\n            || metadata.uid() != owner\n            || metadata.nlink() != 1\n            || metadata.mode() & 0o077 != 0\n        {",
        "        if false {",
        "state_read_permissions_hard_links_and_symlinks_are_refused",
    ),
    (
        "file_nofollow",
        "flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK",
        "flags | libc::O_CLOEXEC | libc::O_NONBLOCK",
        "state_read_permissions_hard_links_and_symlinks_are_refused",
    ),
    (
        "stale_candidate",
        "Ok(_) => return Err(StoreError::RecoveryRequired),",
        "Ok(_) => {},",
        "uncertain_temporary_file_is_preserved_and_requires_explicit_recovery",
    ),
    (
        "generation",
        "        if state.as_ref().map(|state| state.data.generation) != self.generation {\n            return Err(StoreError::Conflict);\n        }\n",
        "",
        "outside_replacement_freezes_handle_without_overwriting_new_bytes",
    ),
    (
        "preflight",
        "        if let Err(error) = self.checked_read() {\n            self.poisoned = true;\n            return Err(error);\n        }\n",
        "",
        "commit_preflight_rejects_changed_or_corrupt_state_before_creating_a_candidate",
    ),
    (
        "freeze",
        "        let (encoded, generation) = snapshot::seal_generated(&self.cipher, Kind::State, &wrapped)?;\n        self.poisoned = true;",
        "        let (encoded, generation) = snapshot::seal_generated(&self.cipher, Kind::State, &wrapped)?;\n        self.poisoned = false;",
        "interrupted_commit_freezes_reads_and_writes_and_retains_both_outcomes",
    ),
    (
        "exclusive_candidate",
        "libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL",
        "libc::O_WRONLY | libc::O_CREAT",
        "exclusive_candidate_creation_never_overwrites_an_uncertain_file",
    ),
    (
        "authenticate_existing",
        "self.read_private_bytes(STATE, MAX_ENCODED_BYTES)?\n            .map(|bytes| Self::decode_state(&self.cipher, &bytes))\n            .transpose()",
        "Ok(None)",
        "wrong_seed_genesis_corruption_and_old_format_never_reset_existing_state",
    ),
]
cases.append(
    (
        "state_envelope_version",
        'plain.len() < STATE_HEADER || &plain[..4] != b"SJS1"',
        "plain.len() < STATE_HEADER",
        "store::reservations::tests::authenticated_legacy_opaque_state_is_preserved_without_automatic_reinterpretation",
    )
)
results = []
try:
    for name, before, after, test in cases:
        require(original.count(before) == 1, "Mutation target changed: " + name)
        source.write_text(original.replace(before, after))
        qualified = test if "::" in test else "store::tests::" + test
        test_source = (
            "src/reservation_tests.rs:"
            if "::reservations::" in qualified
            else "src/store_tests.rs:"
        )
        log = out / (name + ".log")
        with log.open("wb") as stream:
            result = subprocess.run(
                full + ["--lib", qualified, "--", "--exact"],
                cwd=root,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=240,
            )
        text = log.read_text()
        require(
            result.returncode == 101 and ("test " + qualified + " ... FAILED") in text,
            "Expected failed test: " + name,
        )
        require(
            ("panicked at " + test_source) in text and "assertion" in text,
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
