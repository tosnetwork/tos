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
source = root / "tools/shielded-pool-mobile/src/sealed.rs"
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)
original = source.read_text()
(out / "source-before.rs").write_text(original)


def require(value, message):
    if not value:
        raise RuntimeError(message)


full = ["cargo", "test", "--locked", "--manifest-path", "tools/shielded-pool-mobile/Cargo.toml"]
env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
binding_test = "wrong_seed_and_each_independent_binding_are_refused"
cases = [
    ("global", "        out.extend_from_slice(&self.global_id.to_be_bytes());\n", "", binding_test)
]
for field in [
    "pool_account",
    "genesis_root",
    "genesis_file",
    "code_hash",
    "profile_hash",
    "manifest_hash",
    "verifying_key_hash",
]:
    cases.append((field, "            &self." + field + ",\n", "", binding_test))
cases += [
    ("seed", "        shake.update(seed);\n", "", binding_test),
    (
        "header_aad",
        "        aad.extend_from_slice(header);\n",
        "",
        "forging_header_to_match_a_new_position_still_fails_authentication",
    ),
    (
        "random_nonce",
        "        rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|_| Error::Crypto)?;\n",
        "",
        "repeated_state_replacements_use_fresh_nonces",
    ),
    (
        "plaintext_limit",
        "        if plaintext.len() > MAX_PLAINTEXT_BYTES {\n            return Err(Error::Limit);\n        }\n",
        "",
        "plaintext_and_envelope_limits_are_checked_before_crypto",
    ),
    (
        "envelope_limit",
        "        if record.len() > MAX_SEALED_BYTES {\n            return Err(Error::Limit);\n        }\n",
        "",
        "plaintext_and_envelope_limits_are_checked_before_crypto",
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
                full + ["--test", "sealed", test, "--", "--exact"],
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
            "panicked at tests/sealed.rs:" in text and "assertion" in text,
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
