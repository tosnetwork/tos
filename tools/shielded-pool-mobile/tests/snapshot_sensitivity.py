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
source = root / "tools/shielded-pool-mobile/src/snapshot.rs"
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
        "fresh_generation",
        "    rand::rngs::OsRng.try_fill_bytes(&mut generation).map_err(|_| Error::Crypto)?;\n",
        "",
        "round_trip_empty_and_page_edges_with_fresh_generations",
    ),
    (
        "plaintext_cap",
        "    if plaintext.len() > MAX_SNAPSHOT_BYTES {\n        return Err(Error::Limit);\n    }\n",
        "",
        "exact_limit_is_usable_and_over_limit_is_rejected",
    ),
    (
        "envelope_cap",
        "    if encoded.len() > MAX_ENCODED_BYTES {\n        return Err(Error::Limit);\n    }\n",
        "",
        "exact_limit_is_usable_and_over_limit_is_rejected",
    ),
    (
        "manifest_cap",
        "    if manifest_len > MAX_MANIFEST + RECORD_OVERHEAD {\n        return Err(Error::Limit);\n    }\n",
        "",
        "manifest_envelope_length_is_bounded_before_decoding",
    ),
    (
        "manifest_total",
        "    if total > MAX_SNAPSHOT_BYTES || count > MAX_PAGES {\n        return Err(Error::Limit);\n    }\n",
        "",
        "authenticated_manifest_bounds_and_shape_are_checked",
    ),
    (
        "page_hash",
        "        if Sha3_256::digest(page).as_slice() != hash {\n            return Err(Error::Crypto);\n        }\n",
        "",
        "mixed_reordered_missing_and_extra_pages_are_refused",
    ),
    (
        "extra_pages",
        "    if !input.is_empty() || remaining_plain != 0 {\n        return Err(Error::InvalidInput);\n    }\n",
        "",
        "mixed_reordered_missing_and_extra_pages_are_refused",
    ),
    (
        "purpose",
        "Kind::Journal => Err(Error::InvalidInput)",
        "Kind::Journal => Ok(())",
        "wrong_key_purpose_header_and_manifest_are_refused",
    ),
    (
        "container_version",
        "    if take(&mut input, 8)? != MAGIC {\n        return Err(Error::InvalidInput);\n    }\n",
        "    take(&mut input, 8)?;\n",
        "wrong_key_purpose_header_and_manifest_are_refused",
    ),
    (
        "manifest_version",
        '    if take(&mut fields, 4)? != b"SM01" {\n        return Err(Error::InvalidInput);\n    }\n',
        "    take(&mut fields, 4)?;\n",
        "authenticated_manifest_bounds_and_shape_are_checked",
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
                full + ["--test", "snapshot", test, "--", "--exact"],
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
            "panicked at tests/snapshot.rs:" in text and "assertion" in text,
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
