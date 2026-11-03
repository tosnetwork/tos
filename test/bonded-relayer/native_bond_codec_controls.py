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
root = Path(__file__).resolve().parents[2]
source = root / "tools/bonded-relayer/bond-codec/src/lib.rs"
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)
original = source.read_text()
(out / "source-before.rs").write_text(original)


def require(value, message):
    if not value:
        raise RuntimeError(message)


full = [
    "cargo",
    "test",
    "--locked",
    "--manifest-path",
    "tools/bonded-relayer/bond-codec/Cargo.toml",
]
env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
cases = [
    (
        "purpose",
        "b.append_u32(tag)?.append_i32(init.global_id)?;",
        "b.append_u32(POP_TAG)?.append_i32(init.global_id)?;",
        "signatures_bind_network_actor_and_purpose",
    ),
    (
        "address",
        'anyhow::ensure!(&Self::address(&init)? == address, "noncanonical bond address");',
        "let _ = address;",
        "config_roundtrip_and_deployment_identity",
    ),
    (
        "policy",
        "(86700..=2592000).contains(&init.exit_delay)",
        "true",
        "canonical_byte_chains_and_policy_bounds",
    ),
    (
        "endpoint",
        "                && !init.endpoint.bytes().any(|b| b <= 0x20 || b == 0x7f)",
        "",
        "canonical_byte_chains_and_policy_bounds",
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
                full + ["--lib", "tests::" + test, "--", "--exact"],
                cwd=root,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=240,
            )
        text = log.read_text()
        require(
            result.returncode == 101 and ("test tests::" + test + " ... FAILED") in text,
            "Expected failed test: " + name,
        )
        require(
            "panicked at src/lib.rs:" in text and "assertion" in text,
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
    require(restored.returncode == 0, "Restored codec suite did not pass")
    require(source.read_text() == original, "Source was not restored exactly")
    (out / "results.json").write_text(
        json.dumps(
            {
                "controls": results,
                "expected_controls": len(cases),
                "complete": len(results) == len(cases),
                "restored_codec_exit": restored.returncode,
                "source_restored_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )
