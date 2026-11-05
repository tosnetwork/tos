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
sources = {
    name: root / ("tools/shielded-pool-mobile/src/" + name + ".rs") for name in ["sealed", "store"]
}
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)
originals = {name: path.read_text() for name, path in sources.items()}
for name, value in originals.items():
    (out / ("source-before-" + name + ".rs")).write_text(value)


def require(value, message):
    if not value:
        raise RuntimeError(message)


full = ["cargo", "test", "--locked", "--manifest-path", "tools/shielded-pool-mobile/Cargo.toml"]
env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()))
cases = [
    (
        "sealed",
        "master",
        "        identity.update(&*master);\n",
        "",
        "masters_networks_pools_and_genesis_are_separate",
    ),
    (
        "sealed",
        "domain",
        "        identity.update(&shielded_pool_circuit::field::fr_to_be(&domain));\n",
        "",
        "masters_networks_pools_and_genesis_are_separate",
    ),
    (
        "sealed",
        "genesis_root",
        "        identity.update(&binding.genesis_root);\n",
        "",
        "masters_networks_pools_and_genesis_are_separate",
    ),
    (
        "sealed",
        "genesis_file",
        "        identity.update(&binding.genesis_file);\n",
        "",
        "masters_networks_pools_and_genesis_are_separate",
    ),
    (
        "sealed",
        "pin_upgrade",
        "        identity.update(&binding.genesis_file);\n",
        "        identity.update(&binding.genesis_file);\n        identity.update(&binding.code_hash);\n",
        "upgrade_pins_cannot_create_a_fresh_directory_and_forget_reservations",
    ),
    (
        "store",
        "legacy_entries",
        'for name in [STATE, NEXT, reservations::JOURNAL] {',
        "for name in [] as [&CStr; 0] {",
        "legacy_flat_stores_and_their_lock_never_become_fresh_roots",
    ),
    (
        "store",
        "legacy_symlink",
        "libc::AT_SYMLINK_NOFOLLOW",
        "0",
        "legacy_flat_stores_and_their_lock_never_become_fresh_roots",
    ),
    (
        "store",
        "root_validation",
        "        Self::private_directory(&directory)?;\n        Self::exclusive_lock(&directory)?;\n        // Never reinterpret",
        "        Self::exclusive_lock(&directory)?;\n        // Never reinterpret",
        "unsafe_roots_and_child_entries_are_preserved_and_refused",
    ),
    (
        "store",
        "root_lock",
        "        Self::exclusive_lock(&directory)?;\n        // Never reinterpret",
        "        // Never reinterpret",
        "legacy_flat_stores_and_their_lock_never_become_fresh_roots",
    ),
]

results = []
try:
    for file, name, before, after, test in cases:
        for name_to_restore, path in sources.items():
            path.write_text(originals[name_to_restore])
        source = sources[file]
        original = originals[file]
        require(original.count(before) == 1, "Mutation target changed: " + name)
        source.write_text(original.replace(before, after))
        log = out / (name + ".log")
        with log.open("wb") as stream:
            result = subprocess.run(
                full + ["--lib", "store::instance_tests::" + test, "--", "--exact"],
                cwd=root,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=240,
            )
        text = log.read_text()
        require(
            result.returncode == 101
            and ("test store::instance_tests::" + test + " ... FAILED") in text,
            "Expected failed test: " + name,
        )
        require(
            "panicked at src/instance_tests.rs:" in text and "assertion" in text,
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
    for name, path in sources.items():
        path.write_text(originals[name])
    with (out / "restored-full.log").open("wb") as stream:
        restored = subprocess.run(
            full, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=300
        )
    source_restored = all(path.read_text() == originals[name] for name, path in sources.items())
    (out / "results.json").write_text(
        json.dumps(
            {
                "controls": results,
                "expected_controls": len(cases),
                "complete": len(results) == len(cases)
                and restored.returncode == 0
                and source_restored,
                "restored_sdk_exit": restored.returncode,
                "source_restored_sha256": {
                    name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in sources.items()
                },
            },
            indent=2,
        )
        + "\n"
    )

    require(source_restored, "Sources were not restored exactly")
    require(restored.returncode == 0, "Restored SDK suite did not pass")
