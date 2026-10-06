"""Detect config fallback and signature-verification deletion in transaction probes.

Run exclusively: source files are temporarily changed and restored.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        ROOT / "test/wallet-v5r2/release_config_transactions.py",
        "--config",
        args.config.resolve(),
        "--driver",
        args.driver.resolve(),
    ]
    results = {}

    def run(label):
        with (out / (label + ".log")).open("w") as log:
            result = subprocess.run(
                list(map(str, command + ["--output", out / label])),
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        results[label] = result.returncode
        return result.returncode

    def build(label):
        # Use the same target directory as the driver being checked.
        driver = args.driver.resolve()
        if driver.parent.name != "examples" or driver.parent.parent.name != "debug":
            raise RuntimeError("controls require a debug/examples/pq-tx-parity driver")
        env = dict(os.environ, CARGO_TARGET_DIR=str(driver.parent.parent.parent))
        with (out / (label + "-build.log")).open("w") as log:
            result = subprocess.run(
                [
                    "cargo",
                    "build",
                    "--manifest-path",
                    "tosctl/src/Cargo.toml",
                    "--locked",
                    "-p",
                    "tos_executor",
                    "--example",
                    "pq-tx-parity",
                    "-j1",
                ],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        if result.returncode:
            raise RuntimeError("driver build failed; not mutation evidence")

    if run("baseline"):
        raise RuntimeError("baseline failed")
    cases = [
        (
            "native-fallback",
            "test/auth-extensions/native.py",
            "configuration.b64(), vm_log_verbosity",
            "config(18).b64(), vm_log_verbosity",
            "synthesized configuration forbidden",
        ),
        (
            "verification-deleted",
            "test/wallet-v5r2/release-config-probe.fc",
            "throw_unless(901, valid);",
            "",
            "s1-bitflip",
        ),
        (
            "rust-fallback",
            "tosctl/src/executor/examples/pq-tx-parity.rs",
            "BlockchainConfig::with_config(config)?",
            "BlockchainConfig::default_with_global_version(version.version)?",
            "whole-transaction cross-VM divergence",
        ),
    ]
    for label, name, old, new, assertion in cases:
        path = ROOT / name
        original = path.read_text()
        if original.count(old) != 1:
            raise RuntimeError("mutation anchor must occur exactly once")
        try:
            path.write_text(original.replace(old, new))
            if label == "rust-fallback":
                build(label)
            code = run(label)
            log = (out / (label + ".log")).read_text()
            if code != 1 or assertion not in log or "AssertionError" not in log:
                raise RuntimeError("mutation did not reach the intended assertion")
            if label == "rust-fallback":
                first = (out / label / "rust.tsv").read_text().splitlines()[0].split("\t")
                if first[:2] != ["s1-valid", "904"]:
                    raise RuntimeError("Rust fallback did not fail the contract's credit check")
        finally:
            path.write_text(original)
            if label == "rust-fallback":
                build(label + "-restored")
        if run(label + "-restored"):
            raise RuntimeError("restored baseline failed")
    report = dict(passed=True, runs=results, restored_green=True)
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
