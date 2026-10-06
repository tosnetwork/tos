"""Rebuild the actual CLI and require custody preflight and exact-password failures."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    command = ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_cmd.rs"
    inputs = ROOT / "tosctl/src/secrets-vault/src/secret_input.rs"
    originals = {path: path.read_text() for path in (command, inputs)}
    exact = (
        originals[inputs]
        .split("pub fn read_secret_exact(", 1)[1]
        .split("/// The input with surrounding", 1)[0]
    )
    assert exact.count("Ok(data)") == 1
    cases = [
        (
            "custody_preflight",
            command,
            "derived.public_key() == expected_key",
            "true",
            "preflight",
            "CLI opened custody before enrollment validation",
        ),
        (
            "exact_password",
            inputs,
            exact,
            exact.replace("Ok(data)", "Ok(Zeroizing::new(trim_ascii(&data).to_vec()))"),
            "password",
            "CLI rejected valid exact-password recovery",
        ),
    ]
    cases.extend(
        [
            (
                "record_id",
                command,
                "!self.record_id.trim().is_empty()",
                "true",
                "inputs",
                "CLI lost record-id preflight",
            ),
            (
                "key_width",
                command,
                "key.len() == self.role.native().public_key_bytes()",
                "true",
                "inputs",
                "CLI lost key-width preflight",
            ),
            (
                "duplicate_fd",
                command,
                "fds[i].is_none() || fds[i] != fds[j]",
                "true",
                "inputs",
                "CLI lost duplicate-fd preflight",
            ),
        ]
    )
    for name, path, old, _, _, _ in cases:
        assert originals[path].count(old) == 1, name

    def build(label):
        result = subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "tosctl",
                "--features",
                "pq-wallet",
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}-build.log").write_text(log)
        assert result.returncode == 0, log[-4000:]

    def run(label, case):
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "test/wallet-v5r2/cli_restore.py"),
                "--cli",
                str(args.cli.resolve()),
                "--output",
                str(args.output / label),
                "--case",
                case,
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        for case in ("preflight", "password", "inputs"):
            code, log = run(f"{label}-{case}", case)
            assert code == 0 and f"actual CLI restore outcomes verified ({case})" in log, log[
                -4000:
            ]

    results = {}
    try:
        build("baseline")
        positive("baseline")
        for name, path, old, new, case, witness in cases:
            path.write_text(originals[path].replace(old, new))
            build(name)
            code, log = run(name, case)
            assert code != 0 and "AssertionError" in log and witness in log, log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(originals[path])
    finally:
        for path, original in originals.items():
            path.write_text(original)
        build("restored")
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} actual CLI controls detected; restored cases pass")


if __name__ == "__main__":
    main()
