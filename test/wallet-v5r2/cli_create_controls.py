"""Rebuild the CLI to prove backup exclusivity, duplicate preflight and creation entropy policy."""

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
    path = ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_cmd.rs"
    original = path.read_text()
    cases = [
        (
            "backup_overwrite",
            "temporary.persist_noclobber(path)?;",
            "temporary.persist(path)?;",
            "backup",
            "CLI creation outcome primary-existing-backup",
        ),
        (
            "duplicate_preflight",
            "!vault.exists(&id).await?",
            "true",
            "duplicate",
            "duplicate creation generated a new backup",
        ),
        (
            "word_count",
            "tos_native_mnemonic::generate(24)?",
            "tos_native_mnemonic::generate(12)?",
            "all",
            "new PQ key did not use 24 words",
        ),
    ]
    for name, old, _, _, _ in cases:
        assert original.count(old) == 1, name

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
                str(ROOT / "test/wallet-v5r2/cli_create.py"),
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
        code, log = run(label, "all")
        assert code == 0 and "8 actual CLI creation outcomes verified (all)" in log, log[-4000:]

    results = {}
    try:
        build("baseline")
        positive("baseline")
        for name, old, new, case, witness in cases:
            path.write_text(original.replace(old, new))
            build(name)
            code, log = run(name, case)
            assert code != 0 and "AssertionError" in log and witness in log, log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        build("restored")
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} actual creation controls detected; restored commands pass")


if __name__ == "__main__":
    main()
