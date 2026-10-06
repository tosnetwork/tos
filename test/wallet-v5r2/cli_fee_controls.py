"""Require the real fee CLI to bind its master before opening encrypted custody."""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--public-tree", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_fee_cmd.rs"
    original = source.read_text()
    old = """            manifest.verify_initial_fee_master_and_wipe(
                &mut *checked,
                SeedProfile::NativeMnemonic,
                0,
                &path,
            )?;"""
    assert original.count(old) == 1

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
        assert result.returncode == 0, log[-3000:]

    def run(label, positive):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "test/wallet-v5r2/cli_fee_restore.py"),
                "--cli",
                str(args.cli),
                "--public-tree",
                str(args.public_tree),
                "--fixture",
                str(args.fixture),
                "--output",
                str(args.output / label),
                "--skip-rebuild",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        if positive:
            assert result.returncode == 0 and "13 fee CLI recovery outcomes verified" in log, log
        else:
            assert result.returncode != 0 and "metadata-account_index: rejected recovery" in log, (
                log
            )

    try:
        build("baseline")
        run("baseline", True)
        source.write_text(original.replace(old, ""))
        build("bypass")
        run("bypass", False)
    finally:
        source.write_text(original)
        build("restored")
        run("restored", True)
    (args.output / "result.txt").write_text(
        "Fee preflight bypass opened custody for a mismatched account index; restored CLI refuses before storage.\n"
    )
    print("CLI fee preflight bypass detected; restored 13 outcomes pass")


if __name__ == "__main__":
    main()
