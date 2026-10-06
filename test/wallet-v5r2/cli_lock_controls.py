"""Require the SLH lock CLI to sign the exact lock action, not an ordinary execution."""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--genesis-driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_lock_cmd.rs"
    original = source.read_text()
    old = "AuthAction::LockPrimary"
    assert original.count(old) == 3

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
                str(ROOT / "test/wallet-v5r2/cli_lock_primary.py"),
                "--cli",
                str(args.cli),
                "--genesis-driver",
                str(args.genesis_driver),
                "--fixture",
                str(args.fixture),
                "--output",
                str(args.output / label),
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        if positive:
            assert result.returncode == 0 and "6 SLH lock CLI outcomes passed" in log, log
        else:
            assert result.returncode != 0 and "CLI did not sign a lock action" in log, log

    try:
        build("baseline")
        run("baseline", True)
        source.write_text(
            original.replace(old, "AuthAction::Execute { actions: chain_block::Cell::default() }")
        )
        build("bypass")
        run("bypass", False)
    finally:
        source.write_text(original)
        build("restored")
        run("restored", True)
    (args.output / "result.txt").write_text(
        "Lock-action substitution produces a different valid SLH authorization and fails the exact-action assertion; restored lock passes.\n"
    )
    print("CLI lock-action mutation detected; restored 6 SLH lock outcomes pass")


if __name__ == "__main__":
    main()
